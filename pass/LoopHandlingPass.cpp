/*
#COMPILE#
cmake -DCMAKE_BUILD_TYPR=Debug .
make

#RUN#
opt -load-pass-plugin ./libLoopHandlingPass.so -passes=loop-handling-pass -f ../test/loopTest.ll
 OR
opt -load ./libLoopHandlingPass.so --legacy-loop-handling-pass ../test/loopTest.ll
 OR 
clang loopTest.bc -o loopTest-loop.ll -Xclang -load -Xclang ../../install/pass/libLoopHandlingPass.so -mllvm -chunk-exploitation-list=../../install/rules/exploitation_list.txt -Xclang -load -Xclang ../../install/pass/libDFSanPass.so -mllvm -chunk-dfsan-abilist=../../install/rules/angora_abilist.txt -mllvm -chunk-dfsan-abilist=../../install/rules/dfsan_abilist.txt -emit-llvm -S



#DEBUG#

gdb opt
b llvm::Pass::preparePassManager
r -load ./libLoopHandlingPass.so --legacy-loop-handling-pass < ../test/loopTest.ll > /dev/null
b loopHandler
b 
*/



#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopAnalysisManager.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopIterator.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpander.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/Analysis/IVUsers.h"
#include "llvm/Analysis/CFG.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/PassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/SourceMgr.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils.h"
#include "llvm/Pass.h"
#include "llvm/PassAnalysisSupport.h"
#include "llvm/InitializePasses.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./defs.h"
#include "./abilist.h"

/*
#include "./abilist.h"
#include "./defs.h"
#include "./debug.h"
#include "./version.h"

*/

using namespace llvm;
using namespace std;

#define DEBUG_TYPE "loop-handling-pass"

namespace {

//------------------------------------------------------------------------------
// New PM interface
//------------------------------------------------------------------------------

#define MAX_EXPLOIT_CATEGORY 5
// const char *ExploitCategoryCmp = "all";
const char *LengthFunc[] = {"lenfn0", "lenfn1", "lenfn2"};
const char *CompareFunc = "cmpfn";
const char *OffsetFunc = "offsfn";

static cl::list<std::string> ClExploitListFiles(
    "chunk-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);

// hash file name and file size
//DJB hash function
u32 hashName(std::string str) {
    std::ifstream in(str, std::ifstream::ate | std::ifstream::binary);
    u32 fsize = in.tellg();
    u32 hash = 5381 + fsize * 223;
    for (auto c : str)
      hash = ((hash << 5) + hash) + (unsigned char)c; /* hash * 33 + c */
    return hash;
}

struct LoopHandlingPass : public ModulePass {
  static char ID;
  unsigned long int RandSeed = 1;
  u32 FuncID;
  // output some debug data
  bool output_cond_loc;

  //Exploitation
  AngoraABIList ExploitList;
  // Types
  Type *VoidTy;
  IntegerType *Int1Ty;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  Type *Int8PtrTy;
  Type *Int32PtrTy;
  Type *Int64PtrTy;

  Type *PrintfArg;
  // Global vars
  // GlobalVariable *AngoraMapPtr;
  Value *FuncPop;

  // Constants
  Constant *FormatStrVar;
  Constant *NumZero;
  Constant *NumOne;
  Constant *BoolTrue;
  Constant *BoolFalse;

  FunctionType *ChunkCmpTtTy;
  FunctionType *ChunkSwTtTy;
  FunctionType *ChunkCmpFnTtTy;
  FunctionType *ChunkLenFnTtTy;
  FunctionType *ChunkOffsFnTtTy;

  FunctionCallee PrintfFn;
  FunctionCallee LoadLabelDumpFn;
  FunctionCallee PushNewObjFn;
  FunctionCallee DumpEachIterFn;
  FunctionCallee PopObjFn;

  FunctionCallee ChunkCmpTT;
  FunctionCallee ChunkSwTT;
  FunctionCallee ChunkCmpFnTT;
  FunctionCallee ChunkLenFnTT;
  FunctionCallee ChunkOffsFnTT;


  LoopHandlingPass() : ModulePass(ID) {}
  bool runOnModule(Module &M) ;

  //user defined functions
  u32 getRandomNum();
  u32 getRandomInstructionId();
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomLoopId();
  u32 getLoopId(Loop *L);
  u32 getFunctionId(Function *F);
  void setRandomNumSeed(u32 seed);
  void initVariables(Module &M);

  Value *castArgType(IRBuilder<> &IRB, Value *V); //从angorapass里抄来的 setValueNotSan直接注释掉了

  void visitCallInst(Instruction *Inst);
  void visitInvokeInst(Instruction *Inst);
  void visitLoadInst(Instruction *Inst);
  void visitBranchInst(Instruction *Inst, bool loop);
  void visitSwitchInst(Module &M, Instruction *Inst, bool loop);
  void visitCmpInst(Instruction *Inst, bool loop);
  void visitExploitation(Instruction *Inst);

  void processCmp(Instruction *Cond, Instruction *InsertPoint, bool loop);
  void processBoolCmp(Value *Cond, Instruction *InsertPoint,bool loop);
  void processCallInst(Instruction *Inst);
  void processLoadInst(Instruction *Cond, Instruction *InsertPoint);

  void getAnalysisUsage(AnalysisUsage &AU) const override {

    AU.addRequiredID(LoopSimplifyID);
    AU.addRequired<ScalarEvolutionWrapperPass>();
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();

    AU.addPreserved<ScalarEvolutionWrapperPass>();
    AU.addPreserved<LoopInfoWrapperPass>();
    AU.addPreserved<DominatorTreeWrapperPass>();
    AU.setPreservesAll();
  }
};

void LoopHandlingPass::setRandomNumSeed(u32 seed) { RandSeed = seed; }

u32 LoopHandlingPass::getRandomNum() {
  RandSeed = RandSeed * 1103515245 + 12345;
  return (u32)RandSeed;
}

u32 LoopHandlingPass::getRandomInstructionId() { return getRandomNum(); }

u32 LoopHandlingPass::getInstructionId(Instruction *Inst) {
  u32 h = 0;
  DILocation *Loc = Inst->getDebugLoc();
  if (Loc) {
    u32 Line = Loc->getLine();
    u32 Col = Loc->getColumn();
    h = (Col * 33 + Line) * 33 + FuncID;
  } 
  else {
    h = getRandomInstructionId();
  } 
  /*
    errs() << "[ID] " << h << "\n";
    errs() << "[INS] " << *Inst << "\n";
    if (DILocation *Loc = Inst->getDebugLoc()) {
      errs() << "[LOC] " << cast<DIScope>(Loc->getScope())->getFilename()
             << ", Ln " << Loc->getLine() << ", Col " << Loc->getColumn()
             << "\n";
    }
  */
  return h;
}

u32 LoopHandlingPass::getRandomLoopId() { return getRandomNum(); }

u32 LoopHandlingPass::getLoopId(Loop *L) {
  Function &F = *L->getHeader()->getParent();
  u32 h = 0;
  std::string funcName = F.getName();
  std::string headerName = L->getName();
  funcName += "$";
  funcName += headerName;
  if (headerName != "<unnamed loop>" ) {
    h = hashName(funcName);
  }
  else {
    BasicBlock * header = L->getHeader();
    BasicBlock::reverse_iterator ri = header->rbegin();
    if (isa<BranchInst>(&*ri)) {
      h = getInstructionId(&*ri);
    }
  }
  if (h == 0) {
    errs() << "get random loop ID\n";
    h = getRandomLoopId();
  }
  return h;
}

u32 LoopHandlingPass::getFunctionId(Function *F) {
  return hashName(F->getName());
}

std::set<u32> InstrumentedLoopSet;

void LoopHandlingPass::initVariables(Module &M) {
  auto &CTX = M.getContext();
  // string FuncName = F.getName();
  // FuncID = hashName(FuncName);
  // // srandom(FuncID);
  // setRandomNumSeed(FuncID);
  // output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

  VoidTy = Type::getVoidTy(CTX);
  Int1Ty = IntegerType::getInt1Ty(CTX);
  Int8Ty = IntegerType::getInt8Ty(CTX);
  Int32Ty = IntegerType::getInt32Ty(CTX);
  Int64Ty = IntegerType::getInt64Ty(CTX);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int32PtrTy = PointerType::getUnqual(Int32Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  NumZero = ConstantInt::get(Int32Ty, 0);
  NumOne = ConstantInt::get(Int32Ty, 1);
  BoolTrue = ConstantInt::get(Int8Ty, 1);
  BoolFalse = ConstantInt::get(Int8Ty, 0);
/*
  // inject the declaration of printf
  PrintfArg = Int8PtrTy;
  FunctionType *PrintfTy = FunctionType::get(Int32Ty, PrintfArg, true);

  // set attributes
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoUnwind);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::ReadOnly);
    PrintfFn = M.getOrInsertFunction("printf", PrintfTy, AL);                     
  }

  // create & initialize the printf format string
  Constant *FormatStr = ConstantDataArray::getString(CTX, "Loop hash :%u, \n Instruction hash :%u,\n induction variable value: %d\n");
  FormatStrVar =
      M.getOrInsertGlobal("FormatStr", FormatStr->getType());
  dyn_cast<GlobalVariable>(FormatStrVar)->setInitializer(FormatStr);
*/

  Type *LoadLabelDumpArgs[2] = {Int8PtrTy, Int32Ty};
  FunctionType *LoadLabelDumpArgsTy = FunctionType::get(VoidTy, LoadLabelDumpArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    LoadLabelDumpFn = M.getOrInsertFunction("__chunk_get_load_label", LoadLabelDumpArgsTy, AL);   
  }

  Type *PushNewObjArgs[3] = {Int8Ty,Int32Ty,Int32Ty};
  FunctionType *PushNewObjArgsTy = FunctionType::get(VoidTy, PushNewObjArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    PushNewObjFn = M.getOrInsertFunction("__chunk_push_new_obj", PushNewObjArgsTy, AL);   
  }

  Type *DumpEachIterArgs[1] = {Int32Ty};
  FunctionType *DumpEachIterArgsTy = FunctionType::get(VoidTy, DumpEachIterArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    DumpEachIterFn = M.getOrInsertFunction("__chunk_dump_each_iter", DumpEachIterArgsTy, AL);   
  }

  Type *PopObjArgs[1] = {Int32Ty};
  FunctionType *PopObjArgsTy = FunctionType::get(Int8Ty, PopObjArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    PopObjFn = M.getOrInsertFunction("__chunk_pop_obj", PopObjArgsTy, AL);   
  }

  Type *ChunkCmpTtArgs[8] = {Int32Ty, Int32Ty, Int64Ty, Int64Ty, Int32Ty, Int8Ty, Int8Ty, Int8Ty};
  ChunkCmpTtTy = FunctionType::get(VoidTy, ChunkCmpTtArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    ChunkCmpTT = M.getOrInsertFunction("__chunk_trace_cmp_tt", ChunkCmpTtTy, AL);   
  }
  
  //Int64PtrTy,
  Type *ChunkSwTtArgs[4] = {Int32Ty, Int64Ty, Int32Ty,Int8Ty};
  ChunkSwTtTy = FunctionType::get(VoidTy, ChunkSwTtArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    ChunkSwTT = M.getOrInsertFunction("__chunk_trace_switch_tt", ChunkSwTtTy, AL);   
  }

  Type *ChunkCmpFnTtArgs[5] = {Int8PtrTy, Int8PtrTy, Int32Ty, Int8Ty, Int8Ty};
  ChunkCmpFnTtTy = FunctionType::get(VoidTy, ChunkCmpFnTtArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    ChunkCmpFnTT = M.getOrInsertFunction("__chunk_trace_cmpfn_tt", ChunkCmpFnTtTy, AL);   
  }

  Type *ChunkOffsFnTtArgs[3] = {Int32Ty, Int32Ty, Int8Ty};
  ChunkOffsFnTtTy = FunctionType::get(VoidTy, ChunkOffsFnTtArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    ChunkOffsFnTT = M.getOrInsertFunction("__chunk_trace_offsfn_tt", ChunkOffsFnTtTy, AL);   
  }
  
  Type *ChunkLenFnTtArgs[6] = {Int8PtrTy, Int32Ty, Int32Ty, Int8Ty, Int8Ty, Int8Ty};
  ChunkLenFnTtTy = FunctionType::get(VoidTy, ChunkLenFnTtArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    ChunkLenFnTT = M.getOrInsertFunction("__chunk_trace_lenfn_tt", ChunkLenFnTtTy, AL);   
  }

  std::vector<std::string> AllExploitListFiles;
  AllExploitListFiles.insert(AllExploitListFiles.end(),
                             ClExploitListFiles.begin(),
                             ClExploitListFiles.end());
  // for(auto it = AllExploitListFiles.begin();it!=AllExploitListFiles.end();it++){
  //   outs() << *it << "\n";
  // }
  ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles, *vfs::getRealFileSystem()));

}

Value *LoopHandlingPass::castArgType(IRBuilder<> &IRB, Value *V) {
  Type *OpType = V->getType();
  Value *NV = V;
  if (OpType->isFloatTy()) {
    NV = IRB.CreateFPToUI(V, Int32Ty);
    // setValueNonSan(NV);
    NV = IRB.CreateIntCast(NV, Int64Ty, false);
    // setValueNonSan(NV);
  } else if (OpType->isDoubleTy()) {
    NV = IRB.CreateFPToUI(V, Int64Ty);
    // setValueNonSan(NV);
  } else if (OpType->isPointerTy()) {
    NV = IRB.CreatePtrToInt(V, Int64Ty);
  } else {
    if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
      NV = IRB.CreateZExt(V, Int64Ty);
    }
  }
  return NV;
}

void LoopHandlingPass::visitCallInst(Instruction *Inst) {

  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  visitExploitation(Inst);

  if (!Callee || Callee->isIntrinsic() || isa<InlineAsm>(Caller->getCalledValue())) {
    return;
  }

  // instrument before CALL
  processCallInst(Inst);
};

void LoopHandlingPass::visitInvokeInst(Instruction *Inst) {

  InvokeInst *Caller = dyn_cast<InvokeInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  visitExploitation(Inst);

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledValue())) {
    return;
  }

  // instrument before INVOKE
  processCallInst(Inst);
}

void LoopHandlingPass::visitLoadInst(Instruction *Inst) {
  // instrument after LOAD
  Instruction *InsertPoint = Inst->getNextNonDebugInstruction();
  if (!InsertPoint || isa<ConstantInt>(Inst))
    return;
  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  processLoadInst(Inst, InsertPoint);
}

void LoopHandlingPass::visitBranchInst(Instruction *Inst, bool loop) {
  BranchInst *Br = dyn_cast<BranchInst>(Inst);

  // outs() << "Branch: " << *Br << "\t" << Br->getOpcode() << "\n";

  if (Br->isConditional()) {
    Value *Cond = Br->getCondition();
    // outs() << "\t" << Cond->getType()->getTypeID() << "\n";
    if (Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond)) {
      if (!isa<CmpInst>(Cond)) {
        // From  and, or, call, phi ....
        processBoolCmp(Cond, Inst, loop);
      }
    }
  }
}

void LoopHandlingPass::visitSwitchInst(Module &M, Instruction *Inst, bool loop) {

  SwitchInst *Sw = dyn_cast<SwitchInst>(Inst);
  Value *Cond = Sw->getCondition();

  // outs() << "Switch: " << *Sw << "\t" << Sw->getOpcode() << "\n";
  if (!(Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond))) {
    return;
  }

  int num_bits = Cond->getType()->getScalarSizeInBits();
  int num_bytes = num_bits / 8;
  if (num_bytes == 0 || num_bits % 8 > 0)
    return;
  
  IRBuilder<> IRB(Sw);

  Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
  SmallVector<Constant *, 16> ArgList;
  for (auto It : Sw->cases()) {
    Constant *C = It.getCaseValue();
    // outs() << "\t" << C->getType()->getTypeID() << "\n";
    if (C->getType()->getScalarSizeInBits() > Int64Ty->getScalarSizeInBits())
      continue;
    ArgList.push_back(ConstantExpr::getCast(CastInst::ZExt, C, Int64Ty));
  }

  // need to fix
  ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, ArgList.size());
  GlobalVariable *ArgGV = new GlobalVariable( 
      M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
      ConstantArray::get(ArrayOfInt64Ty, ArgList),
      "__chunk_switch_arg_values");
  Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);

  Value *SwNum = ConstantInt::get(Int32Ty, ArgList.size());
  Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);
  Value *is_loop =  loop? BoolTrue : BoolFalse;

  CallInst *ProxyCall = IRB.CreateCall(
      ChunkSwTT, {SizeArg, CondExt, SwNum, ArrPtr, is_loop});

}

void LoopHandlingPass::visitCmpInst(Instruction *Inst, bool is_loop) {
  Instruction *InsertPoint = Inst->getNextNode();
  if (!InsertPoint || isa<ConstantInt>(Inst))
    return;

  processCmp(Inst, InsertPoint,is_loop);
}

// TODO
void LoopHandlingPass::visitExploitation(Instruction *Inst) {

  Instruction* AfterCall= Inst->getNextNonDebugInstruction();
  IRBuilder<> AfterBuilder(AfterCall);
  CallInst *Caller = dyn_cast<CallInst>(Inst);
  
  if(ExploitList.isIn(*Inst, CompareFunc)) {
    Value *OpArg[2];
    OpArg[0] = Caller->getArgOperand(0);
    OpArg[1] = Caller->getArgOperand(1);
    if (!OpArg[0]->getType()->isPointerTy() ||!OpArg[1]->getType()->isPointerTy()) return;

    Value *ArgSize = NumZero;
    if (Caller->getNumArgOperands() > 2) {
      ArgSize = Caller->getArgOperand(2); // int32ty
    }

    Value *is_cnst1 =  isa<Constant>(OpArg[0])? BoolTrue : BoolFalse;
    Value *is_cnst2 =  isa<Constant>(OpArg[1])? BoolTrue : BoolFalse;

    CallInst *CmpFnCall = AfterBuilder.CreateCall(ChunkCmpFnTT, {OpArg[0], OpArg[1], ArgSize, is_cnst1, is_cnst2});

  } else if(ExploitList.isIn(*Inst,OffsetFunc)) {
    // outs() << "fseek inst\n";
    Value *index = Caller->getArgOperand(1);
    Value *op = Caller->getArgOperand(2);

    Value *is_cnst_idx =  isa<Constant>(index)? BoolTrue : BoolFalse;

    CallInst *OffsFnCall = AfterBuilder.CreateCall(ChunkOffsFnTT, {index, op, is_cnst_idx});
    
  } else if(ExploitList.isIn(*Inst, LengthFunc[0])){
    Value *dst = Caller->getArgOperand(0);
    Value *len1 = Caller->getArgOperand(1);
    Value *len2 = Caller->getArgOperand(2);

    Value *is_cnst_dst =  isa<Constant>(dst)? BoolTrue : BoolFalse;
    Value *is_cnst_l1 =  isa<Constant>(len1)? BoolTrue : BoolFalse;
    Value *is_cnst_l2 =  isa<Constant>(len2)? BoolTrue : BoolFalse;

    CallInst *LenFnCall = AfterBuilder.CreateCall(ChunkLenFnTT, {dst, len1, len2, is_cnst_dst, is_cnst_l1, is_cnst_l2});
  }else if(ExploitList.isIn(*Inst, LengthFunc[1]) || ExploitList.isIn(*Inst, LengthFunc[2])){
    Value *len = Caller->getArgOperand(2);

    Value *dst;
    if(ExploitList.isIn(*Inst, LengthFunc[0])){
      dst = Caller->getArgOperand(0);
    } else dst = Caller->getArgOperand(1);

    Value *is_cnst_dst =  isa<Constant>(dst)? BoolTrue : BoolFalse;
    Value *is_cnst_l1 =  isa<Constant>(len)? BoolTrue : BoolFalse;
    
    CallInst *LenFnCall = AfterBuilder.CreateCall(ChunkLenFnTT, {dst, len, NumZero, is_cnst_dst, is_cnst_l1, BoolTrue});
    
  }

  
}


void LoopHandlingPass::processCmp(Instruction *Cond, Instruction *InsertPoint, bool loop) {
  CmpInst *Cmp = dyn_cast<CmpInst>(Cond);

  Value *OpArg[2];
  OpArg[0] = Cmp->getOperand(0);
  OpArg[1] = Cmp->getOperand(1);
  Value *is_cnst1 =  isa<Constant>(OpArg[0])? BoolTrue : BoolFalse;
  Value *is_cnst2 =  isa<Constant>(OpArg[1])? BoolTrue : BoolFalse;
  Value *is_loop =  loop? BoolTrue : BoolFalse;

  Type *OpType = OpArg[0]->getType();
  // outs() << "Compare: " << *Cmp << "\t" << OpType->getTypeID() << "\t" << OpArg[1]->getType()->getTypeID() << "\n";
  if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
        OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
    processBoolCmp(Cond,InsertPoint, loop);
    return;
  }

  int num_bytes = OpType->getScalarSizeInBits() / 8;
  if (num_bytes == 0) {
    if (OpType->isPointerTy()) {
      num_bytes = 8;
    } else {
      return;
    }
  }
  Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);

  u32 predicate = Cmp->getPredicate();
  if (ConstantInt *CInt = dyn_cast<ConstantInt>(OpArg[1])) {
    if (CInt->isNegative()) {
      predicate |= COND_SIGN_MASK;
    }
  }
  Value *TypeArg = ConstantInt::get(Int32Ty, predicate);
  // outs() << "\t" << predicate << "\n" ;
  
  // Instruction *InsertPoint = Inst->getNextNode();
  IRBuilder<> IRB(InsertPoint);
  Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
  OpArg[0] = castArgType(IRB, OpArg[0]);
  OpArg[1] = castArgType(IRB, OpArg[1]);
  // outs() << "insert ChunkCmpTT\n";
  CallInst *ProxyCall =
      IRB.CreateCall(ChunkCmpTT, {SizeArg, TypeArg, OpArg[0], OpArg[1], CondExt, is_loop, is_cnst1, is_cnst2});
}


void LoopHandlingPass::processBoolCmp(Value *Cond, Instruction *InsertPoint, bool loop) {
  if (!Cond->getType()->isIntegerTy() || Cond->getType()->getIntegerBitWidth() > 32) return;

  Value *OpArg[2];
  OpArg[1] = ConstantInt::get(Int64Ty, 1);

  Value *SizeArg = ConstantInt::get(Int32Ty, 1);
  Value *TypeArg = ConstantInt::get(Int32Ty, COND_EQ_OP | COND_BOOL_MASK);
  // outs() << "\tBoolCmp: " << SizeArg->getValueName() << TypeArg->getValueName() << OpArg[1]->getValueName() << "\n";
  
  IRBuilder<> IRB(InsertPoint);
  Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
  OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);

  Value *is_cnst1 =  isa<Constant>(OpArg[0])? BoolTrue : BoolFalse;
  Value *is_cnst2 =  isa<Constant>(OpArg[1])? BoolTrue : BoolFalse;
  Value *is_loop =  loop? BoolTrue : BoolFalse;

  CallInst *ProxyCall =
      IRB.CreateCall(ChunkCmpTT, {SizeArg, TypeArg, OpArg[0], OpArg[1], CondExt, is_loop, is_cnst1, is_cnst2});
  
}


void LoopHandlingPass::processCallInst(Instruction *Inst) {
  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Func = Caller->getCalledFunction();
  

  if (Func->getName().startswith(StringRef("__chunk_")) || Func->getName().startswith(StringRef("__dfsw_")) ||Func->getName().startswith(StringRef("asan.module"))) {
    return;
  }
  if (Func->isDeclaration()) {
    return;
  }

  u32 hFunc = getFunctionId(Func);
  ConstantInt *HFunc = ConstantInt::get(Int32Ty, hFunc);
  IRBuilder<> BeforeBuilder(Inst);
  CallInst *Call1 = BeforeBuilder.CreateCall(PushNewObjFn,{BoolFalse,  NumZero, HFunc});
  Instruction* AfterCall= Inst->getNextNonDebugInstruction();
  IRBuilder<> AfterBuilder(AfterCall);
  Value *PopObjRet = AfterBuilder.CreateCall(PopObjFn, {HFunc});

  return ;
}

void LoopHandlingPass::processLoadInst(Instruction *Inst, Instruction *InsertPoint) {
  LoadInst *LoadI = dyn_cast<LoadInst>(Inst);
  Value *LoadOpr = LoadI->getPointerOperand();
  StringRef VarName = LoadOpr->getName();
  Type* VarType = LoadI->getPointerOperandType()->getPointerElementType();
  unsigned TySize = 0;
  if (VarType->isIntegerTy())
    TySize = VarType->getIntegerBitWidth();
  TySize = TySize / 8; //byte;
  ConstantInt *size = ConstantInt::get(Int32Ty, TySize);

  if (TySize != 0) {
    IRBuilder<> IRB(InsertPoint);
    Value * LoadOprPtr = IRB.CreatePointerCast(
                  LoadOpr, Int8PtrTy, "loadOprPtr");
    CallInst *CallI = IRB.CreateCall(LoadLabelDumpFn, {LoadOprPtr, size});
  }
  /*
  else {
    errs() << "LoadI: " << *LoadI << "\n";
    errs() << "VarName" << VarName << "\n";
    errs() << "VarType" << *VarType << "\n";
    errs() << "TySize" << TySize << "\n";
  }
  */
}


bool LoopHandlingPass::runOnModule(Module &M) {

  initVariables(M);

  for (auto &F : M) {
    if (F.isDeclaration() ||F.getName().startswith(StringRef("__chunk_")) || F.getName().startswith(StringRef("__dfsw_")) || F.getName().startswith(StringRef("asan.module"))) {
      continue;
    }
    auto &LI = getAnalysis<LoopInfoWrapperPass>(F).getLoopInfo();
    std::set<BasicBlock *> loop_header_set;
    for (LoopInfo::iterator LIT = LI.begin(), LEND = LI.end(); LIT != LEND; ++LIT) {
      Loop *LoopI = *LIT;
      BasicBlock *BB = LoopI->getHeader();
      loop_header_set.insert(BB);
    }
    for (auto &BB : F) {
      bool in_loop_header = false;
      if (loop_header_set.find(&BB) != loop_header_set.end()) {
        in_loop_header = true;
      }
      for (auto &Inst : BB) {
        if (isa<CallInst>(&Inst)) 
          visitCallInst(&Inst);
        else if (isa<InvokeInst>(&Inst)) 
          visitInvokeInst(&Inst);
        else if (isa<LoadInst>(&Inst)) {
          visitLoadInst(&Inst);
        } else if (isa<BranchInst>(&Inst)) {
          visitBranchInst(&Inst, in_loop_header);
        } else if (isa<SwitchInst>(&Inst)) {
          visitSwitchInst(M, &Inst, in_loop_header);
        } else if (isa<CmpInst>(&Inst)) {
          visitCmpInst(&Inst, in_loop_header);
        }
      }
    }

    for (LoopInfo::iterator LIT = LI.begin(), LEND = LI.end(); LIT != LEND; ++LIT) {
      Loop *L = *LIT;
      // llvm::printLoop(*L, errs());
      u32 hLoop = getLoopId(L);
      // if (!L->isLoopSimplifyForm()) {
      //   errs() << "not simplify "<< hLoop <<"\n";
      // }
      ConstantInt *HLoop = ConstantInt::get(Int32Ty, hLoop);
      // Insert a global variable COUNTER in the current function.This will insert a declaration into M
      char hexTmp[10];
      sprintf(hexTmp, "%X", hLoop);
      std::string hLoopStr = hexTmp;
      std::string LoopCntName = std::string("LoopCnt_" + hLoopStr);
      BasicBlock *header = L->getHeader();

      IRBuilder<> FunctionBuilder(&*F.getEntryBlock().getFirstInsertionPt());
      Value *LoopCnt = FunctionBuilder.CreateAlloca(Int32Ty, 0, LoopCntName);
      FunctionBuilder.CreateStore(NumZero, LoopCnt);

      //Get an IR builder. Sets the insertion point to loop header
      IRBuilder<> HeaderBuilder(&*L->getHeader()->getFirstInsertionPt());
      LoadInst *LoadLoopCnt = HeaderBuilder.CreateLoad(LoopCnt);
      HeaderBuilder.CreateCall(PushNewObjFn,{BoolTrue,  LoadLoopCnt, HLoop});
      HeaderBuilder.CreateCall(DumpEachIterFn,{LoadLoopCnt});
      Value *Inc = HeaderBuilder.CreateAdd(LoadLoopCnt, NumOne);
      HeaderBuilder.CreateStore(Inc, LoopCnt);

      //Set the insertion point to each ExitBlocks
      SmallVector<BasicBlock *, 16> Exits;
      L->getUniqueExitBlocks(Exits);
      for(BasicBlock *BB : Exits) {
        // errs() << "\nexit block : \n" << *BB;
        BasicBlock::iterator i = BB->begin();
        Instruction* ExitI =  &*i;
        IRBuilder<> ExitBuilder(ExitI);
        LoadInst *LoadLoopCnt2 = ExitBuilder.CreateLoad(LoopCnt);
        ExitBuilder.CreateCall(DumpEachIterFn,{LoadLoopCnt2});
        ExitBuilder.CreateCall(PopObjFn, {HLoop});
        ExitBuilder.CreateStore(NumZero, LoopCnt);
        }
    }

  }

} // runOnModule end

} // namespace end

char LoopHandlingPass::ID = 0;

// Register the pass - required for (among others) opt
static RegisterPass<LoopHandlingPass>
    X(
      /*PassArg=*/"loop-handling-pass", 
      /*Name=*/"LoopHandlingPass",
      /*CFGOnly=*/false, 
      /*is_analysis=*/false
      );

static void registerLoopHandlingPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
  PM.add(new LoopHandlingPass());
}

static RegisterStandardPasses
    RegisterLoopHandlingPass(PassManagerBuilder::EP_OptimizerLast,
                         registerLoopHandlingPass);

static RegisterStandardPasses
    RegisterLoopHandlingPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                          registerLoopHandlingPass);
