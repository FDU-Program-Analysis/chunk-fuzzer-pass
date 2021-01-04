/*
#COMPILE#
cmake -DCMAKE_BUILD_TYPR=Debug .
make

#RUN#
opt -load-pass-plugin ./libLoopHandlingPass.so -passes=loop-handling-pass -f ../test/loopTest.ll
 OR
opt -load ./libLoopHandlingPass.so --legacy-loop-handling-pass ../test/loopTest.ll



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

struct LoopHandlingPass : public LoopPass {
  static char ID;
  unsigned long int RandSeed = 1;
  u32 FuncID;
  // output some debug data
  bool output_cond_loc;

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


  FunctionCallee PrintfFn;
  FunctionCallee LoadLabelDumpFn;
  FunctionCallee PushNewObjFn;
  FunctionCallee DumpEachIterFn;
  FunctionCallee PopObjFn;


  LoopHandlingPass() : LoopPass(ID) {}
  bool runOnLoop(Loop * L, LPPassManager &LPM) override ;

  //user defined functions
  u32 getRandomNum();
  u32 getRandomInstructionId();
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomLoopId();
  u32 getLoopId(Function *F, Loop *L);
  u32 getFunctionId(Function *F);
  void setRandomNumSeed(u32 seed);
  void initVariables(Function &F, Module &M);

  void visitCallInst(Instruction *Inst);
  void visitInvokeInst(Instruction *Inst);
  void visitLoadInst(Instruction *Inst);

  void processCallInst(Instruction *Inst);
  void processLoadInst(Instruction *Cond, Instruction *InsertPoint);

  void getAnalysisUsage(AnalysisUsage &AU) const {
    AU.addRequired<LoopInfoWrapperPass>();
    AU.addRequired<DominatorTreeWrapperPass>();
    AU.addRequired<ScalarEvolutionWrapperPass>();
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

u32 LoopHandlingPass::getLoopId(Function *F, Loop *L) {
  u32 h = 0;
  std::string funcName = F->getName();
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
std::set<u32> InstrumentedFuncSet;

void LoopHandlingPass::initVariables(Function &F, Module &M) {
  auto &CTX = F.getContext();
  string FuncName = F.getName();
  FuncID = hashName(FuncName);
  // srandom(FuncID);
  setRandomNumSeed(FuncID);
  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

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
  // BoolTrue = ConstantInt::getTrue(Int8Ty);
  // BoolFalse = ConstantInt::getFalse(Int8Ty);

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


  Type *LoadLabelDumpArgs[2] = {Int8PtrTy, Int32Ty};
  FunctionType *LoadLabelDumpArgsTy = FunctionType::get(VoidTy, LoadLabelDumpArgs, false);
  {
    AttributeList AL;
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::NoInline);
    AL = AL.addAttribute(CTX, AttributeList::FunctionIndex,
                         Attribute::OptimizeNone);
    LoadLabelDumpFn = M.getOrInsertFunction("__chunk_get_dump_label", LoadLabelDumpArgsTy, AL);   
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

  /*
  FuncPop = M.getOrInsertGlobal("FuncPop", Int8Ty);
  
  // This will change the declaration into definition (and initialise to 0)
  GlobalVariable *FuncPopGV = M.getNamedGlobal("FuncPop");
  FuncPopGV->setLinkage(GlobalValue::CommonLinkage);
  // MaybeAlign(bitWidth/8)
  FuncPopGV->setAlignment(MaybeAlign(1)); 
  FuncPopGV->setInitializer(BoolFalse);
  */

}

void LoopHandlingPass::visitCallInst(Instruction *Inst) {

  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() || isa<InlineAsm>(Caller->getCalledValue())) {
    // outs() << "VisitCall, Returned : " << *Inst <<"\n";
    return;
  }

  // instrument before CALL
  processCallInst(Inst);
};

void LoopHandlingPass::visitInvokeInst(Instruction *Inst) {

  InvokeInst *Caller = dyn_cast<InvokeInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledValue())) {
        // outs() << "VisitCall, Returned : " << *Inst <<"\n";
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

void LoopHandlingPass::processCallInst(Instruction *Inst) {
  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Func = Caller->getCalledFunction();
  u32 hFunc = getFunctionId(Func);
  // outs() << "FunctionName: " << Func->getName()<< " FunctionHash : " << hFunc << "\n";
  if (Func->getName().startswith(StringRef("__chunk_")) || Func->getName().startswith(StringRef("__dfsw_")) ||Func->getName().startswith(StringRef("asan.module"))) {
    // outs() <<"retrun because name: " << Func->getName() << "\n";
    return;
  }
  if (Func->isDeclaration()) {
    // outs() << "return because isDeclaration\n" <<  Func->getName() << "\n";
    return;
  }
  ConstantInt *HFunc = ConstantInt::get(Int32Ty, hFunc);
  IRBuilder<> BeforeBuilder(Inst);
  // outs() << "Before Call: " << *Inst << "\n";
  CallInst *Call1 = BeforeBuilder.CreateCall(PushNewObjFn,{BoolFalse,  NumZero, HFunc});
  // outs() << "CallInst Push: " << *Call1 << "\n";
  Instruction* AfterCall= Inst->getNextNonDebugInstruction();
  // outs() << "After Call: " << *AfterCall << "\n";
  IRBuilder<> AfterBuilder(AfterCall);
  Value *PopObjRet = AfterBuilder.CreateCall(PopObjFn, {HFunc});
  // outs() << "CallInst Pop: " << *PopObjRet << "\n";
  // AfterBuilder.CreateStore(PopObjRet,FuncPop);


  if (InstrumentedFuncSet.find(hFunc) != InstrumentedFuncSet.end()) 
    return;
  else 
    InstrumentedFuncSet.insert(hFunc);
  // outs() << "Instrument CallInst\n";
  DominatorTree DT(*Func);
  LoopInfo LI(DT);
  // LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>(*Func).getLoopInfo();
  std::set<BasicBlock *> skip_bb_set;
  for (LoopInfo::iterator LIT = LI.begin(), LEND = LI.end(); LIT != LEND; ++LIT) {
    Loop *LoopI = *LIT;
    u32 hLoopI = getLoopId(Func,LoopI);
    if (InstrumentedLoopSet.find(hLoopI) != InstrumentedLoopSet.end()) {
      for (BasicBlock *BB : LoopI->getBlocks()) {
        skip_bb_set.insert(BB);
      }
    }
  }
  for (auto &BB : *Func) {
    if (skip_bb_set.find(&BB) == skip_bb_set.end()) {
      for (auto &Inst : BB) {
        if (isa<CallInst>(&Inst)) 
          visitCallInst(&Inst);
        else if (isa<InvokeInst>(&Inst)) 
          visitInvokeInst(&Inst);
        else if (isa<LoadInst>(&Inst)) {
          visitLoadInst(&Inst);
        }
      }
    }
  }
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
  ConstantInt *size = ConstantInt::get(Int32Ty, TySize);

  IRBuilder<> IRB(InsertPoint);
  Value * LoadOprPtr = IRB.CreatePointerCast(
                 LoadOpr, Int8PtrTy, "loadOprPtr");
  CallInst *CallI = IRB.CreateCall(LoadLabelDumpFn, {LoadOprPtr, size});
}



bool LoopHandlingPass::runOnLoop(Loop * L, LPPassManager &LPM) {

  // llvm::printLoop(*L, outs());
  bool isChildLoop = false;
  bool isInstrumented = false;


  if (L->getParentLoop()) {
    // outs() << "getParentLoop \n ";
    isChildLoop = true;
  }

  Function &F = *L->getHeader()->getParent();
  Module &M = *L->getHeader()->getModule();
  auto &CTX = F.getContext();
  initVariables(F, M);

  //check if this loop has been instrumented through runOnLoop
  u32 hLoop = getLoopId(&F,L);
  if (InstrumentedLoopSet.find(hLoop) != InstrumentedLoopSet.end()) {
    // outs() << hLoop << " :Instrumented\n";
    return false;
  }
  else InstrumentedLoopSet.insert(hLoop);

  // check if this loop has beed instrumented through processCallInst
  u32 hFunc = getFunctionId(&F);
  if (InstrumentedFuncSet.find(hFunc) != InstrumentedFuncSet.end()) {
    // outs() << "Func Instrumented: " <<hFunc << "\n";
    isInstrumented = true;
  }
  
  ConstantInt *HLoop = ConstantInt::get(Int32Ty, hLoop);

  // Instrument LoadInst and CallInst\InvokeInst
  if (!(isChildLoop || isInstrumented)) {
    for (BasicBlock *BB : L->getBlocks()) {
      for (auto &Inst : *BB) {
        if (isa<CallInst>(&Inst)) 
            visitCallInst(&Inst);
        else if (isa<InvokeInst>(&Inst)) 
            visitInvokeInst(&Inst);
        else if (isa<LoadInst>(&Inst)) 
            visitLoadInst(&Inst);
      }
    }
  }

  // Insert a global variable COUNTER in the current function.This will insert a declaration into M
  char hexTmp[10];
  sprintf(hexTmp, "%X", hLoop);
  std::string hLoopStr = hexTmp;
  std::string LoopCntName = std::string("LoopCnt_" + hLoopStr);
  Value *LoopCnt = 
      M.getOrInsertGlobal(LoopCntName, Int32Ty);
  
  // This will change the declaration into definition (and initialise to 0)
  GlobalVariable *LoopCntGV = M.getNamedGlobal(LoopCntName);
  LoopCntGV->setLinkage(GlobalValue::CommonLinkage);
  // MaybeAlign(bitWidth/8)
  LoopCntGV->setAlignment(MaybeAlign(4)); 
  LoopCntGV->setInitializer(NumZero);

  //Get an IR builder. Sets the insertion point to loop header
  IRBuilder<> HeaderBuilder(&*L->getHeader()->getFirstInsertionPt());
  LoadInst *LoadLoopCnt = HeaderBuilder.CreateLoad(LoopCnt);
  HeaderBuilder.CreateCall(PushNewObjFn,{BoolTrue,  LoadLoopCnt, HLoop});
  HeaderBuilder.CreateCall(DumpEachIterFn,{LoadLoopCnt});
  Value *Inc = HeaderBuilder.CreateAdd(LoadLoopCnt, NumOne);
  HeaderBuilder.CreateStore(Inc, LoopCnt);

  //Set the insertion point to each ExitBlocks
  SmallVector<BasicBlock *, 16> Exits;
  L->getExitBlocks(Exits);
  for(BasicBlock *BB : Exits) {
    BasicBlock::iterator i = BB->begin();
    Instruction* ExitI =  &*i;
    IRBuilder<> ExitBuilder(ExitI);
    LoadInst *LoadLoopCnt = ExitBuilder.CreateLoad(LoopCnt);
    ExitBuilder.CreateCall(DumpEachIterFn,{LoadLoopCnt});
    ExitBuilder.CreateCall(PopObjFn, {HLoop});
    ExitBuilder.CreateStore(NumZero, LoopCnt);
  }

  return true;

} //runOnLoop end

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
