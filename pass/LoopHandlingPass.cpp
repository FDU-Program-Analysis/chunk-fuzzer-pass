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
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/PassAnalysisSupport.h"
#include "llvm/InitializePasses.h"
#include "llvm/AsmParser/Parser.h"
#include "llvm/Passes/PassPlugin.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"



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
  Type *Int64PtrTy;

  LoopHandlingPass() : LoopPass(ID) {}
  bool runOnLoop(Loop * L, LPPassManager &LPM) override ;

  u32 getRandomNum();
  u32 getRandomInstructionId();
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomLoopId();
  u32 getLoopId(Loop *L);
  void setRandomNumSeed(u32 seed);

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

  if (output_cond_loc) {
    errs() << "[ID] " << h << "\n";
    errs() << "[INS] " << *Inst << "\n";
    if (DILocation *Loc = Inst->getDebugLoc()) {
      errs() << "[LOC] " << cast<DIScope>(Loc->getScope())->getFilename()
             << ", Ln " << Loc->getLine() << ", Col " << Loc->getColumn()
             << "\n";
    }
  }
  return h;
}

u32 LoopHandlingPass::getRandomLoopId() { return getRandomNum(); }

u32 LoopHandlingPass::getLoopId(Loop *L) {
  u32 h1 = 0,h2 = 0, h = 0;
  DILocation *st= L->getStartLoc();
  DILocation *ed= L->getLocRange().getEnd();;
  if (st && ed) {
    u32 stLine = st->getLine();
    u32 stCol = st->getColumn();
    h1 = (stCol * 33 + stLine) * 33 + FuncID;
    u32 edLine = ed->getLine();
    u32 edCol = ed->getColumn();
    h2 = (edCol * 33 + edLine) * 33 + FuncID;

    h = (h2 + 0x9e3779b9 + (h1<<6) + (h1>>2)) ^ h1;
  }
  else {
    h = getRandomLoopId();
  }
  return h;
}


bool LoopHandlingPass::runOnLoop(Loop * L, LPPassManager &LPM) {
  // if (skipLoop(L)){
  //   outs() << "skipLoop \n ";
  //   return false;
  // }
    
  // Only visit top-level loops.
  // if (L->getParentLoop()) {
  //   outs() << "getParentLoop \n ";
  //   return false;
  // }

  // llvm::printLoop(*L, outs()) ;
  // bool Instrumented = false;
  const Function &F = *L->getHeader()->getParent();
  Module &M = *L->getHeader()->getModule();
  auto &CTX = F.getContext();

  string FuncName = F.getName();
  if (F.getName().startswith(StringRef("__dfsw_"))) {
    return false;
  }

  FuncID = hashName(FuncName);
  srandom(FuncID);
  setRandomNumSeed(FuncID);

  // outs() << "FuncName: " << FuncName << "\n";

  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

  VoidTy = Type::getVoidTy(CTX);
  Int1Ty = IntegerType::getInt1Ty(CTX);
  Int8Ty = IntegerType::getInt8Ty(CTX);
  Int32Ty = IntegerType::getInt32Ty(CTX);
  Int64Ty = IntegerType::getInt64Ty(CTX);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  // insert a global variable FLAG in the current function
  // This will insert a declaration into F
  std::string FunctionLoopFlagName = std::string(FuncName + "_LoopFlag");
  Constant *FunctionLoopFlag = 
      M.getOrInsertGlobal(FunctionLoopFlagName, Int8Ty);
  
  // This will change the declaration into definition (and initialise to 0)
  GlobalVariable *NewGV = M.getNamedGlobal(FunctionLoopFlagName);
  NewGV->setLinkage(GlobalValue::CommonLinkage);
  NewGV->setAlignment(MaybeAlign(1));
  NewGV->setInitializer(llvm::ConstantInt::get(CTX, APInt(8, 0)));


  // inject the declaration of printf
  Type *PrintfArgTy = Int8PtrTy;
  FunctionType *PrintfTy =
      FunctionType::get(Int32Ty, PrintfArgTy, true);
  FunctionCallee Printf = M.getOrInsertFunction("printf", PrintfTy);

  // set attributes
  Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
  PrintfF->setDoesNotThrow();
  PrintfF->addParamAttr(0, Attribute::NoCapture);
  PrintfF->addParamAttr(0, Attribute::ReadOnly);

  // create & initialize the printf format string
  Constant *FormatStr = ConstantDataArray::getString(CTX, "Loop hash :%u, \n Instruction hash :%u,\n induction variable value: %d\n");
  Constant *FormatStrVar =
      M.getOrInsertGlobal("FormatStr", FormatStr->getType());
  dyn_cast<GlobalVariable>(FormatStrVar)->setInitializer(FormatStr);

  u32 hLoop = getLoopId(L);
  ConstantInt *HLoop = ConstantInt::get(Int32Ty, hLoop);
  ConstantInt *NumZero = ConstantInt::get(Int32Ty, 0);


  
  //Get an IR builder. Sets the insertion point to loop header
  //outs() << "loop header:\n" << *L.getHeader();
  
  //Enter Loop : set flag = true;
  ConstantInt *NumOne = ConstantInt::get(Int8Ty, 1);
  IRBuilder<> HeaderBuilder(&*L->getHeader()->getFirstInsertionPt());
  HeaderBuilder.CreateStore(NumOne, FunctionLoopFlag);
  // Value *FormatStrPtr = HeaderBuilder.CreatePointerCast(
  //                 FormatStrVar, PrintfArgTy, "formatStr");
  // HeaderBuilder.CreateCall(Printf, {FormatStrPtr, HLoop, NumZero, NumZero});
  
  // get Latches and ExitingBlocks to get backedges and exiting edges
  SmallVector<BasicBlock *, 16> Latches;
  L->getLoopLatches(Latches);
  // for (auto &LatchI : Latches) {
  //   outs() << "loop lacth :\n" << *LatchI;
  // }
  SmallVector<BasicBlock *, 16> Exitings;
  L->getExitingBlocks(Exitings);
  // for (auto &ExitingI : Exitings) {
  //   outs() << "loop exiting :\n" << *ExitingI;
  // }
  //backedges and exiting edges
  SmallSet<Instruction *, 32> Backedges;
  for(BasicBlock *BB : Latches) {
    //instrument before jump instruction
    BasicBlock::reverse_iterator i = BB->rbegin();

      if (i != BB->rend()) {
      //If the previous instruction of the jump instruction 
      //is a comparison instruction, then instrument before the comparison instruction
      BasicBlock::reverse_iterator i2 = BB->rbegin();
      i2++;
      if (i2 != BB->rend() && isa<CmpInst>(&*i2)) {
        // outs() << "backedges: \n" << *i2 << "\n";
        Backedges.insert(&*i2);
      }
      else {
        // outs() << "backedges: \n" << *i << "\n";
        Backedges.insert(&*i);
      }
    }
  }

  SmallSet<Instruction *, 32> Exitingedges;
  for(BasicBlock *BB : Exitings) {
    BasicBlock::reverse_iterator i = BB->rbegin();
    if (i != BB->rend()) {
      BasicBlock::reverse_iterator i2 = BB->rbegin();
      i2++;
      if (i2 != BB->rend() && isa<CmpInst>(&*i2)) {
        // outs() << "exitings: \n" << *i2 << "\n";
        Exitingedges.insert(&*i2);
      }
      else {
        // outs() << "exitings: \n" << *i << "\n";
        Exitingedges.insert(&*i);
      }
    }
  }

  // instrument and dump chunk info
  for (Instruction * Inst : Backedges) {
    u32 hInst = getInstructionId(Inst);
    ConstantInt *HInst = ConstantInt::get(Int32Ty, hInst);

    IRBuilder<> InstBuilder(Inst);
    Value *FormatStrPtr = InstBuilder.CreatePointerCast(
                  FormatStrVar, PrintfArgTy, "formatStr");
    InstBuilder.CreateCall(Printf, {FormatStrPtr, HLoop, HInst, NumZero});
    // insert dump labels
  }

  //instrument dump chunk info
  //flag = false
  for (Instruction * Inst : Exitingedges) {
    u32 hInst = getInstructionId(Inst);
    ConstantInt *HInst = ConstantInt::get(Int32Ty, hInst);
    //get induction variable value
    IRBuilder<> InstBuilder(Inst);
    Value *FormatStrPtr = InstBuilder.CreatePointerCast(
                  FormatStrVar, PrintfArgTy, "formatStr");
    InstBuilder.CreateCall(Printf, {FormatStrPtr, HLoop, HInst, NumZero});
    //insert dump labels
  }

  
  return true;
  // return Instrumented;

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
