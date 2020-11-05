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
b loopHandler(llvm::Function&, llvm::LoopInfo&)
b 
*/




#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
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



#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

/*
#include "./abilist.h"
#include "./defs.h"
#include "./debug.h"
#include "./version.h"

*/

using namespace llvm;

#define DEBUG_TYPE "loop-handling-pass"

namespace {

//------------------------------------------------------------------------------
// New PM interface
//------------------------------------------------------------------------------

struct LoopHandlingPass : public PassInfoMixin<LoopHandlingPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &)  ;
  bool loopHandler(Function &F, LoopInfo &LI) ;
  
};

//void LoopHandlingPass::getAnalysisUsage(AnalysisUsage &AU) const 

bool LoopHandlingPass::loopHandler(Function &F, LoopInfo &LI) {
  // if (!F.getName().startswith(StringRef("read_markers")))
  //  return false;
  if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
    return false;
  bool Instrumented = false;
  auto &CTX = F.getContext();

  // inject the declaration of printf
  PointerType *PrintfArgTy = PointerType::getUnqual(Type::getInt8Ty(CTX));
  FunctionType *PrintfTy =
      FunctionType::get(IntegerType::getInt32Ty(CTX), PrintfArgTy, true);
  FunctionCallee Printf = F.getParent()->getOrInsertFunction("printf", PrintfTy);

  // set attributes
  Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
  PrintfF->setDoesNotThrow();
  PrintfF->addParamAttr(0, Attribute::NoCapture);
  PrintfF->addParamAttr(0, Attribute::ReadOnly);

  // create & initialize the printf format string
  Constant *FormatStr = ConstantDataArray::getString(CTX, "%d --> %d\n");
  Constant *FormatStrVar =
      F.getParent()->getOrInsertGlobal("FormatStr", FormatStr->getType());
  dyn_cast<GlobalVariable>(FormatStrVar)->setInitializer(FormatStr);

  StringRef Name = F.getName();
  outs() << "name: " << Name << "\n";

  for (auto &LIT : LI) { 
    Loop &L = *LIT;
    //llvm::printLoop(L, outs());
    
    //Get an IR builder. Sets the insertion point to loop header
    //outs() << "loop header:\n" << *L.getHeader();
    IRBuilder<> HeaderBuilder(&*L.getHeader()->getFirstInsertionPt());
    
    // get Latches and ExitingBlocks to get backedges and exiting edges
    SmallVector<BasicBlock *, 8> Latches;
    L.getLoopLatches(Latches);
    for (auto &LatchI : Latches) {
      outs() << "loop lacth ;\n" << *LatchI;
    }
    SmallVector<BasicBlock *, 8> Exitings;
    L.getExitingBlocks(Exitings);
    for (auto &ExitingI : Exitings) {
      outs() << "loop exiting ;\n" << *ExitingI;
    }
    
    

    for(BasicBlock *BB : L.getBlocks()) {
      for (auto &Inst : *BB) {

        //TODO
        // focus on memory access

      }

    }
    
  }
  return Instrumented;

} //loopHandler end

PreservedAnalyses LoopHandlingPass::run(Function &F, FunctionAnalysisManager &FAM) {
  LoopInfo &LI = FAM.getResult<LoopAnalysis>(F);
    bool Changed = loopHandler(F, LI);

    return (Changed ? PreservedAnalyses::none() : PreservedAnalyses::all());
} // run end

//------------------------------------------------------------------------------
// Legacy PM interface
//------------------------------------------------------------------------------
struct LegacyLoopHandlingPass : public FunctionPass {
  static char ID;
  LegacyLoopHandlingPass() : FunctionPass(ID) {}
  bool runOnFunction(Function &F) override {

    bool changed = Impl.loopHandler(F, getAnalysis<LoopInfoWrapperPass>().getLoopInfo());

    return changed;
  };
  void getAnalysisUsage(AnalysisUsage &AU) const {
      AU.addRequired<LoopInfoWrapperPass>();
  }

  LoopHandlingPass Impl;
};

} // namespace

//-----------------------------------------------------------------------------
// New PM Registration
//-----------------------------------------------------------------------------
PassPluginLibraryInfo getLoopHandlingPassPluginInfo() {
  return {LLVM_PLUGIN_API_VERSION, "LoopHandlingPass", LLVM_VERSION_STRING,
          [](PassBuilder &PB) {
            PB.registerPipelineParsingCallback(
                [](StringRef Name, FunctionPassManager &MPM,
                   ArrayRef<PassBuilder::PipelineElement>) {
                  if (Name == "loop-handling-pass") {
                    MPM.addPass(LoopHandlingPass());
                    return true;
                  }
                  return false;
                });
          }};
}

extern "C" LLVM_ATTRIBUTE_WEAK ::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getLoopHandlingPassPluginInfo();
}

//-----------------------------------------------------------------------------
// Legacy PM Registration
//-----------------------------------------------------------------------------
char LegacyLoopHandlingPass::ID = 0;

// Register the pass - required for (among others) opt
static RegisterPass<LegacyLoopHandlingPass>
    X(
      /*PassArg=*/"legacy-loop-handling-pass", 
      /*Name=*/"LegacyLoopHandlingPass",
      /*CFGOnly=*/false, 
      /*is_analysis=*/false
      );