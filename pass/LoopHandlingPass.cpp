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
#include "llvm/Analysis/ScalarEvolution.h"
#include "llvm/Analysis/ScalarEvolutionExpressions.h"
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

struct LoopHandlingPass : public PassInfoMixin<LoopHandlingPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &)  ;
  bool loopHandler(Function &F, LoopInfo &LI) ;

  // Types
  Type *VoidTy;
  IntegerType *Int1Ty;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  Type *Int8PtrTy;
  Type *Int64PtrTy;

  unsigned long int RandSeed = 1;
  u32 ModId;
  // output some debug data
  bool output_cond_loc;

  u32 getRandomNum();
  u32 getRandomInstructionId();
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomLoopId();
  u32 getLoopId(Loop *L);
  void setRandomNumSeed(u32 seed);

// private:
//   ScalarEvolution *SE = nullptr;
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
    h = (Col * 33 + Line) * 33 + ModId;
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
    h1 = (stCol * 33 + stLine) * 33 + ModId;
    u32 edLine = ed->getLine();
    u32 edCol = ed->getColumn();
    h2 = (edCol * 33 + edLine) * 33 + ModId;

    h = (h2 + 0x9e3779b9 + (h1<<6) + (h1>>2)) ^ h1;
  }
  else {
    h = getRandomLoopId();
  }
  return h;
}

bool LoopHandlingPass::loopHandler(Function &F, LoopInfo &LI) {
  // if (!F.getName().startswith(StringRef("read_markers")))
  //  return false;
  if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
    return false;

  string FuncName = F.getParent()->getModuleIdentifier();
  FuncName += "@";
  FuncName += F.getName();
  ModId = hashName(FuncName);
  srandom(ModId);
  setRandomNumSeed(ModId);
  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

  bool Instrumented = false;
  auto &CTX = F.getContext();

  VoidTy = Type::getVoidTy(CTX);
  Int1Ty = IntegerType::getInt1Ty(CTX);
  Int8Ty = IntegerType::getInt8Ty(CTX);
  Int32Ty = IntegerType::getInt32Ty(CTX);
  Int64Ty = IntegerType::getInt64Ty(CTX);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  // inject the declaration of printf
  Type *PrintfArgTy = Int8PtrTy;
  FunctionType *PrintfTy =
      FunctionType::get(Int32Ty, PrintfArgTy, true);
  FunctionCallee Printf = F.getParent()->getOrInsertFunction("printf", PrintfTy);

  // set attributes
  Function *PrintfF = dyn_cast<Function>(Printf.getCallee());
  PrintfF->setDoesNotThrow();
  PrintfF->addParamAttr(0, Attribute::NoCapture);
  PrintfF->addParamAttr(0, Attribute::ReadOnly);

  // create & initialize the printf format string
  Constant *FormatStr = ConstantDataArray::getString(CTX, "Loop hash :%u, \n Instruction hash :%u,\n induction variable value: %d\n");
  Constant *FormatStrVar =
      F.getParent()->getOrInsertGlobal("FormatStr", FormatStr->getType());
  dyn_cast<GlobalVariable>(FormatStrVar)->setInitializer(FormatStr);

  StringRef Name = F.getName();
  outs() << "name: " << Name << "\n";

  for (auto &LIT : LI) { 
    Loop &L = *LIT;
    //llvm::printLoop(L, outs());
    u32 hLoop = getLoopId(&L);
    ConstantInt *HLoop = ConstantInt::get(Int32Ty, hLoop);
    ConstantInt *NumZero = ConstantInt::get(Int32Ty, 0);
    
    //Get an IR builder. Sets the insertion point to loop header
    //outs() << "loop header:\n" << *L.getHeader();
    
    //flag = true;
    IRBuilder<> HeaderBuilder(&*L.getHeader()->getFirstInsertionPt());
    Value *FormatStrPtr = HeaderBuilder.CreatePointerCast(
                    FormatStrVar, PrintfArgTy, "formatStr");
    HeaderBuilder.CreateCall(Printf, {FormatStrPtr, HLoop, NumZero, NumZero});
    
    // get Latches and ExitingBlocks to get backedges and exiting edges
    SmallVector<BasicBlock *, 16> Latches;
    L.getLoopLatches(Latches);
    for (auto &LatchI : Latches) {
      outs() << "loop lacth :\n" << *LatchI;
    }
    SmallVector<BasicBlock *, 16> Exitings;
    L.getExitingBlocks(Exitings);
    for (auto &ExitingI : Exitings) {
      outs() << "loop exiting :\n" << *ExitingI;
    }
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
          outs() << "backedges: \n" << *i2 << "\n";
          Backedges.insert(&*i2);
        }
        else {
          outs() << "backedges: \n" << *i << "\n";
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
          outs() << "backedges: \n" << *i2 << "\n";
          Exitingedges.insert(&*i2);
        }
        else {
          outs() << "backedges: \n" << *i << "\n";
          Exitingedges.insert(&*i);
        }
      }
    }

    // dump chunk info
    for (Instruction * Inst : Backedges) {
      u32 hInst = getInstructionId(Inst);
      ConstantInt *HInst = ConstantInt::get(Int32Ty, hInst);

      IRBuilder<> InstBuilder(Inst);
      Value *FormatStrPtr = InstBuilder.CreatePointerCast(
                    FormatStrVar, PrintfArgTy, "formatStr");
      InstBuilder.CreateCall(Printf, {FormatStrPtr, HLoop, HInst, NumZero});
      
    }

    //dump chunk info
    //flag = false
    for (Instruction * Inst : Exitingedges) {
      u32 hInst = getInstructionId(Inst);
      ConstantInt *HInst = ConstantInt::get(Int32Ty, hInst);
      //get induction variable value
      IRBuilder<> InstBuilder(Inst);
      Value *FormatStrPtr = InstBuilder.CreatePointerCast(
                    FormatStrVar, PrintfArgTy, "formatStr");
      InstBuilder.CreateCall(Printf, {FormatStrPtr, HLoop, HInst, NumZero});
      
    }

    
  }
  return Instrumented;

} //loopHandler end

PreservedAnalyses LoopHandlingPass::run(Function &F, FunctionAnalysisManager &FAM) {
  LoopInfo &LI = FAM.getResult<LoopAnalysis>(F);
    bool Changed = loopHandler(F, LI);
    // SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();

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
      // AU.addRequired<ScalarEvolutionWrapperPass>();
  }

  LoopHandlingPass Impl;
  // LoopHandlingPass::SE = &getAnalysis<ScalarEvolutionWrapperPass>().getSE();
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

static void registerLegacyLoopHandlingPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {
  PM.add(new LegacyLoopHandlingPass());
}

static RegisterStandardPasses
    RegisterLegacyLoopHandlingPass(PassManagerBuilder::EP_OptimizerLast,
                         registerLegacyLoopHandlingPass);

static RegisterStandardPasses
    RegisterLegacyLoopHandlingPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                          registerLegacyLoopHandlingPass);
