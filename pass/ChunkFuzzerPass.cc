#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/Analysis/LoopPass.h"
#include "llvm/Analysis/IVUsers.h"
#include "llvm/Pass.h"
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./abilist.h"
#include "./defs.h"
#include "./debug.h"
#include "./version.h"

using namespace llvm;
// only do taint tracking, used for compile 3rd libraries.
static cl::opt<bool> DFSanMode("DFSanMode", cl::desc("dfsan mode"), cl::Hidden);

static cl::opt<bool> TrackMode("TrackMode", cl::desc("track mode"), cl::Hidden);


static cl::list<std::string> ClABIListFiles(
    "chunk-fuzzer-dfsan-abilist",
    cl::desc("file listing native abi functions and how the pass treats them"),
    cl::Hidden);

static cl::list<std::string> ClExploitListFiles(
    "chunk-fuzzer-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);


namespace {

#define MAX_EXPLOIT_CATEGORY 5
  const char *ExploitCategoryAll = "all";
  const char *ExploitCategory[] = {"i0", "i1", "i2", "i3", "i4"};
  const char *CompareFuncCat = "cmpfn";

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

class ChunkFuzzerPass : public ModulePass {
public:
  static char ID;
  bool FastMode = false;
  std::string ModName;
  u32 ModId;
  u32 CidCounter;
  unsigned long int RandSeed = 1;
  bool is_bc;
  unsigned int inst_ratio = 100;

  // Const Variables
  DenseSet<u32> UniqCidSet;

  // Configurations
  bool gen_id_random;
  bool output_cond_loc;
  int num_fn_ctx;

  MDNode *ColdCallWeights;

  // Types
  Type *VoidTy;
  IntegerType *Int1Ty;
  IntegerType *Int8Ty;
  IntegerType *Int16Ty;
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  Type *Int8PtrTy;
  Type *Int64PtrTy;

  // Global vars
  GlobalVariable *ChunkFuzzerMapPtr;
  GlobalVariable *ChunkFuzzerPrevLoc;
  GlobalVariable *ChunkFuzzerContext;
  GlobalVariable *ChunkFuzzerCondId;
  GlobalVariable *ChunkFuzzerCallSite;

  // Constant *TraceCmp;
  // Constant *TraceSw;
  Constant *TraceCmpTT;
  Constant *TraceSwTT;
  Constant *TraceFnTT;
  Constant *TraceExploitTT;

  FunctionType *TraceCmpTy;
  FunctionType *TraceSwTy;
  FunctionType *TraceCmpTtTy;
  FunctionType *TraceSwTtTy;
  FunctionType *TraceFnTtTy;
  FunctionType *TraceExploitTtTy;

  Custom setting
  ChunkFuzzerABIList ABIList;
  ChunkFuzzerABIList ExploitList;

  // Meta
  unsigned NoSanMetaId;
  MDTuple *NoneMetaNode;

  ChunkFuzzerLLVMPass() : ModulePass(ID) {}

  bool runOnModule(Module &M) override;
  u32 getInstructionId(Instruction *Inst);
  u32 getRandomBasicBlockId();
  bool skipBasicBlock();
  u32 getRandomNum();
  void setRandomNumSeed(u32 seed);
  u32 getRandomContextId();
  u32 getRandomInstructionId();
  void setValueNonSan(Value *v);
  void setInsNonSan(Instruction *v);
  Value *castArgType(IRBuilder<> &IRB, Value *V);
  void initVariables(Module &M);
  void countEdge(Module &M, BasicBlock &BB);
  void visitCallInst(Instruction *Inst);
  void visitInvokeInst(Instruction *Inst);
  void visitCompareFunc(Instruction *Inst);
  void visitBranchInst(Instruction *Inst);
  void visitCmpInst(Instruction *Inst);
  void processCmp(Instruction *Cond, Constant *Cid, Instruction *InsertPoint);
  void processBoolCmp(Value *Cond, Constant *Cid, Instruction *InsertPoint);
  void visitSwitchInst(Module &M, Instruction *Inst);
  void visitExploitation(Instruction *Inst);
  void processCall(Instruction *Inst);
  void addFnWrap(Function &F);
};

} // namespace

char ChunkFuzzerPass::ID = 0;

u32 ChunkFuzzerPass::getRandomBasicBlockId() { return random() % MAP_SIZE; }

// bool ChunkFuzzerPass::skipBasicBlock() { return (random() % 100) >= inst_ratio; }

u32 ChunkFuzzerPass::getRandomNum()
{
  RandSeed = RandSeed * 1103515245 + 12345;
  return (u32)RandSeed;
}

void ChunkFuzzerPass::setRandomNumSeed(u32 seed) { RandSeed = seed; }

// u32 ChunkFuzzerPass::getRandomContextId() {
//   u32 context = getRandomNum() % MAP_SIZE;
//   if (output_cond_loc) {
//     errs() << "[CONTEXT] " << context << "\n";
//   }
//   return context;
// }

u32 ChunkFuzzerPass::getRandomInstructionId() { return getRandomNum(); }

u32 AngoraLLVMPass::getInstructionId(Instruction *Inst) {
  u32 h = 0;
  if (is_bc) {
    h = ++CidCounter;
  } else {
    if (gen_id_random) {
      h = getRandomInstructionId();
    } else {
      DILocation *Loc = Inst->getDebugLoc();
      if (Loc) {
        u32 Line = Loc->getLine();
        u32 Col = Loc->getColumn();
        h = (Col * 33 + Line) * 33 + ModId;
      } else {
        h = getRandomInstructionId();
      }
    }

    while (UniqCidSet.count(h) > 0) {
      h = h * 3 + 1;
    }
    UniqCidSet.insert(h);
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

u32 ChunkFuzzerPass::getRandomLoopId() { return getRandomNum(); }

u32 ChunkFuzzerPass::getLoopId(Loop *L) {
  u32 h = 0;
  DILocation *Loc = L->getStartLoc();
  if (Loc) {
    u32 Line = Loc->getLine();
    u32 Col = Loc->getColumn();
    h = (Col * 33 + Line) * 33 + ModId;
  }
  else {
    h = getRandomLoopId();
  }
}

u32 ChunkFuzzerPass::getLoopIterationId(Loop *L, int it) {


}

void ChunkFuzzerPass::setValueNonSan(Value *v) {
  if (Instruction *ins = dyn_cast<Instruction>(v))
    setInsNonSan(ins);
}

void ChunkFuzzerPass::setInsNonSan(Instruction *ins) {
  if (ins)
    ins->setMetadata(NoSanMetaId, NoneMetaNode);
}

void ChunkFuzzerPass::initVariables(Module &M) {
  // To ensure different version binaries have the same id
  ModName = M.getModuleIdentifier();
  if (ModName.size() == 0)
    FATAL("No ModName!\n");
  ModId = hashName(ModName);
  errs() << "ModName: " << ModName << " -- " << ModId << "\n";
  is_bc = 0 == ModName.compare(ModName.length() - 3, 3, ".bc");
  if (is_bc) {
    errs() << "Input is LLVM bitcode\n";
  }

  char *inst_ratio_str = getenv("CHUNK_FUZZER_INST_RATIO");
  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of CHUNK_FUZZER_INST_RATIO (must be between 1 and 100)");
  }
  errs() << "inst_ratio: " << inst_ratio << "\n";

  // set seed
  srandom(ModId);
  setRandomNumSeed(ModId);
  CidCounter = 0;

  LLVMContext &C = M.getContext();
  VoidTy = Type::getVoidTy(C);
  Int1Ty = IntegerType::getInt1Ty(C);
  Int8Ty = IntegerType::getInt8Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);

  // ColdCallWeights = MDBuilder(C).createBranchWeights(1, 1000);

  NoSanMetaId = C.getMDKindID("nosanitize");
  NoneMetaNode = MDNode::get(C, None);

  ChunkFuzzerContext =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__chunk_fuzzer_context", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

  ChunkFuzzerCallSite = new GlobalVariable(
      M, Int32Ty, false, GlobalValue::CommonLinkage, 
      ConstantInt::get(Int32Ty, 0), "__chunk_fuzzer_call_site", 0, 
      GlobalVariable::GeneralDynamicTLSModel, 0, false);

  if (TrackMode) {
    Type *TraceCmpTtArgs[7] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty,
                               Int64Ty, Int64Ty, Int32Ty};
    TraceCmpTtTy = FunctionType::get(VoidTy, TraceCmpTtArgs, false);
    TraceCmpTT = M.getOrInsertFunction("__chunk_fuzzer_trace_cmp_tt", TraceCmpTtTy);
    if (Function *F = dyn_cast<Function>(TraceCmpTT)) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
    }

    Type *TraceSwTtArgs[6] = {Int32Ty, Int32Ty, Int32Ty,
                              Int64Ty, Int32Ty, Int64PtrTy};
    TraceSwTtTy = FunctionType::get(VoidTy, TraceSwTtArgs, false);
    TraceSwTT = M.getOrInsertFunction("__chunk_fuzzer_trace_switch_tt", TraceSwTtTy);
    if (Function *F = dyn_cast<Function>(TraceSwTT)) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
    }

    Type *TraceFnTtArgs[5] = {Int32Ty, Int32Ty, Int32Ty, Int8PtrTy, Int8PtrTy};
    TraceFnTtTy = FunctionType::get(VoidTy, TraceFnTtArgs, false);
    TraceFnTT = M.getOrInsertFunction("__chunk_fuzzer_trace_fn_tt", TraceFnTtTy);
    if (Function *F = dyn_cast<Function>(TraceFnTT)) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadOnly);
    }

    Type *TraceExploitTtArgs[5] = {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty};
    TraceExploitTtTy = FunctionType::get(VoidTy, TraceExploitTtArgs, false);
    TraceExploitTT = M.getOrInsertFunction("__chunk_fuzzer_trace_exploit_val_tt",
                                           TraceExploitTtTy);
    if (Function *F = dyn_cast<Function>(TraceExploitTT)) {
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::NoUnwind);
      F->addAttribute(LLVM_ATTRIBUTE_LIST::FunctionIndex, Attribute::ReadNone);
    }
    // TODO :LOOP
  }

  std::vector<std::string> AllABIListFiles;
  AllABIListFiles.insert(AllABIListFiles.end(), ClABIListFiles.begin(),
                         ClABIListFiles.end());
  ABIList.set(SpecialCaseList::createOrDie(AllABIListFiles));

  std::vector<std::string> AllExploitListFiles;
  AllExploitListFiles.insert(AllExploitListFiles.end(),
                             ClExploitListFiles.begin(),
                             ClExploitListFiles.end());
  ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles));

  gen_id_random = !!getenv(GEN_ID_RANDOM_VAR);
  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);


  if (gen_id_random) {
    errs() << "generate id randomly\n";
  }

  if (output_cond_loc) {
    errs() << "Output cond log\n";
  }
}

void handleLoop(Loop *L) {
  if (/* skipLoop(L) ||  */ L->getParentLoop())
      return false;
  std::vector<BasicBlock *> bb_list;
  for (auto bb = L->block_begin(); bb != L->block_end(); bb++)
    bb_list.push_back(&(*bb));
  for (auto bi = bb_list.begin(); bi != bb_list.end(); bi++)
  {
      BasicBlock *BB = *bi;
      std::vector<Instruction *> inst_list;

      for (auto inst = BB->begin(); inst != BB->end(); inst++)
      {
        Instruction *Inst = &(*inst);
        inst_list.push_back(Inst);
      }

      for (auto inst = inst_list.begin(); inst != inst_list.end(); inst++)
      {
        Instruction *Inst = *inst;
        if (Inst->getMetadata(NoSanMetaId))
          continue;
        // if (Inst == &(*BB->getFirstInsertionPt()))
        // {
        //   countEdge(M, *BB);
        // }
        // if (isa<CallInst>(Inst)) {
        //   visitCallInst(Inst);
        // } else if (isa<InvokeInst>(Inst)) {
        //   visitInvokeInst(Inst);
        // } else if (isa<BranchInst>(Inst)) {
        //   visitBranchInst(Inst);
        // } else if (isa<SwitchInst>(Inst)) {
        //   visitSwitchInst(M, Inst);
        // } else if (isa<CmpInst>(Inst)) {
        //   visitCmpInst(Inst);
        // } else {
        //   visitExploitation(Inst);
        // }
      }
    }

}

bool ChunkFuzzerPass::runOnModule(Module &M)
{
  SAYF(cCYA "chunk-fuzzer-pass\n");
  if (TrackMode) {
    OKF("Track Mode.");
  }
  else
  {
    FastMode = true;
    OKF("Fast Mode.");
  }

  initVariables(M);

  for (auto &F : M)
  {
    if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")))
      continue;

    LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>(*F);
    for (LoopInfo::iterator LIT = LI.begin(), LEND = LI.end(); LIT != LEND; ++LIT) {
      handleLoop(*LIT);
    }
    


  }

  if (is_bc)
    OKF("Max constraint id is %d", CidCounter);
  return true;
}

static void registerChunkFuzzerPass(const PassManagerBuilder &,
                                    legacy::PassManagerBase &PM)
{
  PM.add(new ChunkFuzzerPass());
}

static RegisterPass<ChunkFuzzerPass> X("chunk_fuzzer_pass", "Chunk Fuzzer Pass",
                                       false, false);

static RegisterStandardPasses
    RegisterChunkFuzzerPass(PassManagerBuilder::EP_OptimizerLast,
                            registerChunkFuzzerPass);

static RegisterStandardPasses
    RegisterChunkFuzzerPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                             registerChunkFuzzerPass);
