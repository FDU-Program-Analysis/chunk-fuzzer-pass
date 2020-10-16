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
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "./defs.h"
#include "./debug.h"

using namespace llvm;

// static cl::opt<bool> DFSanMode("DFSanMode", cl::desc("dfsan mode"), cl::Hidden);

static cl::opt<bool> TrackMode("TrackMode", cl::desc("track mode"), cl::Hidden);


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

namespace
{

    class ChunkFuzzerPass : public ModulePass
    {
    public:
        static char ID;
        bool FastMode = true;
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

        Constant *TraceCmp;
        Constant *TraceSw;
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

        // Custom setting
        // ChunkFuzzerABIList ABIList;
        // ChunkFuzzerABIList ExploitList;

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
    }
} // namespace


char ChunkFuzzerPass::ID = 0;

u32 ChunkFuzzerPass::getRandomBasicBlockId() { return random() % MAP_SIZE; }

bool ChunkFuzzerPass::skipBasicBlock() { return (random() % 100) >= inst_ratio; }

u32 ChunkFuzzerPass::getRandomNum() {
  RandSeed = RandSeed * 1103515245 + 12345;
  return (u32)RandSeed;
}

void ChunkFuzzerPass::setRandomNumSeed(u32 seed) { RandSeed = seed; }

u32 ChunkFuzzerPass::getRandomContextId() {
  u32 context = getRandomNum() % MAP_SIZE;
  if (output_cond_loc) {
    errs() << "[CONTEXT] " << context << "\n";
  }
  return context;
}

u32 ChunkFuzzerPass::getRandomInstructionId() { return getRandomNum(); }








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

  char* inst_ratio_str = getenv("ANGORA_INST_RATIO");
  if (inst_ratio_str) {
    if (sscanf(inst_ratio_str, "%u", &inst_ratio) != 1 || !inst_ratio ||
        inst_ratio > 100)
      FATAL("Bad value of ANGORA_INST_RATIO (must be between 1 and 100)");
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


  
}

bool ChunkFuzzerPass::runOnModule(Module &M) {
  SAYF(cCYA "chunk-fuzzer-pass\n");
  if (TrackMode) {
    OKF("Track Mode.");
  } else if (DFSanMode) {
    OKF("DFSan Mode.");
  } else {
    FastMode = true;
    OKF("Fast Mode.");

    initVariables(M);


  }
}