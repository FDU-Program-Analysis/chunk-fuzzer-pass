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
        
    }
