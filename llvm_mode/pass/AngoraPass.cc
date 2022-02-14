#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <unordered_set>
#include <utility>

// LLVM
#include "llvm/ADT/DenseSet.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

// Angora
#include "./abilist.h"
#include "./debug.h"
#include "./defs.h"
#include "./util.h"
#include "./version.h"
#include "CtorDtorFuncs.hpp"
using namespace llvm;
// only do taint tracking, used for compile 3rd libraries.
static cl::opt<bool> DFSanMode("DFSanMode", cl::desc("dfsan mode"), cl::Hidden);

static cl::opt<bool> TrackMode("TrackMode", cl::desc("track mode"), cl::Hidden);

static cl::list<std::string> ClABIListFiles(
    "angora-dfsan-abilist",
    cl::desc("file listing native abi functions and how the pass treats them"),
    cl::Hidden);

static cl::list<std::string> ClExploitListFiles(
    "angora-exploitation-list",
    cl::desc("file listing functions and instructions to exploit"), cl::Hidden);

namespace {

#define MAX_EXPLOIT_CATEGORY 5
const char *ExploitCategoryAll = "all";
const char *ExploitCategory[] = {"i0", "i1", "i2", "i3", "i4", "i5"};
const char *CompareFuncCat = "cmpfn";
char COUNT_PTR_SYMBOL[] = "__branch_count_table_ptr";
char SUB_COUNT_PTR_SYMBOL[] = "__branch_count_sub_table_ptr";
char COUNT_ALLOCATOR_SYMBOL[] = "__alloc_branch_count_table";
char IND_FUNC_PTR_SYMBOL[] = "__branch_count_indirect_func_ptr";
char SORT_FUNC_MAP_SYMBOL[] = "__branch_table_sort_function_map";
char DYN_RSLV_SYMBOL[] = "__branch_table_dynamic_resolve_base_ptr";

using std::make_pair;
using std::max;
using std::unordered_map;
using std::unordered_set;
using std::vector;

typedef std::pair<BasicBlock *, BasicBlock *> Edge;

class IndFuncType {
 public:
  std::vector<llvm::Constant *> data{};
  size_t size = 0;
  llvm::GlobalVariable *symbolPtr = nullptr;
  llvm::ConstantInt *symbolLen = nullptr;

  IndFuncType() = default;
};

class TypePairHash;

class TypePair {
  friend TypePairHash;

  llvm::Type *first, *second;

 public:
  TypePair(llvm::Type *first, llvm::Type *second)
      : first{first}, second{second} {
    if ((size_t)first > (size_t)second) std::swap(this->first, this->second);
  }

  bool operator==(const TypePair &other) const {
    return first == other.first && second == other.second;
  }

  ~TypePair() = default;
};

class TypePairHash {
 public:
  size_t operator()(const TypePair &pair) const {
    return (size_t)pair.first ^ (size_t)pair.second;
  }
};

class TypeSet {
 private:
  typedef std::unordered_map<llvm::Type *, std::pair<llvm::Type *, size_t>> Set;
  typedef typename Set::iterator iterator;

  Set set;

  iterator makeSet(llvm::Type *a) {
    auto ptr = set.find(a);
    if (ptr != set.end())
      return ptr;
    else
      return set.emplace(make_pair(a, std::make_pair(a, 0))).first;
  }

  iterator findSetPtr(llvm::Type *a) {
    auto index = set.find(a);
    if (index->second.first != a) {
      auto newIndex = findSetPtr(index->second.first);
      index->second.first = newIndex->second.first;
      index = newIndex;
    }
    return index;
  }

 public:
  TypeSet() : set{} {}

  llvm::Type *findSet(llvm::Type *a) {
    auto ptr = set.find(a);
    if (ptr == set.end()) return a;

    auto index = ptr->second.first;
    if (index != a) index = findSet(index);
    return index;
  }

  void unionSet(llvm::Type *a, llvm::Type *b) {
    makeSet(a);
    makeSet(b);

    auto rootA = findSetPtr(a);
    auto rootB = findSetPtr(b);

    if (rootA == rootB) return;

    if (rootA->second.second > rootB->second.second) {
      rootB->second.first = rootA->second.first;
    } else {
      if (rootA->second.second == rootB->second.second)
        ++(rootB->second.second);
      rootA->second.first = rootB->second.first;
    }
  }

  ~TypeSet() = default;
};

// hash file name and file size
u32 hashName(std::string str) {
  std::ifstream in(str, std::ifstream::ate | std::ifstream::binary);
  u32 fsize = in.tellg();
  u32 hash = 5381 + fsize * 223;
  for (auto c : str)
    hash = ((hash << 5) + hash) + (unsigned char)c; /* hash * 33 + c */
  return hash;
}

class AngoraLLVMPass : public ModulePass {
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
  IntegerType *Int1Ty = nullptr;
  IntegerType *Int8Ty = nullptr;
  IntegerType *Int16Ty = nullptr;
  IntegerType *Int32Ty = nullptr;
  IntegerType *Int64Ty = nullptr;
  Type *VoidTy = nullptr;
  Type *Int8PtrTy = nullptr;
  Type *Int16PtrTy = nullptr;
  Type *Int64PtrTy = nullptr;
  Type *VoidPtrTy = nullptr;
  Constant *Int8PtrNull = nullptr;
  Constant *Int16PtrNull = nullptr;

  // Global vars
  // GlobalVariable *AngoraMapPtr;
  // GlobalVariable *AngoraPrevLoc;
  GlobalVariable *AngoraContext;
  GlobalVariable *AngoraCondId;
  GlobalVariable *AngoraCallSite;
  GlobalVariable *AngoraBranchCount;

  FunctionCallee TraceCmp;
  FunctionCallee TraceSw;
  FunctionCallee TraceCmpTT;
  FunctionCallee TraceSwTT;
  FunctionCallee TraceFnTT;
  FunctionCallee TraceExploitTT;

  FunctionCallee TraceExploitDiv;
  FunctionCallee TraceExploitDivTT;
  FunctionCallee TraceExploitIntflow;
  FunctionCallee TraceExploitIntflowTT;
  FunctionCallee TraceExploitMemArg;
  FunctionCallee TraceExploitMemArgTT;

  typedef unordered_map<Instruction *, vector<bool>> OptMap;
  typedef unordered_set<TypePair, TypePairHash> Done;
  typedef unordered_map<Function *, size_t> SizeMap;
  typedef unordered_map<Type *, IndFuncType> FuncMap;

  // Custom setting
  AngoraABIList ABIList;
  AngoraABIList ExploitList;

  // Constructor and deconstructors in the module.
  const CtorDtorFuncs *CDF = nullptr;
  unsigned InstIdMeta;

  AngoraLLVMPass() : ModulePass(ID) {}
  bool runOnModule(Module &M) override;
  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<LoopInfoWrapperPass>();
  }

  void runOnFunctionFastMode(Function *func);
  void runOnFunctionFastModeCond(Function *func);
  void runOnFunctionFastModeExpInt(Function *func);
  void runOnFunctionFastModeExpMem(Function *func);

  void runOnFunctionTrackMode(Function *func);

  u32 getInstructionId(Instruction *Inst);

  u32 initInstructionId(LLVMContext &C, Instruction *Inst);
  bool skipBasicBlock();
  u32 getRandomNum();
  void setRandomNumSeed(u32 seed);
  u32 getRandomContextId();
  u32 getRandomInstructionId();

  Value *castArgType(IRBuilder<> &IRB, Value *V);
  void initVariables(Module &M);
  void countEdge(Module &M, BasicBlock &BB);

  // visit functions for virgin code
  void visitCallInstVirgin(Instruction *Inst);

  void visitCallInst(Instruction *Inst);
  void visitInvokeInst(Instruction *Inst);
  void visitCompareFunc(Instruction *Inst);
  void visitBranchInst(Instruction *Inst);
  void visitCmpInst(Instruction *Inst);
  void processCmp(Instruction *Cond, Constant *Cid, Instruction *InsertPoint);
  void processBoolCmp(Value *Cond, Constant *Cid, Instruction *InsertPoint);
  void visitSwitchInst(Module &M, Instruction *Inst);
  void processCall(Instruction *Inst);
  void addFnWrap(Function *F);
  size_t branchInstrument(Module &module, SizeMap &sizeMap);
  void pathOptimize(Function &func, OptMap &optMap);
  void naivePathOptimize(Function &func, OptMap &optMap);
  void loopPathOptimize(Function &func, OptMap &optMap);
  void typeUnion(Module &module, TypeSet &set, Done &done, Type *a, Type *b);
  void typeConstant(Module &module, TypeSet &set, Done &done, Constant *dest);
  void typeAnalysis(Module &module, TypeSet &set);
  void indirectFuncCallAnalysis(Module &module, SizeMap &sizeMap,
                                TypeSet &typeSet, FuncMap &funcMap);
  size_t funcCallInstrument(Module &module, SizeMap &sizeMap, TypeSet &typeSet,
                            FuncMap &funcMap, size_t branchCount);
  void bootstrapInstrument(Module &module, FuncMap &funcMap,
                           size_t branchCount);

  void visitIntExploitation(Instruction *inst);
  void exploitDiv(Instruction *inst);
  void exploitIntflow(Instruction *inst);
  void visitMemExploitation(Instruction *inst);
  void exploitMemArg(Instruction *inst, Value *exploitable_arg,
                     unsigned exp_id);
};

}  // namespace

char AngoraLLVMPass::ID = 0;

bool AngoraLLVMPass::skipBasicBlock() { return (random() % 100) >= inst_ratio; }

// http://pubs.opengroup.org/onlinepubs/009695399/functions/rand.html
u32 AngoraLLVMPass::getRandomNum() {
  RandSeed = RandSeed * 1103515245 + 12345;
  return (u32)RandSeed;
}

void AngoraLLVMPass::setRandomNumSeed(u32 seed) { RandSeed = seed; }

u32 AngoraLLVMPass::getRandomContextId() {
  u32 context = getRandomNum() % MAP_SIZE;
  if (output_cond_loc) {
    errs() << "[CONTEXT] " << context << "\n";
  }
  return context;
}

u32 AngoraLLVMPass::getRandomInstructionId() { return getRandomNum(); }

u32 AngoraLLVMPass::getInstructionId(Instruction *Inst) {
  if (Inst) {
    auto meta = Inst->getMetadata(InstIdMeta);
    auto &metaOp = meta->getOperand(0);
    if (ValueAsMetadata *valmeta = dyn_cast<ValueAsMetadata>(metaOp)) {
      Value *val = valmeta->getValue();
      if (ConstantInt *ci = dyn_cast<ConstantInt>(val)) {
        return ci->getZExtValue();
      }
    }
    WARNF("Asking for instruction with no ID. ");
    errs() << *Inst << '\n';
  }

  return 0;
}
u32 AngoraLLVMPass::initInstructionId(LLVMContext &C, Instruction *Inst) {
  u32 h = 0;
  if (is_bc) {
    h = ++CidCounter;
    // Save the first three bits for exploitation purposes.
    h = h & 0x1fffffff;
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
    // Save the first three bits for exploitation purposes.
    // Although this code is not used, since valkyrie needs bc.
    // But it is written here for consistency purposes.
    h = h & 0x1fffffff;
    while (UniqCidSet.count(h) > 0) {
      h = (h * 3 + 1) & 0x1fffffff;
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

  Inst->setMetadata(
      InstIdMeta,
      MDNode::get(C, ValueAsMetadata::get(ConstantInt::get(Int32Ty, h))));
  return h;
}

void AngoraLLVMPass::initVariables(Module &M) {
  // To ensure different version binaries have the same id
  ModName = M.getModuleIdentifier();
  if (ModName.size() == 0) {
    FATAL("No ModName!\n");
  }
#if LTO
  is_bc = true;
  // ModId is used to set random seed for random edge id,
  // which should be useless in LTO.
  // Besides, ModName will always be the same, giving the
  // same ModId anyway.
  ModId = 0;
#else
  is_bc = 0 == ModName.compare(ModName.length() - 3, 3, ".bc");
  ModId = is_bc ? 0 : hashName(ModName);
#endif
  errs() << "ModName: " << ModName << " -- " << ModId << "\n";
  if (is_bc) {
    errs() << "Input is the whole program's LLVM bitcode\n";
  }

  char *inst_ratio_str = getenv("ANGORA_INST_RATIO");
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
  initMeta(C);
  VoidTy = Type::getVoidTy(C);
  Int1Ty = IntegerType::getInt1Ty(C);
  Int8Ty = IntegerType::getInt8Ty(C);
  Int16Ty = IntegerType::getInt16Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int8PtrTy = PointerType::getUnqual(Int8Ty);
  Int16PtrTy = PointerType::getUnqual(Int16Ty);
  Int64PtrTy = PointerType::getUnqual(Int64Ty);
  // VoidPtrTy = PointerType::getUnqual(VoidTy);
  Int8PtrNull = Constant::getNullValue(Int8PtrTy);
  Int16PtrNull = Constant::getNullValue(Int16PtrTy);

  ColdCallWeights = MDBuilder(C).createBranchWeights(1, 1000);

  InstIdMeta = C.getMDKindID("inst_id");

  AngoraContext =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_context", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);

  AngoraCallSite =
      new GlobalVariable(M, Int32Ty, false, GlobalValue::CommonLinkage,
                         ConstantInt::get(Int32Ty, 0), "__angora_call_site", 0,
                         GlobalVariable::GeneralDynamicTLSModel, 0, false);
  if (FastMode) {
    /* AngoraMapPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                      GlobalValue::ExternalLinkage, 0,
                                      "__angora_area_ptr"); */
    AngoraCondId =
        new GlobalVariable(M, Int32Ty, false, GlobalValue::ExternalLinkage, 0,
                           "__angora_cond_cmpid");

    GET_OR_INSERT_FUNCTION(TraceExploitDiv, VoidTy,
                           "__angora_trace_exploit_div",
                           {Int32Ty, Int32Ty, Int32Ty, Int64Ty})
    GET_OR_INSERT_FUNCTION(TraceExploitIntflow, VoidTy,
                           "__angora_trace_exploit_intflow",
                           {Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty})
    GET_OR_INSERT_FUNCTION(TraceExploitMemArg, VoidTy,
                           "__angora_trace_exploit_mem_arg",
                           {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty})
    GET_OR_INSERT_FUNCTION(TraceCmp, Int32Ty, "__angora_trace_cmp",
                           {Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty});
    GET_OR_INSERT_FUNCTION(TraceSw, Int64Ty, "__angora_trace_switch",
                           {Int32Ty, Int32Ty, Int64Ty});

  } else if (TrackMode) {
    GET_OR_INSERT_FUNCTION(
        TraceCmpTT, VoidTy, "__angora_trace_cmp_tt",
        {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int64Ty, Int32Ty})
    GET_OR_INSERT_FUNCTION(
        TraceSwTT, VoidTy, "__angora_trace_switch_tt",
        {Int32Ty, Int32Ty, Int32Ty, Int64Ty, Int32Ty, Int64PtrTy})
    GET_OR_INSERT_FUNCTION(TraceFnTT, VoidTy, "__angora_trace_fn_tt",
                           {Int32Ty, Int32Ty, Int64Ty, Int8PtrTy, Int8PtrTy})
    GET_OR_INSERT_FUNCTION(TraceExploitTT, VoidTy,
                           "__angora_trace_exploit_val_tt",
                           {Int32Ty, Int32Ty, Int32Ty, Int32Ty, Int64Ty})
    GET_OR_INSERT_FUNCTION(TraceExploitDivTT, VoidTy,
                           "__angora_trace_exploit_div_tt",
                           {Int32Ty, /*Int32Ty,*/ Int32Ty, Int32Ty, Int64Ty})
    GET_OR_INSERT_FUNCTION(
        TraceExploitIntflowTT, VoidTy, "__angora_trace_exploit_intflow_tt",
        {Int32Ty, /*Int32Ty,*/ Int32Ty, Int32Ty, Int64Ty, Int64Ty})
    GET_OR_INSERT_FUNCTION(
        TraceExploitMemArgTT, VoidTy, "__angora_trace_exploit_mem_arg_tt",
        {Int32Ty, /*Int32Ty,*/ Int32Ty, Int32Ty, Int32Ty, Int64Ty})
  }

  std::vector<std::string> AllABIListFiles;
  AllABIListFiles.insert(AllABIListFiles.end(), ClABIListFiles.begin(),
                         ClABIListFiles.end());
  ABIList.set(
      SpecialCaseList::createOrDie(AllABIListFiles, *vfs::getRealFileSystem()));

  std::vector<std::string> AllExploitListFiles;
  AllExploitListFiles.insert(AllExploitListFiles.end(),
                             ClExploitListFiles.begin(),
                             ClExploitListFiles.end());
  ExploitList.set(SpecialCaseList::createOrDie(AllExploitListFiles,
                                               *vfs::getRealFileSystem()));

  gen_id_random = !!getenv(GEN_ID_RANDOM_VAR);
  output_cond_loc = !!getenv(OUTPUT_COND_LOC_VAR);

  num_fn_ctx = -1;
  char *custom_fn_ctx = getenv(CUSTOM_FN_CTX);
  if (custom_fn_ctx) {
    num_fn_ctx = atoi(custom_fn_ctx);
    if (num_fn_ctx < 0 || num_fn_ctx >= 32) {
      errs() << "custom context should be: >= 0 && < 32 \n";
      exit(1);
    }
  }

  if (num_fn_ctx == 0) {
    errs() << "disable context\n";
  }

  if (num_fn_ctx > 0) {
    errs() << "use custom function call context: " << num_fn_ctx << "\n";
  }

  if (gen_id_random) {
    errs() << "generate id randomly\n";
  }

  if (output_cond_loc) {
    errs() << "Output cond log\n";
  }
};

void AngoraLLVMPass::pathOptimize(Function &func, OptMap &optMap) {
  if (getenv("NAVIE_PATH_OPT")) {
    OKF("Using naivePathOptimize");
    naivePathOptimize(func, optMap);
  } else {
    loopPathOptimize(func, optMap);
  }
}
void AngoraLLVMPass::loopPathOptimize(Function &func, OptMap &optMap) {
  // Whether to keep an edge or not.
  std::map<Edge, bool> keep;

  // Init
  for (BasicBlock &bb : func) {
    Instruction *terminator = bb.getTerminator();
    unsigned int numSuccessors = terminator->getNumSuccessors();
    for (int i = 0; i < numSuccessors; i++) {
      BasicBlock *successor = terminator->getSuccessor(i);
      keep[Edge(&bb, successor)] = false;
    }
  }

  // For each loop, instrument it's backedge(s)
  LoopInfo &LI = getAnalysis<LoopInfoWrapperPass>(func).getLoopInfo();
  // Somehow LI's own iterator doesn't return all loops, so use
  // getLoopsInPreorder.
  for (Loop *loop : LI.getLoopsInPreorder()) {
    BasicBlock *header = loop->getHeader();
    Instruction *terminator = header->getTerminator();
    unsigned int numSuccessors = terminator->getNumSuccessors();
    for (int i = 0; i < numSuccessors; i++) {
      BasicBlock *successor = terminator->getSuccessor(i);
      if (loop->contains(successor)) {
        keep[Edge(header, successor)] = true;
      }
    }
  }

  // For all blocks with multiple out going edges, leave one uninstrumented.
  for (BasicBlock &bb : func) {
    Instruction *terminator = bb.getTerminator();
    unsigned int numSuccessors = terminator->getNumSuccessors();
    unsigned int numFalse = 0;
    for (int i = 0; i < numSuccessors; i++) {
      BasicBlock *successor = terminator->getSuccessor(i);
      if (isHelperBlock(successor)) {
        continue;
      }
      Edge e = Edge(&bb, successor);
      if (!keep[e]) {
        if (numFalse == 0) {
          numFalse++;
        } else {
          keep[e] = true;
        }
      }
    }
  }

  // Organize it in the form of optMap
  for (BasicBlock &bb : func) {
    Instruction *terminator = bb.getTerminator();
    unsigned int numSuccessors = terminator->getNumSuccessors();
    std::vector<bool> doDelete;
    for (int i = 0; i < numSuccessors; i++) {
      BasicBlock *successor = terminator->getSuccessor(i);
      doDelete.push_back(!keep[Edge(&bb, successor)]);
    }
    optMap[terminator] = doDelete;
  }
}

void AngoraLLVMPass::naivePathOptimize(Function &func, OptMap &optMap) {
  for (auto &block : func) {
    if (block.getTerminator()->getNumSuccessors() < 2) {
      continue;
    }

    auto *successor = &block;
    auto *predecessor = block.getSinglePredecessor();
    while (predecessor != nullptr) {
      auto *terminator = predecessor->getTerminator();
      unsigned int numSuccessors = terminator->getNumSuccessors();
      if (numSuccessors > 1) {
        auto result = optMap.find(terminator);
        for (unsigned int i = 0; i < numSuccessors; ++i) {
          if (terminator->getSuccessor(i) == successor) {
            if (result == optMap.end()) {
              auto optTable = vector<bool>(numSuccessors, false);
              optTable[i] = true;
              optMap[terminator] = optTable;
            } else {
              result->second[i] = true;
            }
            break;
          }
        }
        break;
      }
      successor = predecessor;
      predecessor = predecessor->getSinglePredecessor();
    }
  }
}

size_t AngoraLLVMPass::branchInstrument(Module &module, SizeMap &sizeMap) {
  auto &context = module.getContext();
  IRBuilder<> builder(context);
#ifdef __x86_64__
  IntegerType *isize = IntegerType::getInt64Ty(context);
#else
  IntegerType *isize = IntegerType::getInt32Ty(context);
#endif

  // OKF("Instrumenting branches");

  auto *branchBase = module.getGlobalVariable(SUB_COUNT_PTR_SYMBOL, true);

  size_t maxSize = 0;
  for (Function &func : module) {
    if (func.isDeclaration() ||
        func.getName().startswith(StringRef("asan.module")) ||
        func.getName().startswith(StringRef("magma")) ||
        CDF->isCtorDtor(func)) {
      continue;
    }
    OptMap optMap{};

    pathOptimize(func, optMap);

    size_t funcCount = 0;

    builder.SetInsertPoint(&(*func.getEntryBlock().getFirstInsertionPt()));
    auto *branchTable = builder.CreateLoad(branchBase);
    setInsNoSan(branchTable);

    for (auto &block : func) {
      auto *terminator = block.getTerminator();
      size_t numSuccessors = terminator->getNumSuccessors();
      if (numSuccessors < 2) {
        continue;
      }

      auto result = optMap.find(terminator);
      auto optTable = result == optMap.end()
                          ? vector<bool>(numSuccessors, false)
                          : result->second;

      for (size_t i = 0; i < numSuccessors; ++i) {
        if (optTable[i]) {
          continue;
        }
        /*
        errs() << funcCount << " " << block << "\n->"
               << *terminator->getSuccessor(i) << "\n";
        */
        /// code inject
        builder.SetInsertPoint(
            &(*terminator->getSuccessor(i)->getFirstInsertionPt()));
        auto *branchIdx = builder.CreateInBoundsGEP(
            branchTable, ConstantInt::get(isize, funcCount));
        setValueNoSan(branchIdx);
        setValueInstrumented(branchIdx);
        auto *branchEntry = builder.CreateLoad(branchIdx);
        setInsNoSan(branchEntry);
        auto *branchVal =
            builder.CreateAdd(branchEntry, ConstantInt::get(Int16Ty, 1));
        setValueNoSan(branchVal);
        setInsNoSan(builder.CreateStore(branchVal, branchIdx));

        ++funcCount;
      }
    }
    maxSize = max(maxSize, funcCount);
    if (funcCount == 0)
      branchTable->eraseFromParent();
    else
      sizeMap[&func] = funcCount;
  }
  return maxSize;
}

void AngoraLLVMPass::typeUnion(Module &module, TypeSet &set, Done &done,
                               Type *a, Type *b) {
  if (a == b) return;
  TypePair pair{a, b};
  if (done.find(pair) == done.end())
    done.emplace(pair);
  else
    return;

  auto *a_func = dyn_cast<FunctionType>(a);
  auto *b_func = dyn_cast<FunctionType>(b);
  if (a_func != nullptr && b_func != nullptr) {
    if (a_func->isVarArg() && b_func->isVarArg()) {
      set.unionSet(a_func, b_func);  // todo: variable arguments
      return;
    }

    size_t aNum = a_func->getNumParams();
    size_t bNum = b_func->getNumParams();
    if (aNum == bNum) {
      set.unionSet(a_func, b_func);

      for (size_t i = 0; i < aNum; ++i) {
        auto *a_arg = a_func->getParamType(i);
        auto *b_arg = b_func->getParamType(i);
        typeUnion(module, set, done, a_arg, b_arg);
      }
      return;
    }
  }

  auto *a_ptr = dyn_cast<PointerType>(a);
  auto *b_ptr = dyn_cast<PointerType>(b);
  if (a_ptr != nullptr && b_ptr != nullptr) {
    auto a_type = a_ptr->getPointerElementType();
    auto b_type = b_ptr->getPointerElementType();
    typeUnion(module, set, done, a_type, b_type);
    return;
  }

  auto *a_arr = dyn_cast<ArrayType>(a);
  auto *b_arr = dyn_cast<ArrayType>(b);
  if (a_arr != nullptr && b_arr != nullptr) {
    auto a_type = a_arr->getElementType();
    auto b_type = b_arr->getElementType();
    typeUnion(module, set, done, a_type, b_type);
    return;
  }

  auto *a_vec = dyn_cast<VectorType>(a);
  auto *b_vec = dyn_cast<VectorType>(b);
  if (a_vec != nullptr && b_vec != nullptr) {
    auto a_type = a_vec->getElementType();
    auto b_type = b_vec->getElementType();
    typeUnion(module, set, done, a_type, b_type);
    return;
  }

  auto *a_struct = dyn_cast<StructType>(a);
  auto *b_struct = dyn_cast<StructType>(b);
  if (a_struct != nullptr && b_struct != nullptr) {
    auto &layout = module.getDataLayout();
    auto *aLayout = layout.getStructLayout(a_struct);
    auto *bLayout = layout.getStructLayout(b_struct);

    size_t aIdx = 0, bIdx = 0;
    while (aIdx < a_struct->getStructNumElements() &&
           bIdx < b_struct->getStructNumElements()) {
      size_t aOffset = aLayout->getElementOffset(aIdx);
      size_t bOffset = bLayout->getElementOffset(bIdx);

      if (aOffset == bOffset) {
        auto *a_type = a_struct->getStructElementType(aIdx);
        auto *b_type = b_struct->getStructElementType(bIdx);
        typeUnion(module, set, done, a_type, b_type);
      }

      if (aOffset <= bOffset) ++aIdx;
      if (aOffset >= bOffset) ++bIdx;
    }
  }
}

void AngoraLLVMPass::typeConstant(Module &module, TypeSet &set, Done &done,
                                  Constant *dest) {
  auto *expr = dyn_cast<ConstantExpr>(dest);
  if (expr != nullptr) {
    if (expr->isCast()) {
      auto *src = expr->getOperand(0);
      auto *dest_type = dest->getType();
      auto *src_type = src->getType();
      if (dest_type != src_type)
        typeUnion(module, set, done, dest_type, src_type);
    }

    for (auto &op : expr->operands()) {
      auto *value = dyn_cast<Constant>(op.get());
      if (value != nullptr) typeConstant(module, set, done, value);
    }

    return;
  }

  auto *aggregate = dyn_cast<ConstantAggregate>(dest);
  if (aggregate != nullptr) {
    Constant *value = aggregate->getAggregateElement(0U);
    for (size_t i = 0; value != nullptr;
         ++i, value = aggregate->getAggregateElement(i))
      typeConstant(module, set, done, value);

    return;
  }
}

void AngoraLLVMPass::typeAnalysis(Module &module, TypeSet &set) {
  Done done{};

  for (auto &var : module.getGlobalList())
    if (var.hasInitializer())
      typeConstant(module, set, done, var.getInitializer());

  for (auto &func : module) {
    for (auto &block : func) {
      for (auto &inst : block) {
        auto bitCast = dyn_cast<BitCastInst>(&inst);
        if (bitCast != nullptr)
          typeUnion(module, set, done, bitCast->getType(),
                    bitCast->getOperand(0)->getType());

        for (auto &op : inst.operands()) {
          auto *value = dyn_cast<Constant>(op.get());
          if (value != nullptr) typeConstant(module, set, done, value);
        }
      }
    }
  }
}

void AngoraLLVMPass::indirectFuncCallAnalysis(Module &module, SizeMap &sizeMap,
                                              TypeSet &typeSet,
                                              FuncMap &funcMap) {
  auto &context = module.getContext();
  IntegerType *i8 = IntegerType::getInt8Ty(context);
#ifdef __x86_64__
  IntegerType *isize = IntegerType::getInt64Ty(context);
#else
  IntegerType *isize = IntegerType::getInt32Ty(context);
#endif
  auto *i8_ptr = PointerType::get(i8, 0);
  auto *ind_tuple = StructType::get(i8_ptr, isize);

  for (auto &func : module) {
    auto funcSize = sizeMap.find(&func);
    if (funcSize == sizeMap.end() || CDF->isCtorDtor(func)) {
      continue;
    }

    for (auto *user : func.users()) {
      CallBase *callBase = dyn_cast<CallBase>(user);
      if (callBase != nullptr) {
        Function *calledFunction = callBase->getCalledFunction();
        if (calledFunction == &func) continue;
      }

      auto *func_type =
          typeSet.findSet(func.getType()->getPointerElementType());
      auto typeEntry = funcMap.find(func_type);
      if (typeEntry == funcMap.end()) {
        auto newPair = make_pair(func_type, IndFuncType{});
        typeEntry = funcMap.emplace(newPair).first;
      }

      auto *funcPtr = ConstantExpr::getBitCast(&func, i8_ptr);
      auto *funcOffset = ConstantInt::get(isize, typeEntry->second.size);
      auto *indPair = ConstantStruct::get(ind_tuple, funcPtr, funcOffset);

      typeEntry->second.data.push_back(indPair);
      typeEntry->second.size += funcSize->second;

      break;
    }
  }

  for (auto &pair : funcMap) {
    auto &value = pair.second;
    size_t arraySize = value.data.size();

    auto *ind_array = ArrayType::get(ind_tuple, arraySize);

    auto *indFuncPtrInit =
        ConstantArray::get(ind_array, ArrayRef<Constant *>(value.data));
    value.symbolPtr = new GlobalVariable(module, ind_array, false,
                                         GlobalVariable::InternalLinkage,
                                         indFuncPtrInit, IND_FUNC_PTR_SYMBOL);
    value.symbolLen = ConstantInt::get(isize, arraySize);
  }
}

size_t AngoraLLVMPass::funcCallInstrument(Module &module, SizeMap &sizeMap,
                                          TypeSet &typeSet, FuncMap &funcMap,
                                          size_t branchCount) {
  OKF("Instrumenting function calls.");
  auto &context = module.getContext();
  IRBuilder<> builder(context);

  IntegerType *i8 = IntegerType::getInt8Ty(context);
#ifdef __x86_64__
  IntegerType *isize = IntegerType::getInt64Ty(context);
#else
  IntegerType *isize = IntegerType::getInt32Ty(context);
#endif
  auto *i8_ptr = PointerType::get(i8, 0);
  auto *ind_tuple = StructType::get(i8_ptr, isize);
  auto *ind_tuple_ptr = PointerType::get(ind_tuple, 0);
  auto *dyn_rslv =
      FunctionType::get(isize, {isize, i8_ptr, ind_tuple_ptr, isize}, false);

  GlobalVariable *branchPtr = module.getGlobalVariable(COUNT_PTR_SYMBOL, true);
  GlobalVariable *branchBase =
      module.getGlobalVariable(SUB_COUNT_PTR_SYMBOL, true);
  FunctionCallee dynRslv =
      module.getOrInsertFunction(DYN_RSLV_SYMBOL, dyn_rslv);

  auto *zero = ConstantInt::get(isize, 0);

  for (auto &func : module) {
    if (func.isDeclaration() ||
        func.getName().startswith(StringRef("asan.module")) ||
        func.getName().startswith(StringRef("magma")) ||
        CDF->isCtorDtor(func)) {
      continue;
    }

    if (func.getName() == "main") {
      auto result = sizeMap.find(&func);
      if (result != sizeMap.end()) {
        builder.SetInsertPoint(&(*func.getEntryBlock().getFirstInsertionPt()));
        LoadInst *branchTable = builder.CreateLoad(branchPtr);
        setInsNoSan(branchTable);
        auto *branchIdx = builder.CreateInBoundsGEP(
            branchTable, ConstantInt::get(isize, branchCount));
        setValueNoSan(branchIdx);
        setInsNoSan(builder.CreateStore(branchIdx, branchBase));

        branchCount += result->second;
      }
    }

    for (auto &block : func) {
      for (auto &inst : block) {
        CallBase *callBase = dyn_cast<CallBase>(&inst);
        if (!callBase) {
          continue;
        }
        Value *calledValue = callBase->getCalledOperand();
        Function *calledFunction =
            dyn_cast<Function>(calledValue->stripPointerCasts());

        // Don't instrument certain function calls.
        if (calledFunction &&
            (calledFunction->isDeclaration() ||
             calledFunction->getName().startswith(StringRef("asan.module")) ||
             calledFunction->getName().startswith(StringRef("magma")) ||
             CDF->isCtorDtor(calledFunction))) {
          continue;
        }

        builder.SetInsertPoint(&inst);
        auto *branchTable = builder.CreateLoad(branchPtr);
        setInsNoSan(branchTable);

        if (calledFunction != nullptr) {
          // direct function call
          auto result = sizeMap.find(calledFunction);
          if (result != sizeMap.end()) {
            // local function call
            auto *contextOffset = ConstantInt::get(isize, branchCount);

            auto *branchIdx =
                builder.CreateInBoundsGEP(branchTable, contextOffset);
            setValueNoSan(branchIdx);
            setInsNoSan(builder.CreateStore(branchIdx, branchBase));

            branchCount += result->second;
          } else {
            // foreign function call
            setInsNoSan(builder.CreateStore(branchTable, branchBase));
          }
        } else if (callBase->isIndirectCall()) {
          // indirect function call
          auto *calledType =
              typeSet.findSet(calledValue->getType()->getPointerElementType());
          auto result = funcMap.find(calledType);
          if (result != funcMap.end()) {
            // has type
            auto *funcPtr = builder.CreateBitCast(calledValue, i8_ptr);
            setValueNoSan(funcPtr);
            auto *typePtr =
                builder.CreateGEP(result->second.symbolPtr, {zero, zero});
            setValueNoSan(typePtr);
            auto *branchOffset = builder.CreateCall(
                dynRslv, {
                             ConstantInt::get(isize, branchCount),
                             funcPtr,
                             typePtr,
                             result->second.symbolLen,
                         });
            setInsNoSan(branchOffset);
            auto *branchIdx =
                builder.CreateInBoundsGEP(branchTable, branchOffset);
            setValueNoSan(branchIdx);
            setInsNoSan(builder.CreateStore(branchIdx, branchBase));

            branchCount += result->second.size;
          } else {
            // no type
            setInsNoSan(builder.CreateStore(branchTable, branchBase));
          }
        } else {
          // todo: other kinds of call site
          errs() << "[!] Branch Table: Unknown call site: \"";
          inst.print(errs());
          errs() << "\"\n";
        }
      }
    }
  }

  return branchCount;
}

void AngoraLLVMPass::bootstrapInstrument(Module &module, FuncMap &funcMap,
                                         size_t branchCount) {
  OKF("Adding branch counting initialization function calls");
  auto &context = module.getContext();
  IRBuilder<> builder(context);

  IntegerType *i8 = IntegerType::getInt8Ty(context);
#ifdef __x86_64__
  IntegerType *isize = IntegerType::getInt64Ty(context);
#else
  IntegerType *isize = IntegerType::getInt32Ty(context);
#endif
  auto *i8_ptr = PointerType::get(i8, 0);
  auto *ind_tuple = StructType::get(i8_ptr, isize);
  auto *ind_tuple_ptr = PointerType::get(ind_tuple, 0);
  auto *branch_allocator = FunctionType::get(Int16PtrTy, {isize, isize}, false);
  auto *sort_func_map = FunctionType::get(Type::getVoidTy(context),
                                          {ind_tuple_ptr, isize}, false);

  auto *branchPtr = module.getGlobalVariable(COUNT_PTR_SYMBOL, true);
  FunctionCallee branchAllocator =
      module.getOrInsertFunction(COUNT_ALLOCATOR_SYMBOL, branch_allocator);
  FunctionCallee sortFuncMap =
      module.getOrInsertFunction(SORT_FUNC_MAP_SYMBOL, sort_func_map);

  auto *zero = ConstantInt::get(isize, 0);

  /*
   * Move valkyrie initializer to the top of the program.
   * The start of the program would look like this:
   *
   * ```
   * __libc_start_main
   * __libc_csu_init
   * // ... All init functions stored in `llvm.global_ctors`
   * main
   * ```
   *
   * Before, we put initializer right after main. However, some programs
   * have initializer code registered and are also instrumented.
   * These code has two types:
   *
   * - C functions labelled with attribute constructor
   * - C++ static constructor.
   *
   * The previous one is taken care of using `CtorDtorFuncs` and is not
   * instrumented. The later is tricker since we can't just 'not' instrument it,
   * c++ constructors can be called both pre-main and after-main.
   *
   * This would cause a problem before main since the branch counting table is
   * not set up yet, the table pointer is a null pointer, yet the instrumented
   * code is trying to put hit count in the table.
   *
   * This leaves us with the following options:
   *
   * - Clonee constructors, the pre-main constructors get special,
   * non-instrumented copy.
   *    - Pro: No overhead.
   *    - Con: Difficult to implement
   * - Before incrmenting hit count in the table, always check if the table is
   *    - Pro: medium hard to implement
   *    - Con: Runtime overhead. Even with branch prediction, it would still
   *    cause over head everytime we access table.
   * - (We are using) Put initializer before main, before any other
   * initializers.
   *    - Pro: easy to implement
   *    - Con: Slightly add overhead to branch counting table since pre-main
   *    code don't need to be branch counted.
   */
  Function *TraceInit =
      getOrCreateInitFunction(module, "__valkyrie_init_branch_count");
  BasicBlock *BB = BasicBlock::Create(context, "entry", TraceInit);
  builder.SetInsertPoint(BB);
  auto *ptr = builder.CreateCall(branchAllocator,
                                 {ConstantInt::get(isize, sizeof(uint16_t)),
                                  ConstantInt::get(isize, branchCount)});
  setValueNoSan(ptr);
  setValueNoSan(builder.CreateStore(ptr, branchPtr));
  // sort indirect function map for better look up speed
  for (auto &pair : funcMap) {
    auto *basePtr = builder.CreateGEP(pair.second.symbolPtr, {zero, zero});
    builder.CreateCall(sortFuncMap, {basePtr, pair.second.symbolLen});
  }
  builder.CreateRetVoid();
  for (auto &func : module) {
    if (func.isDeclaration() ||
        func.getName().startswith(StringRef("asan.module")) ||
        func.getName().startswith(StringRef("magma")) ||
        CDF->isCtorDtor(func)) {
      continue;
    }
    if (func.getName() == "main") {
      // allocate branch count table
      builder.SetInsertPoint(&(*func.getEntryBlock().getFirstInsertionPt()));
      /*
      auto *ptr = builder.CreateCall(branchAllocator,
                                     {ConstantInt::get(isize, sizeof(uint16_t)),
                                      ConstantInt::get(isize, branchCount)});
      setValueNoSan(ptr);
      setValueNoSan(builder.CreateStore(ptr, branchPtr));

      // sort indirect function map for better look up speed
      for (auto &pair : funcMap) {
        auto *basePtr = builder.CreateGEP(pair.second.symbolPtr, {zero, zero});
        builder.CreateCall(sortFuncMap, {basePtr, pair.second.symbolLen});
      }
      */
      // Sequential call to forkserver after initialization
      FunctionCallee TraceInitFn = module.getOrInsertFunction(
          "__trace_init", FunctionType::get(VoidTy, false));
      builder.CreateCall(TraceInitFn);
    }
  }
}

// Coverage statistics: AFL's Branch count
// Angora enable function-call context.
void AngoraLLVMPass::countEdge(Module &M, BasicBlock &BB) {
  if (!FastMode || skipBasicBlock()) return;

  // LLVMContext &C = M.getContext();
  // unsigned int cur_loc = getRandomBasicBlockId();
  // ConstantInt *CurLoc = ConstantInt::get(Int32Ty, cur_loc);

  // BasicBlock::iterator IP = BB.getFirstInsertionPt();
  // IRBuilder<> IRB(&(*IP));

  // LoadInst *PrevLoc = IRB.CreateLoad(AngoraPrevLoc);
  // setInsNoSan(PrevLoc);

  // Value *PrevLocCasted = IRB.CreateZExt(PrevLoc, Int32Ty);
  // setValueNoSan(PrevLocCasted);

  // Get Map[idx]
  // LoadInst *MapPtr = IRB.CreateLoad(AngoraMapPtr);
  // setInsNoSan(MapPtr);

  // Value *BrId = IRB.CreateXor(PrevLocCasted, CurLoc);
  // setValueNoSan(BrId);
  // Value *MapPtrIdx = IRB.CreateGEP(MapPtr, BrId);
  // setValueNoSan(MapPtrIdx);

  // Increase 1 : IncRet <- Map[idx] + 1
  // LoadInst *Counter = IRB.CreateLoad(MapPtrIdx);
  // setInsNoSan(Counter);

  // Implementation of saturating counter.
  // Value *CmpOF = IRB.CreateICmpNE(Counter, ConstantInt::get(Int8Ty, -1));
  // setValueNoSan(CmpOF);
  // Value *IncVal = IRB.CreateZExt(CmpOF, Int8Ty);
  // setValueNoSan(IncVal);
  // Value *IncRet = IRB.CreateAdd(Counter, IncVal);
  // setValueNoSan(IncRet);

  // Implementation of Never-zero counter
  // The idea is from Marc and Heiko in AFLPlusPlus
  // Reference: :
  // https://github.com/vanhauser-thc/AFLplusplus/blob/master/llvm_mode/README.neverzero
  // and https://github.com/vanhauser-thc/AFLplusplus/issues/10

  // Value *IncRet = IRB.CreateAdd(Counter, ConstantInt::get(Int8Ty, 1));
  // setValueNoSan(IncRet);
  // Value *IsZero = IRB.CreateICmpEQ(IncRet, ConstantInt::get(Int8Ty, 0));
  // setValueNoSan(IsZero);
  // Value *IncVal = IRB.CreateZExt(IsZero, Int8Ty);
  // setValueNoSan(IncVal);
  // IncRet = IRB.CreateAdd(IncRet, IncVal);
  // setValueNoSan(IncRet);

  // Store Back Map[idx]
  // IRB.CreateStore(IncRet, MapPtrIdx)->setMetadata(NoSanMetaId, NoneMetaNode);

  // Value *NewPrevLoc = NULL;
  // if (num_fn_ctx != 0) { // Call-based context
  //   // Load ctx
  //   LoadInst *CtxVal = IRB.CreateLoad(AngoraContext);
  //   setInsNoSan(CtxVal);

  //   Value *CtxValCasted = IRB.CreateZExt(CtxVal, Int32Ty);
  //   setValueNoSan(CtxValCasted);
  //   // Udate PrevLoc
  //   NewPrevLoc =
  //       IRB.CreateXor(CtxValCasted, ConstantInt::get(Int32Ty, cur_loc >> 1));
  // } else { // disable context
  //   NewPrevLoc = ConstantInt::get(Int32Ty, cur_loc >> 1);
  // }
  // setValueNoSan(NewPrevLoc);

  // StoreInst *Store = IRB.CreateStore(NewPrevLoc, AngoraPrevLoc);
  // setInsNoSan(Store);
};

void AngoraLLVMPass::addFnWrap(Function *F) {
  if (num_fn_ctx == 0) return;

  // *** Pre Fn ***
  BasicBlock *BB = &(F->getEntryBlock());
  Instruction *InsertPoint = &(*(BB->getFirstInsertionPt()));
  IRBuilder<> IRB(InsertPoint);

  Value *CallSite = IRB.CreateLoad(AngoraCallSite);
  setValueNoSan(CallSite);

  Value *OriCtxVal = IRB.CreateLoad(AngoraContext);
  setValueNoSan(OriCtxVal);

  // ***** Add Context *****
  // instrument code before and after each function call to add context
  // We did `xor` simply.
  // This can avoid recursion. The effect of call in recursion will be removed
  // by `xor` with the same value
  // Implementation of function context for AFL by heiko eissfeldt:
  // https://github.com/vanhauser-thc/afl-patches/blob/master/afl-fuzz-context_sensitive.diff
  if (num_fn_ctx > 0) {
    OriCtxVal = IRB.CreateLShr(OriCtxVal, 32 / num_fn_ctx);
    setValueNoSan(OriCtxVal);
  }

  Value *UpdatedCtx = IRB.CreateXor(OriCtxVal, CallSite);
  setValueNoSan(UpdatedCtx);

  StoreInst *SaveCtx = IRB.CreateStore(UpdatedCtx, AngoraContext);
  setInsNoSan(SaveCtx);

  // *** Post Fn ***
  for (auto bb = F->begin(); bb != F->end(); bb++) {
    BasicBlock *BB = &(*bb);
    Instruction *Inst = BB->getTerminator();
    if (isa<ReturnInst>(Inst) || isa<ResumeInst>(Inst)) {
      // ***** Reload Context *****
      IRBuilder<> Post_IRB(Inst);
      Post_IRB.CreateStore(OriCtxVal, AngoraContext)
          ->setMetadata(NoSanMetaId, NoneMetaNode);
    }
  }
}

void AngoraLLVMPass::processCall(Instruction *Inst) {
  //  if (ABIList.isIn(*Callee, "uninstrumented"))
  //  return;
  /* if (num_fn_ctx != 0) {
    IRBuilder<> IRB(Inst);
    Constant *CallSite = ConstantInt::get(Int32Ty, getRandomContextId());
    IRB.CreateStore(CallSite, AngoraCallSite)
        ->setMetadata(NoSanMetaId, NoneMetaNode);
  } */
}

void AngoraLLVMPass::visitCallInst(Instruction *Inst) {
  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  /*
  remove inserted "unfold" functions has been moved to visitCallInstVirgin();
  */
  /*
   // remove inserted "unfold" functions
   if (!Callee->getName().compare(StringRef("__unfold_branch_fn"))) {
     if (Caller->use_empty()) {
       Caller->eraseFromParent();
     }
     return;
   } */

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledOperand())) {
    return;
  }

  processCall(Inst);
};

void AngoraLLVMPass::visitCallInstVirgin(Instruction *Inst) {
  // Can't use `CallBase<T>` here, as it needs a template argument, which is its
  // child(insane!) i.e. `class CallInst: public CallBase<CallInst>`, check the
  // header yourself.
  CallInst *Caller = dyn_cast<CallInst>(Inst);
  InvokeInst *Invoker = dyn_cast<InvokeInst>(Inst);

  Function *Callee =
      (Caller) ? Caller->getCalledFunction() : Invoker->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      (Caller && isa<InlineAsm>(Caller->getCalledOperand())) ||
      (Invoker && isa<InlineAsm>(Invoker->getCalledOperand()))) {
    return;
  }

  // remove inserted "unfold" functions
  if (!Callee->getName().compare(StringRef("__unfold_branch_fn"))) {
    if (Caller && Caller->use_empty()) {
      Caller->eraseFromParent();
    }
    if (Invoker && Invoker->use_empty()) {
      Invoker->eraseFromParent();
    }
    return;
  }
  if (num_fn_ctx != 0) {
    IRBuilder<> IRB(Inst);
    Constant *CallSite = ConstantInt::get(Int32Ty, getRandomContextId());
    IRB.CreateStore(CallSite, AngoraCallSite)
        ->setMetadata(NoSanMetaId, NoneMetaNode);
  }
}

void AngoraLLVMPass::visitInvokeInst(Instruction *Inst) {
  InvokeInst *Caller = dyn_cast<InvokeInst>(Inst);
  Function *Callee = Caller->getCalledFunction();

  if (!Callee || Callee->isIntrinsic() ||
      isa<InlineAsm>(Caller->getCalledOperand())) {
    return;
  }

  processCall(Inst);
}

void AngoraLLVMPass::visitCompareFunc(Instruction *Inst) {
  // configuration file: custom/exploitation_list.txt  fun:xx=cmpfn

  if (!TrackMode || !isa<CallInst>(Inst) ||
      !ExploitList.isIn(*Inst, CompareFuncCat)) {
    return;
  }

  ConstantInt *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  CallInst *Caller = dyn_cast<CallInst>(Inst);
  Value *OpArg[2];
  OpArg[0] = Caller->getArgOperand(0);
  OpArg[1] = Caller->getArgOperand(1);

  if (!OpArg[0]->getType()->isPointerTy() ||
      !OpArg[1]->getType()->isPointerTy()) {
    return;
  }

  Value *ArgSize = nullptr;
  if (Caller->getNumArgOperands() > 2) {
    ArgSize = Caller->getArgOperand(2);  // int32ty
  } else {
    ArgSize = ConstantInt::get(Int64Ty, 0);
  }

  IRBuilder<> IRB(Inst);
  LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
  setInsNoSan(CurCtx);
  CallInst *ProxyCall =
      IRB.CreateCall(TraceFnTT, {Cid, CurCtx, ArgSize, OpArg[0], OpArg[1]});
  setInsNoSan(ProxyCall);
}

Value *AngoraLLVMPass::castArgType(IRBuilder<> &IRB, Value *V) {
  Type *OpType = V->getType();
  Value *NV = V;
  if (OpType->isFloatTy()) {
    NV = IRB.CreateFPToUI(V, Int32Ty);
    setValueNoSan(NV);
    NV = IRB.CreateIntCast(NV, Int64Ty, false);
    setValueNoSan(NV);
  } else if (OpType->isDoubleTy()) {
    NV = IRB.CreateFPToUI(V, Int64Ty);
    setValueNoSan(NV);
  } else if (OpType->isPointerTy()) {
    NV = IRB.CreatePtrToInt(V, Int64Ty);
  } else {
    if (OpType->isIntegerTy() && OpType->getIntegerBitWidth() < 64) {
      NV = IRB.CreateZExt(V, Int64Ty);
    }
  }
  return NV;
}

void AngoraLLVMPass::processCmp(Instruction *Cond, Constant *Cid,
                                Instruction *InsertPoint) {
  CmpInst *Cmp = dyn_cast<CmpInst>(Cond);
  Value *OpArg[2];
  OpArg[0] = Cmp->getOperand(0);
  OpArg[1] = Cmp->getOperand(1);
  Type *OpType = OpArg[0]->getType();
  if (!((OpType->isIntegerTy() && OpType->getIntegerBitWidth() <= 64) ||
        OpType->isFloatTy() || OpType->isDoubleTy() || OpType->isPointerTy())) {
    processBoolCmp(Cond, Cid, InsertPoint);
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

  IRBuilder<> IRB(InsertPoint);

  // OKF("Processing ordinary cmp");
  // errs() << *Cond << " constraint id = " << *Cid << '\n';

  if (FastMode) {
    /*
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNoSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNoSan(ProxyCall);
    */
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNoSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNoSan(CmpEq);

    Instruction *ThenTI = nullptr;
    Instruction *ElseTI = nullptr;

    // BI = cast<BranchInst>(
    //     SplitBlockAndInsertIfThen(CmpEq, InsertPoint, false,
    //     ColdCallWeights));
    SplitBlockAndInsertIfThenElse(CmpEq, InsertPoint, &ThenTI, &ElseTI,
                                  ColdCallWeights);
    setInsNoSan(ThenTI);
    setInsNoSan(ElseTI);
    setHelperBlock(ThenTI->getParent());
    setHelperBlock(ElseTI->getParent());

    BranchInst *BI = cast<BranchInst>(ThenTI);

    IRBuilder<> ThenB(BI);
    OpArg[0] = castArgType(ThenB, OpArg[0]);
    OpArg[1] = castArgType(ThenB, OpArg[1]);
    Value *CondExt = ThenB.CreateZExt(Cond, Int32Ty);
    setValueNoSan(CondExt);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall =
        ThenB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNoSan(ProxyCall);
    /*
    // Should be used when we move the above branch to rust side.
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNoSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall =
        IRB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNoSan(ProxyCall);
    */
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    u32 predicate = Cmp->getPredicate();
    if (ConstantInt *CInt = dyn_cast<ConstantInt>(OpArg[1])) {
      if (CInt->isNegative()) {
        predicate |= COND_SIGN_MASK;
      }
    }
    Value *TypeArg = ConstantInt::get(Int32Ty, predicate);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNoSan(CondExt);
    OpArg[0] = castArgType(IRB, OpArg[0]);
    OpArg[1] = castArgType(IRB, OpArg[1]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall = IRB.CreateCall(
        TraceCmpTT,
        {Cid, CurCtx, SizeArg, TypeArg, OpArg[0], OpArg[1], CondExt});
    setInsNoSan(ProxyCall);
  }
}

void AngoraLLVMPass::processBoolCmp(Value *Cond, Constant *Cid,
                                    Instruction *InsertPoint) {
  if (!Cond->getType()->isIntegerTy() ||
      Cond->getType()->getIntegerBitWidth() > 32)
    return;
  Value *OpArg[2];
  OpArg[1] = ConstantInt::get(Int64Ty, 1);
  IRBuilder<> IRB(InsertPoint);

  // OKF("Processing bool cmp");
  // errs() << *Cond << " constraint id = " << *Cid << '\n';
  if (FastMode) {
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNoSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNoSan(CmpEq);

    Instruction *ThenTI = nullptr;
    Instruction *ElseTI = nullptr;

    SplitBlockAndInsertIfThenElse(CmpEq, InsertPoint, &ThenTI, &ElseTI,
                                  ColdCallWeights);

    setInsNoSan(ThenTI);
    setInsNoSan(ElseTI);
    setHelperBlock(ThenTI->getParent());
    setHelperBlock(ElseTI->getParent());

    BranchInst *BI = cast<BranchInst>(ThenTI);
    // setInsNoSan(BI);
    IRBuilder<> ThenB(BI);
    Value *CondExt = ThenB.CreateZExt(Cond, Int32Ty);
    setValueNoSan(CondExt);
    OpArg[0] = ThenB.CreateZExt(CondExt, Int64Ty);
    setValueNoSan(OpArg[0]);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall =
        ThenB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
    setInsNoSan(ProxyCall);
    /*
     // Should be used when we move the above branch to rust side.
     Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
     setValueNoSan(CondExt);
     OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
     setValueNoSan(OpArg[0]);
     LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
     setInsNoSan(CurCtx);
     CallInst *ProxyCall =
         IRB.CreateCall(TraceCmp, {CondExt, Cid, CurCtx, OpArg[0], OpArg[1]});
     setInsNoSan(ProxyCall);
     */
  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, 1);
    Value *TypeArg = ConstantInt::get(Int32Ty, COND_EQ_OP | COND_BOOL_MASK);
    Value *CondExt = IRB.CreateZExt(Cond, Int32Ty);
    setValueNoSan(CondExt);
    OpArg[0] = IRB.CreateZExt(CondExt, Int64Ty);
    setValueNoSan(OpArg[0]);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall = IRB.CreateCall(
        TraceCmpTT,
        {Cid, CurCtx, SizeArg, TypeArg, OpArg[0], OpArg[1], CondExt});
    setInsNoSan(ProxyCall);
  }
}

void AngoraLLVMPass::visitCmpInst(Instruction *Inst) {
  Instruction *InsertPoint = Inst->getNextNode();
  if (!InsertPoint || isa<ConstantInt>(Inst)) return;
  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  processCmp(Inst, Cid, InsertPoint);
}

void AngoraLLVMPass::visitBranchInst(Instruction *Inst) {
  BranchInst *Br = dyn_cast<BranchInst>(Inst);
  if (Br->isConditional()) {
    Value *Cond = Br->getCondition();
    if (Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond)) {
      if (!isa<CmpInst>(Cond)) {
        // From  and, or, call, phi ....
        Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
        processBoolCmp(Cond, Cid, Inst);
      }
    }
  }
}

void AngoraLLVMPass::visitSwitchInst(Module &M, Instruction *Inst) {
  SwitchInst *Sw = dyn_cast<SwitchInst>(Inst);
  Value *Cond = Sw->getCondition();

  if (!(Cond && Cond->getType()->isIntegerTy() && !isa<ConstantInt>(Cond))) {
    return;
  }

  int num_bits = Cond->getType()->getScalarSizeInBits();
  int num_bytes = num_bits / 8;
  if (num_bytes == 0 || num_bits % 8 > 0) return;

  Constant *Cid = ConstantInt::get(Int32Ty, getInstructionId(Inst));
  IRBuilder<> IRB(Sw);

  if (FastMode) {
    LoadInst *CurCid = IRB.CreateLoad(AngoraCondId);
    setInsNoSan(CurCid);
    Value *CmpEq = IRB.CreateICmpEQ(Cid, CurCid);
    setValueNoSan(CmpEq);

    Instruction *ThenTI = nullptr;
    Instruction *ElseTI = nullptr;
    SplitBlockAndInsertIfThenElse(CmpEq, Sw, &ThenTI, &ElseTI, ColdCallWeights);
    setInsNoSan(ThenTI);
    setInsNoSan(ElseTI);
    setHelperBlock(ThenTI->getParent());
    setHelperBlock(ElseTI->getParent());

    BranchInst *BI = cast<BranchInst>(ThenTI);
    // setInsNoSan(BI);
    IRBuilder<> ThenB(BI);
    Value *CondExt = ThenB.CreateZExt(Cond, Int64Ty);
    setValueNoSan(CondExt);
    LoadInst *CurCtx = ThenB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall = ThenB.CreateCall(TraceSw, {Cid, CurCtx, CondExt});
    setInsNoSan(ProxyCall);

  } else if (TrackMode) {
    Value *SizeArg = ConstantInt::get(Int32Ty, num_bytes);
    SmallVector<Constant *, 16> ArgList;
    for (auto It : Sw->cases()) {
      Constant *C = It.getCaseValue();
      if (C->getType()->getScalarSizeInBits() > Int64Ty->getScalarSizeInBits())
        continue;
      ArgList.push_back(ConstantExpr::getCast(CastInst::ZExt, C, Int64Ty));
    }

    ArrayType *ArrayOfInt64Ty = ArrayType::get(Int64Ty, ArgList.size());
    GlobalVariable *ArgGV = new GlobalVariable(
        M, ArrayOfInt64Ty, false, GlobalVariable::InternalLinkage,
        ConstantArray::get(ArrayOfInt64Ty, ArgList),
        "__angora_switch_arg_values");
    Value *SwNum = ConstantInt::get(Int32Ty, ArgList.size());
    Value *ArrPtr = IRB.CreatePointerCast(ArgGV, Int64PtrTy);
    setValueNoSan(ArrPtr);
    Value *CondExt = IRB.CreateZExt(Cond, Int64Ty);
    setValueNoSan(CondExt);
    LoadInst *CurCtx = IRB.CreateLoad(AngoraContext);
    setInsNoSan(CurCtx);
    CallInst *ProxyCall = IRB.CreateCall(
        TraceSwTT, {Cid, CurCtx, SizeArg, CondExt, SwNum, ArrPtr});
    setInsNoSan(ProxyCall);
  }
}
void AngoraLLVMPass::exploitDiv(Instruction *inst) {
  Value *dividend = inst->getOperand(1);
  Type *dividend_ty = dividend->getType();

  // errs() << "dividend: " << *dividend << " type: " << *dividend_ty << "\n";
  // Not an integer or constant integer.
  if (!dividend_ty->isIntegerTy() || isa<ConstantInt>(dividend)) {
    return;
  }

  IRBuilder<> IRB(inst);
  ConstantInt *cmpid = ConstantInt::get(Int32Ty, getInstructionId(inst));
  LoadInst *ctx_arg = IRB.CreateLoad(AngoraContext);
  setInsNoSan(ctx_arg);

  int size = dividend_ty->getScalarSizeInBits() / 8;
  Value *size_arg = ConstantInt::get(Int32Ty, size);

  if (!dividend_ty->isIntegerTy(64)) {
    dividend = IRB.CreateZExt(dividend, Int64Ty);
  }
  if (TrackMode) {
    // Value *fn_id = ConstantInt::get(Int32Ty, getFunctionId(inst));
    CallInst *ProxyCall = IRB.CreateCall(
        TraceExploitDivTT, {cmpid, /*fn_id,*/ ctx_arg, size_arg, dividend});
    setInsNoSan(ProxyCall);
  }
  if (FastMode) {
    CallInst *ProxyCall =
        IRB.CreateCall(TraceExploitDiv, {cmpid, ctx_arg, size_arg, dividend});
    setInsNoSan(ProxyCall);
  }
}
void AngoraLLVMPass::exploitIntflow(Instruction *inst) {
  Value *arg0 = inst->getOperand(0);
  Value *arg1 = inst->getOperand(1);

  Type *arg_ty = arg0->getType();

  // Not an integer or both are constant integers.
  if (!arg_ty->isIntegerTy() ||
      (isa<ConstantInt>(arg0) && isa<ConstantInt>(arg1))) {
    return;
  }
  int size = arg_ty->getScalarSizeInBits() / 8;
  Value *size_arg = ConstantInt::get(Int32Ty, size);
  if (size > 8) {
    return;
  }

  IRBuilder<> IRB(inst);
  ConstantInt *cmpid = ConstantInt::get(Int32Ty, getInstructionId(inst));
  LoadInst *ctx_arg = IRB.CreateLoad(AngoraContext);
  setInsNoSan(ctx_arg);

  unsigned opcode = inst->getOpcode();
  // At this point we know neither is 64 or higher bits.
  Value *result_signed;
  Value *arg0_signed = IRB.CreateSExt(arg0, Int64Ty);
  Value *arg1_signed = IRB.CreateSExt(arg1, Int64Ty);
  if (opcode == Instruction::Add) {
    result_signed = IRB.CreateAdd(arg0_signed, arg1_signed);
  } else if (opcode == Instruction::Sub) {
    result_signed = IRB.CreateSub(arg0_signed, arg1_signed);
  } else if (opcode == Instruction::Mul) {
    result_signed = IRB.CreateMul(arg0_signed, arg1_signed);
  } else {
    errs() << "Shouldn't be here.";
  }
  Value *result_unsigned;
  Value *arg0_unsigned = IRB.CreateZExt(arg0, Int64Ty);
  Value *arg1_unsigned = IRB.CreateZExt(arg1, Int64Ty);
  if (opcode == Instruction::Add) {
    result_unsigned = IRB.CreateAdd(arg0_unsigned, arg1_unsigned);
  } else if (opcode == Instruction::Sub) {
    result_unsigned = IRB.CreateSub(arg0_unsigned, arg1_unsigned);
  } else if (opcode == Instruction::Mul) {
    result_unsigned = IRB.CreateMul(arg0_unsigned, arg1_unsigned);
  } else {
    errs() << "Shouldn't be here.";
  }

  if (TrackMode) {
    // Value *fn_id = ConstantInt::get(Int32Ty, getFunctionId(inst));
    CallInst *ProxyCall = IRB.CreateCall(
        TraceExploitIntflowTT,
        {cmpid, /*fn_id,*/ ctx_arg, size_arg, result_signed, result_unsigned});
    setInsNoSan(ProxyCall);
  }
  if (FastMode) {
    CallInst *ProxyCall = IRB.CreateCall(
        TraceExploitIntflow,
        {cmpid, ctx_arg, size_arg, result_signed, result_unsigned});
    setInsNoSan(ProxyCall);
  }
}

void AngoraLLVMPass::visitIntExploitation(Instruction *inst) {
  unsigned opcode = inst->getOpcode();
  if (TrackMode || FastMode) {
    if (opcode == Instruction::SDiv || opcode == Instruction::UDiv) {
      // errs() << "Exploit div" << *inst << "\n";
      exploitDiv(inst);
    } else if (opcode == Instruction::Add || opcode == Instruction::Sub ||
               opcode == Instruction::Mul) {
      // errs() << "Exploit mul/sub/add" << *inst << "\n";
      if (opcode == Instruction::Add || opcode == Instruction::Sub) {
        // errs() << "Exploit add/sub may incur huge overhead. Skipping for "
        //"now.\n";
        return;
      }
      exploitIntflow(inst);
    }
  }
}

void AngoraLLVMPass::exploitMemArg(Instruction *inst, Value *exploitable_arg,
                                   unsigned exp_id) {
  if (!exploitable_arg) {
    return;
  }
  if (isa<ConstantInt>(exploitable_arg)) {
    // errs() << *inst << "\n";
    // OKF("Exploitable arg is a constant");
    return;
  }
  Type *val_type = exploitable_arg->getType();
  if (!val_type->isIntegerTy() && !val_type->isPointerTy()) {
    // OKF("Exploitable arg is not a pointer nor integer");
    return;
  }
  // errs() << "exploiting " << *inst << "\n";
  // Value *func_id = ConstantInt::get(Int32Ty, getFunctionId(inst));

  IRBuilder<> IRB(inst);
  LoadInst *ctx = IRB.CreateLoad(AngoraContext);
  setInsNoSan(ctx);

  ConstantInt *cmpid = ConstantInt::get(Int32Ty, getInstructionId(inst));
  // exp_id == 0 is reserved for non-exp instructions.
  ConstantInt *expid = ConstantInt::get(Int32Ty, exp_id + 1);
  if (val_type->isIntegerTy()) {
    Value *size_asg = ConstantInt::get(Int32Ty, 8);
    int size = val_type->getScalarSizeInBits() / 8;
    if (!val_type->isIntegerTy(64)) {
      exploitable_arg = IRB.CreateZExt(exploitable_arg, Int64Ty);
    }
    Value *size_arg = ConstantInt::get(Int32Ty, size);
    if (TrackMode) {
      CallInst *call = IRB.CreateCall(
          TraceExploitMemArgTT,
          {cmpid, expid, /*func_id,*/ ctx, size_arg, exploitable_arg});
      setInsNoSan(call);
    } else if (FastMode) {
      CallInst *call = IRB.CreateCall(
          TraceExploitMemArg, {cmpid, expid, ctx, size_arg, exploitable_arg});
      setInsNoSan(call);
    } else {
      FATAL("Shouldn't be here");
    }
  } else if (val_type->isPointerTy()) {
    FATAL("We shouldn't run into pointers...");
    if (TrackMode) {
      Value *size_arg = ConstantInt::get(Int32Ty, 8);
      Value *ty_arg =
          ConstantInt::get(Int32Ty, COND_EXPLOIT_MASK | inst->getOpcode());

      CallInst *call = IRB.CreateCall(
          TraceExploitTT,
          {cmpid, /*func_id,*/ ctx, size_arg, ty_arg, exploitable_arg});
      setInsNoSan(call);
    }
  }
}
void AngoraLLVMPass::visitMemExploitation(Instruction *inst) {
  if (!TrackMode && !FastMode) {
    OKF("Not exploiting...");
    return;
  }
  if (IntrinsicInst *intrinsic_caller = dyn_cast<IntrinsicInst>(inst)) {
    const Function *callee = intrinsic_caller->getCalledFunction();
    const std::string callee_name = callee->getName().str();
    if ((callee_name.find("llvm.memcpy") != std::string::npos) ||
        (callee_name.find("llvm.memmove") != std::string::npos) ||
        (callee_name.find("llvm.memset") != std::string::npos)) {
      // All three intrinsics are the 2nd arg.
      exploitMemArg(intrinsic_caller, intrinsic_caller->getArgOperand(2), 0);
    } else {
      // We don't cared the rest of intrinsics.
    }
  } else {
    CallInst *caller = dyn_cast<CallInst>(inst);

    bool exploit_all = ExploitList.isIn(*inst, ExploitCategoryAll);
    int num_params;
    if (caller) {
      num_params = caller->getNumArgOperands();
    } else {
      num_params = inst->getNumOperands();
    }
    for (int i = 0; i < num_params && i < MAX_EXPLOIT_CATEGORY; i++) {
      if (exploit_all || ExploitList.isIn(*inst, ExploitCategory[i])) {
        if (caller) {
          exploitMemArg(inst, caller->getArgOperand(i), i);
        } else {
          exploitMemArg(inst, inst->getOperand(i), i);
        }
      }
    }
  }
}

void AngoraLLVMPass::runOnFunctionFastModeExpInt(Function *func) {
  // OKF("Instrumenting exploiting int code");
  // Int
  for (BasicBlock &basicBlock : *func) {
    for (Instruction &I : basicBlock) {
      Instruction *inst = &I;
      // TOOD
      if (isInstNoSan(inst)) {
        continue;
      }
      visitIntExploitation(inst);
    }
  }
}
void AngoraLLVMPass::runOnFunctionFastModeExpMem(Function *func) {
  // OKF("Instrumenting exploiting mem code");
  // Mem
  for (BasicBlock &basicBlock : *func) {
    for (Instruction &I : basicBlock) {
      Instruction *inst = &I;
      // TOOD
      if (isInstNoSan(inst)) {
        continue;
      }
      // There is a white list in rules/exploitation_list.txt and defined
      // all insts that should exploit
      visitMemExploitation(inst);
    }
  }
}
void AngoraLLVMPass::runOnFunctionFastModeCond(Function *func) {
  // OKF("Instrumenting cond");
  std::vector<BasicBlock *> bb_list;
  for (auto bb = func->begin(); bb != func->end(); bb++) {
    bb_list.push_back(&(*bb));
  }

  for (auto bi = bb_list.begin(); bi != bb_list.end(); bi++) {
    BasicBlock *BB = *bi;
    std::vector<Instruction *> inst_list;

    for (auto inst = BB->begin(); inst != BB->end(); inst++) {
      Instruction *Inst = &(*inst);
      inst_list.push_back(Inst);
    }

    for (auto inst = inst_list.begin(); inst != inst_list.end(); inst++) {
      Instruction *Inst = *inst;
      if (isInstNoSan(Inst)) {
        continue;
      }
      if (Inst == &(*BB->getFirstInsertionPt())) {
        // countEdge(M, *BB);
      }
      if (isa<CallInst>(Inst)) {
        // We shouldn't be doing exploitation here anymore.
        visitCallInst(Inst);
      } else if (isa<InvokeInst>(Inst)) {
        // Exploit on invoke inst shouldn't happen if my understanding to
        // invoke inst is right. Some reading links:
        //
        // https://stackoverflow.com/questions/35368366/call-vs-invoke-in-ir-codes-of-llvm/35368917
        // https://lists.llvm.org/pipermail/llvm-dev/2006-October/007047.html

        // visitCompareFunc(Inst);
        // visitMemExploitation(Inst);
        bool exploit_all = ExploitList.isIn(*Inst, ExploitCategoryAll);
        for (int i = 0; i < MAX_EXPLOIT_CATEGORY; i++) {
          if (exploit_all || ExploitList.isIn(*Inst, ExploitCategory[i])) {
            FATAL(
                "There shouldn't be exploitable mem operations using "
                "invoke inst.");
          }
        }
        visitInvokeInst(Inst);
      } else if (isa<BranchInst>(Inst)) {
        visitBranchInst(Inst);
      } else if (isa<SwitchInst>(Inst)) {
        visitSwitchInst(*func->getParent(), Inst);
      } else if (isa<CmpInst>(Inst)) {
        visitCmpInst(Inst);
      } else {
        // We shouldn't be doing exploitation here anymore.
        // Unless it's tracking mode.
        // visitExploitation(Inst);
      }
    }
  }
}
void AngoraLLVMPass::runOnFunctionFastMode(Function *func) {
  // OKF("Doing function splitting");
}
void AngoraLLVMPass::runOnFunctionTrackMode(Function *func) {
  std::vector<BasicBlock *> bb_list;
  for (auto bb = func->begin(); bb != func->end(); bb++) {
    bb_list.push_back(&(*bb));
  }
  for (BasicBlock *BB : bb_list) {
    std::vector<Instruction *> inst_list;
    for (auto inst = BB->begin(); inst != BB->end(); inst++) {
      Instruction *Inst = &(*inst);
      inst_list.push_back(Inst);
    }
    for (Instruction *Inst : inst_list) {
      if (isInstNoSan(Inst)) {
        continue;
      }
      if (isa<CallInst>(Inst)) {
        // We shouldn't be doing exploitation here anymore.
        visitCompareFunc(Inst);
        visitMemExploitation(Inst);
        visitCallInst(Inst);
      } else if (isa<InvokeInst>(Inst)) {
        // Exploit on invoke inst shouldn't happen if my understanding to
        // invoke inst is right. Some reading links:
        //
        // https://stackoverflow.com/questions/35368366/call-vs-invoke-in-ir-codes-of-llvm/35368917
        // https://lists.llvm.org/pipermail/llvm-dev/2006-October/007047.html

        // visitCompareFunc(Inst);
        // visitMemExploitation(Inst);
        bool exploit_all = ExploitList.isIn(*Inst, ExploitCategoryAll);
        for (int i = 0; i < MAX_EXPLOIT_CATEGORY; i++) {
          if (exploit_all || ExploitList.isIn(*Inst, ExploitCategory[i])) {
            FATAL(
                "There shouldn't be exploitable mem operations using invoke "
                "inst.");
          }
        }
        visitInvokeInst(Inst);
      } else if (isa<BranchInst>(Inst)) {
        visitBranchInst(Inst);
      } else if (isa<SwitchInst>(Inst)) {
        visitSwitchInst(*func->getParent(), Inst);
      } else if (isa<CmpInst>(Inst)) {
        visitCmpInst(Inst);
      } else {
        // We shouldn't be doing exploitation here anymore.
        // Unless it's tracking mode.
        visitIntExploitation(Inst);
        visitMemExploitation(Inst);
      }
    }
  }
}

bool AngoraLLVMPass::runOnModule(Module &M) {
  // Convert intrinsic function calls to libc calls/
  // memset, memcpy, and memmove.
  // ConvertIntrinsicPass().runOnModule(M);
  SAYF(cCYA "angora-llvm-pass\n");
  if (TrackMode) {
    OKF("Track Mode.");
  } else if (DFSanMode) {
    OKF("DFSan Mode.");
  } else {
    FastMode = true;
    OKF("Fast Mode.");
  }

  initVariables(M);
  CDF = new CtorDtorFuncs(M);
  if (!is_bc && FastMode) {
    WARNF(
        "Valkyrie requires the entire bitcode file to properly insert branch "
        "instrumentation. Please ensure your input is the entire bitcode of "
        "a program.");
  }

  if (DFSanMode) {
    return true;
  }

  new GlobalVariable(M, Int16PtrTy, false, GlobalVariable::InternalLinkage,
                     Int16PtrNull, COUNT_PTR_SYMBOL);
  new GlobalVariable(M, Int16PtrTy, false, GlobalVariable::InternalLinkage,
                     Int16PtrNull, SUB_COUNT_PTR_SYMBOL);

  // Assign function and instruction IDs.
  OKF("Assigning function and instruction IDs.");
  for (auto &F : M) {
    if (F.isDeclaration() || F.getName().startswith(StringRef("asan.module")) ||
        F.getName().startswith(StringRef("magma"))) {
      continue;
    }
    // initFunctionId(M.getContext(), &F);
    for (auto &BB : F) {
      for (auto &I : BB) {
        if (I.getMetadata(NoSanMetaId)) {
          continue;
        }
        initInstructionId(M.getContext(), &I);
      }
    }
  }

  OKF("Processing virgin code.");
  // Process "virgin" code
  for (auto &F : M) {
    std::vector<Instruction *> inst_list;
    for (auto BB = F.begin(); BB != F.end(); BB++) {
      for (auto Inst = BB->begin(); Inst != BB->end(); Inst++) {
        inst_list.push_back(&*Inst);
      }
    }
    for (auto Inst : inst_list) {
      if (isa<CallInst>(Inst) || isa<InvokeInst>(Inst)) {
        // Removes unfold branch fn and adds angora context to all callsites
        visitCallInstVirgin(Inst);
      }
    }
  }
  // Add branch counting instrumentation to fast binaries
  size_t branchCount = 0;
  SizeMap sizeMap{};
  TypeSet typeSet{};
  FuncMap funcMap{};
  if (FastMode) {
    OKF("Instrumenting branch counting code for fast binaries.");
    size_t maxSize = branchInstrument(M, sizeMap);
    typeAnalysis(M, typeSet);
    indirectFuncCallAnalysis(M, sizeMap, typeSet, funcMap);
    branchCount = funcCallInstrument(M, sizeMap, typeSet, funcMap, maxSize);
    OKF("Branch Table: branch table size: %ld", branchCount);
    if (getenv("PLOT_BRANCH_INSTRUMENT")) {
      plotBranchInstrument(M, "before.dot");
    }
  }

  OKF("Adding feedback mechanisms.");
  std::vector<Function *> func_list;
  for (auto &func : M) {
    if (func.isDeclaration() ||
        func.getName().startswith(StringRef("asan.module")) ||
        func.getName().startswith(StringRef("magma"))) {
      continue;
    }
    func_list.push_back(&func);
  }

  for (Function *func : func_list) {
    // Add function context update wrapper to each function
    addFnWrap(func);
    if (TrackMode) {
      if (false /*Trak loop var*/) {
        // runOnFunctionTrackLoop(func);
      }
      runOnFunctionTrackMode(func);
    } else if (FastMode) {
      if (false /*Do function split*/) {
        // Split a function into 4 copies for different
        // instrumentations to optimize runtime speed.
        runOnFunctionFastMode(func);
      } else {
        // Add all instrumentations in the same function
        runOnFunctionFastModeCond(func);
        runOnFunctionFastModeExpInt(func);
        runOnFunctionFastModeExpMem(func);
      }
    }
  }

  // Add the fast binary forksrv and branch counting function calls
  if (FastMode) {
    if (branchCount != 0) {
      bootstrapInstrument(M, funcMap, branchCount);
    }
    if (getenv("PLOT_BRANCH_INSTRUMENT")) {
      plotBranchInstrument(M, "final.dot");
    }
  }

  if (is_bc) {
    OKF("Max constraint id is %d", CidCounter);
  }
  delete CDF;
  return true;
}

static void registerAngoraLLVMPass(const PassManagerBuilder &,
                                   legacy::PassManagerBase &PM) {
  PM.add(new AngoraLLVMPass());
}

static RegisterPass<AngoraLLVMPass> X("angora_llvm_pass", "Angora LLVM Pass",
                                      false, false);

#ifdef LTO
static RegisterStandardPasses RegisterAngoraLLVMPass(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerAngoraLLVMPass);
#else
static RegisterStandardPasses RegisterAngoraLLVMPass(
    PassManagerBuilder::EP_OptimizerLast, registerAngoraLLVMPass);
static RegisterStandardPasses RegisterAngoraLLVMPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerAngoraLLVMPass);
#endif