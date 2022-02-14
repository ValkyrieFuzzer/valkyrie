#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"

using namespace llvm;

namespace {

// TODO: Make this class it's own dyn lib.

/// Helper class borrowed from https://reviews.llvm.org/D19855
///
/// The helper class checks if a particular function is a global_ctor or
/// global_dtor.
class CtorDtorFuncs {
 public:
  CtorDtorFuncs(const Module &M) : M(M) { this->collect(); }
  // Return true if F is a function referenced in llvm.global_ctors
  // or llvm.global_dtors.
  bool isCtorDtor(Function *F) const { return CtorDtorSet.count(F) == 1; }
  bool isCtorDtor(Function &F) const { return isCtorDtor(&F); }
  // Collect the functions referenced in llvm.global_ctors and
  // llvm.global_dtors and put them in a set.
  void collect() {
    collectCtorDtorFuncs("llvm.global_ctors");
    collectCtorDtorFuncs("llvm.global_dtors");
    std::vector<std::string> skip_funcs({"OPENSSL_cpuid_setup"});
    for (std::string &s : skip_funcs) {
      Function *F = M.getFunction(s);
      if (F) {
        CtorDtorSet.insert(F);
      }
    }
  }

 private:
  const Module &M;
  void collectCtorDtorFuncs(const char *GVName);
  SmallPtrSet<Function *, 4> CtorDtorSet;
};
}  // namespace

// GVName can be either "llvm.global_ctors" and "llvm.global_dtors".
// This function Parses the array in these globals, extracts the function decls,
// and puts them to a set.
void CtorDtorFuncs::collectCtorDtorFuncs(const char *GVName) {
  GlobalVariable *GV = M.getGlobalVariable(GVName);
  if (!GV) return;
  ConstantArray *InitList = cast<ConstantArray>(GV->getInitializer());
  if (!InitList) return;
  for (Value *OI : InitList->operands()) {
    ConstantStruct *CS = dyn_cast<ConstantStruct>(OI);
    if (!CS) continue;
    // Found a null terminator, skip the rest.
    if (CS->getOperand(1)->isNullValue()) break;
    Function *F = dyn_cast<Function>(CS->getOperand(1));
    if (F) CtorDtorSet.insert(F);
  }
}