/* RemoveSelectPass
 *
 * Force selection instruction into if-then-else. For example, the following:
 *
 * ```
 * int a = (flag) ? x : y;
 * ```
 *
 * Would be converted into:
 *
 * ```
 * if (flag) {
 *   a = x;
 * } else {
 *   a = y;
 * }
 * ```
 *
 * This would disable taint tracking, i.e. `a` is no longer tracked by `flag`.
 * However, we still want this for a good reason:
 *
 * 1. It's meanless to taint `flag` and `a` anyway, gradient descend can't make
 * anysense out of it.
 * 2. We can convert this case into standard implicit flow.
 * 3. With multi-init points, this actually helps with two initial points.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "llvm/ADT/SmallSet.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
// Angora
#include "./debug.h"
#include "./util.h"
#include "./version.h"
#include "CtorDtorFuncs.hpp"

using namespace llvm;

namespace {

class RemoveSelectPass : public FunctionPass {
 private:
 public:
  static char ID;

  CtorDtorFuncs *CDF;
  MDNode *EqCallWeights;

  RemoveSelectPass() : FunctionPass(ID){};

  bool doInitialization(Module &M) override;
  bool doFinalization(Module &M) override;
  bool runOnFunction(Function &F) override;
};

}  // namespace

char RemoveSelectPass::ID = 0;

bool RemoveSelectPass::doInitialization(Module &M) {
  CDF = new CtorDtorFuncs(M);
  EqCallWeights = MDBuilder(M.getContext()).createBranchWeights(1, 1);
  return true;
}

bool RemoveSelectPass::doFinalization(Module &M) {
  delete CDF;
  return true;
}

bool RemoveSelectPass::runOnFunction(Function &func) {
  // if the function is declaration, ignore
  if (func.isDeclaration() || CDF->isCtorDtor(func)) {
    return false;
  }

  bool modified = false;
  std::vector<BasicBlock *> bb_vec;
  for (BasicBlock &bb : func) {
    bb_vec.push_back(&bb);
  }

  for (BasicBlock *bb : bb_vec) {
    std::vector<Instruction *> inst_vec;
    for (Instruction &inst : *bb) {
      inst_vec.push_back(&inst);
    }
    for (Instruction *inst : inst_vec) {
      SelectInst *select = dyn_cast<SelectInst>(inst);
      if (select) {
        BasicBlock *cur_bb = select->getParent();

        Value *cond = select->getCondition();
        Value *true_val = select->getTrueValue();
        Value *false_val = select->getFalseValue();

        Instruction *true_br = nullptr;
        Instruction *false_br = nullptr;
        SplitBlockAndInsertIfThenElse(cond, select, &true_br, &false_br,
                                      EqCallWeights);
        BasicBlock *true_bb = true_br->getParent();
        BasicBlock *false_bb = false_br->getParent();

        Type *type = true_val->getType();
        PHINode *phi = PHINode::Create(type, 2);
        phi->addIncoming(true_val, true_bb);
        phi->addIncoming(false_val, false_bb);
        ReplaceInstWithInst(select, phi);
        modified = true;
      }
    }
  }

  return modified;
}

static void registerRemoveSelectPassPass(const PassManagerBuilder &,
                                         legacy::PassManagerBase &PM) {
  PM.add(new RemoveSelectPass());
}

static RegisterPass<RemoveSelectPass> X("remove_select_pass",
                                        "Remove Select Pass");

static RegisterStandardPasses RegisterRemoveSelectPass(
    PassManagerBuilder::EP_EarlyAsPossible, registerRemoveSelectPassPass);

/*
static RegisterStandardPasses RegisterRemoveSelectPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerRemoveSelectPassPass);
*/
