#pragma once

#define GET_OR_INSERT_READONLY_FUNCTION(callee_obj, ret_ty, func_name, ...) \
  {                                                                         \
    FunctionType *callee_obj##Ty =                                          \
        FunctionType::get(ret_ty, __VA_ARGS__, false);                      \
    AttributeList AL;                                                       \
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,      \
                         Attribute::NoUnwind);                              \
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex,      \
                         Attribute::ReadOnly);                              \
    callee_obj = M.getOrInsertFunction(func_name, callee_obj##Ty, AL);      \
  }

#define GET_OR_INSERT_FUNCTION(callee_obj, ret_ty, func_name, ...)     \
  {                                                                    \
    FunctionType *callee_obj##Ty =                                     \
        FunctionType::get(ret_ty, __VA_ARGS__, false);                 \
    AttributeList AL;                                                  \
    AL = AL.addAttribute(M.getContext(), AttributeList::FunctionIndex, \
                         Attribute::NoUnwind);                         \
    callee_obj = M.getOrInsertFunction(func_name, callee_obj##Ty, AL); \
  }

#include <fstream>
#include <iostream>

#include "defs.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Value.h"

namespace {
// Meta
static unsigned NoSanMetaId;
static unsigned HelperBlock;
static unsigned Instrumented;
static llvm::MDTuple *NoneMetaNode;

using llvm::BasicBlock;
using llvm::errs;
using llvm::Function;
using llvm::Instruction;
using llvm::Module;
using llvm::raw_string_ostream;
using llvm::StringRef;

void initMeta(llvm::LLVMContext &C) {
  NoSanMetaId = C.getMDKindID("nosanitize");
  HelperBlock = C.getMDKindID("helperblock");
  Instrumented = C.getMDKindID("instrumented");
  NoneMetaNode = llvm::MDNode::get(C, llvm::None);
}
void setInsNoSan(llvm::Instruction *ins) {
  if (ins) ins->setMetadata(NoSanMetaId, NoneMetaNode);
}
void setValueNoSan(llvm::Value *v) {
  if (auto *ins = llvm::dyn_cast<llvm::Instruction>(v)) {
    setInsNoSan(ins);
  }
}
bool isInstNoSan(llvm::Instruction *ins) {
  return (ins->getMetadata(NoSanMetaId) != nullptr);
}

u32 getRandomBasicBlockId() { return random() % MAP_SIZE; }

void setHelperBlock(llvm::BasicBlock *block) {
  auto *terminator = block->getTerminator();
  terminator->setMetadata(HelperBlock, NoneMetaNode);
}
bool isHelperBlock(llvm::BasicBlock *block) {
  auto *terminator = block->getTerminator();
  return (terminator->getMetadata(HelperBlock) != nullptr);
}
void setHelperBlock(llvm::BasicBlock &block) { setHelperBlock(&block); }
bool isHelperBlock(llvm::BasicBlock &block) { isHelperBlock(&block); }

void setValueInstrumented(llvm::Value *value) {
  if (llvm::Instruction *ins = llvm::dyn_cast<llvm::Instruction>(value)) {
    ins->setMetadata(Instrumented, NoneMetaNode);
  }
}
bool isInstrumented(llvm::Instruction *inst) {
  return (inst->getMetadata(Instrumented) != nullptr);
}

std::string get_bb_name(BasicBlock &bb) {
  Function *func = bb.getParent();
  std::string block_address;
  raw_string_ostream string_stream(block_address);
  bb.printAsOperand(string_stream, false);

  std::string s = string_stream.str().replace(0, 1, "_");
  size_t start_pos = s.find(".");
  if (start_pos != std::string::npos) {
    s.replace(start_pos, 1, "");
  }

  return func->getName().str() + s;
}
std::string get_bb_name(BasicBlock *bb) { return get_bb_name(*bb); }
void plotBranchInstrument(Module &module, std::string name) {
  OKF("Dumping branch instrument graph");
  std::ofstream fs;
  fs.open(name);
  fs << "digraph G {\n";
  for (Function &func : module) {
    if (func.isDeclaration() ||
        func.getName().startswith(StringRef("asan.module")) ||
        func.getName().startswith(StringRef("__valkyrie"))) {
      continue;
    }

    fs << "\tsubgraph ";
    fs << func.getName().str();
    fs << " {\n";

    for (BasicBlock &bb : func) {
      fs << "\t\t" << get_bb_name(bb) << "; \n";
    }
    fs << "\t\t" << func.getName().str() << "_return;\n";
    fs << "\n";
    for (BasicBlock &bb : func) {
      Instruction *terminator = bb.getTerminator();
      unsigned int numSuccessors = terminator->getNumSuccessors();
      for (int i = 0; i < numSuccessors; i++) {
        BasicBlock *successor = terminator->getSuccessor(i);
        fs << "\t\t" << get_bb_name(bb) << " -> " << get_bb_name(*successor);
        errs() << "\t\t" << get_bb_name(bb) << " -> " << get_bb_name(*successor)
               << " " << isHelperBlock(&bb) << isHelperBlock(successor) << "\n";
        if (isInstrumented(&*successor->getFirstInsertionPt())) {
          fs << " [style=bold];\n";
        } else if (isHelperBlock(successor) || isHelperBlock(&bb)) {
          fs << " [style=dotted];\n";
        } else {
          fs << " [style=dashed];\n";
        }
      }
      if (numSuccessors == 0) {
        fs << "\t\t" << get_bb_name(bb) << " -> " << func.getName().str()
           << "_return [style=dashed];\n";
      }
    }
    fs << "\t}\n";
  }
  fs << "}\n";
  fs.close();
}
}  // namespace
