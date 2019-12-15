// 
// The Violet Project
//
// Created by yigonghu on 10/11/19.
//
// Copyright (c) 2019, Johns Hopkins University - Order Lab.
//
//    All rights reserved.
//    Licensed under the Apache License, Version 2.0 (the "License");
//

#include "DynamicSymbolicTracker.h"
#include <s2e/S2E.h>
#include <s2e/Utils.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(DynamicSymbolicTracker,           // Plugin class
    "Violet - Tracking maybe symbolic variables",   // Description
    "DynamicSymbolicTracker",                       // Plugin function name
    );

void DynamicSymbolicTracker::initialize() {
    m_base = s2e()->getPlugin<BaseInstructions>();
    s2e()->getCorePlugin()->onStateFork.connect(
        sigc::mem_fun(*this, &DynamicSymbolicTracker::onFork));
}

void DynamicSymbolicTracker::onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                             const std::vector<klee::ref<klee::Expr>> &newConditions) {
    assert(newStates.size() > 0);

    for (unsigned i = 0; i < newStates.size(); i++) {
      getDebugStream(state) << "encountering a fork of state " << newStates[i]->getGuid() 
        << ", pc=" << hexval(newStates[i]->regs()->getPc()) << '\n';
      foreach2 (it, newStates[i]->symbolics.begin(), newStates[i]->symbolics.end()) { getDebugStream(state) << (*it).first->name << "\n"; }
    }
}


void DynamicSymbolicTracker::trackSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
        const std::string &nameStr, bool maybe) {
  getDebugStream() << "tracking " << (maybe ? "maybe ": "") << "symbolic call of " 
      << nameStr << "@" << hexval(address) << ", state id=" << state->getGuid()
      << ", pc=" << hexval(state->regs()->getPc()) << '\n';
  if (maybe) {
    m_base->makeSymbolic(state, address, size, nameStr);
  }
}

} // namespace plugin
} // namespace s2e
