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

#include "InstructionTracker.h"
#include <s2e/S2E.h>
#include <s2e/Utils.h>

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(InstructionTracker,     // Plugin class
    "Tutorial - Tracking instructions",   // Description
    "InstructionTracker",                 // Plugin function name
    );

void InstructionTracker::initialize() {
  m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
  s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
      sigc::mem_fun(*this, &InstructionTracker::onTranslateInstruction));
}

void InstructionTracker::onTranslateInstruction(ExecutionSignal *signal,
    S2EExecutionState *state,
    TranslationBlock *tb,
    uint64_t pc) {
  DECLARE_PLUGINSTATE(InstructionTrackerState, state);
  s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';
  uint64_t entryPoint = plgState->getEntryPoint();
  if(entryPoint && ((m_address + entryPoint) == pc)) {
    // When we find an interesting address, ask S2E to invoke our callback when the address is actually
    // executed
    signal->connect(sigc::mem_fun(*this, &InstructionTracker::onInstructionExecution));
  }
}

void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
  // This macro declares the plgState variable of type InstructionTrackerState.
  // It automatically takes care of retrieving the right plugin state attached to the specified execution state
  DECLARE_PLUGINSTATE(InstructionTrackerState, state);

  getDebugStream(state) << "Executing instruction at " << hexval(pc) << '\n';

  // Increment the count
  plgState->increment();
  if (plgState->get() > 11) {
    // Kill the current state
    getInfoStream(state) << "Killing state " << state->getID() << '\n';
    getInfoStream(state) << "Terminating state: State was terminated by exceeding the threshold\n";
    s2e()->getExecutor()->terminateState(*state);
  }
}

void InstructionTracker::setEntryPoint(S2EExecutionState *state,uint64_t entry_point) {
  DECLARE_PLUGINSTATE(InstructionTrackerState, state);
  getInfoStream(state) << "Set the Entry Point " << hexval(entry_point) << '\n';
  return  plgState->setEntryPoint(entry_point);
}

} // namespace plugin
} // namespace s2e
