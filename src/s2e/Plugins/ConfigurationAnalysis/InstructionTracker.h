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

#ifndef VIOLET_INSTRTRACKER_H
#define VIOLET_INSTRTRACKER_H

#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>

namespace s2e {
namespace plugins {

class InstructionTracker : public Plugin {
  S2E_PLUGIN

  public:
    uint64_t m_address;
    InstructionTracker(S2E *s2e) : Plugin(s2e) {}

    void initialize();
    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
    void onTranslateInstruction(ExecutionSignal *signal,S2EExecutionState *state, TranslationBlock *tb, uint64_t pc);
    void setEntryPoint(S2EExecutionState *state,uint64_t entry_point);
};

class InstructionTrackerState : public PluginState {
  private:
    int m_count;
    uint64_t entry_point;
  public:
    InstructionTrackerState() {
      m_count = 0;
    }

    virtual ~InstructionTrackerState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
      return new InstructionTrackerState();
    }

    InstructionTrackerState *clone() const {
      return new InstructionTrackerState(*this);
    }

    void increment() {
      ++m_count;
    }

    int get() {
      return m_count;
    }

    void setEntryPoint(uint64_t EntryPoint){
      entry_point = EntryPoint;
    }

    uint64_t getEntryPoint() {
      return entry_point;
    }
};

} // namespace plugins
} // namespace s2e

#endif // VIOLET_INSTRTRACKER_H
