// 
// The Violet Project
//
// Created by ryanhuang on 12/15/19.
//
// Copyright (c) 2019, Johns Hopkins University - Order Lab.
//
//    All rights reserved.
//    Licensed under the Apache License, Version 2.0 (the "License");
//

#ifndef VIOLET_DYNAMIC_SYMBOLIC_TRACKER_H
#define VIOLET_DYNAMIC_SYMBOLIC_TRACKER_H

#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/Core/BaseInstructions.h>

namespace s2e {
namespace plugins {

class DynamicSymbolicTracker : public Plugin {
  S2E_PLUGIN

  public:
    DynamicSymbolicTracker(S2E *s2e) : Plugin(s2e) {}

    void initialize();
    void onFork(S2EExecutionState *state, const std::vector<S2EExecutionState *> &newStates,
                const std::vector<klee::ref<klee::Expr>> &newConditions); 

    void trackSymbolic(S2EExecutionState *state, uintptr_t address, unsigned size,
        const std::string &nameStr, bool maybe);

  private:
    BaseInstructions *m_base;
};

class DynamicSymbolicTrackerState : public PluginState {
  private:
    int m_count;
  public:
    DynamicSymbolicTrackerState() {
      m_count = 0;
    }

    virtual ~DynamicSymbolicTrackerState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
      return new DynamicSymbolicTrackerState();
    }

    DynamicSymbolicTrackerState* clone() const {
      return new DynamicSymbolicTrackerState(*this);
    }

    void increment() {
      ++m_count;
    }

    int get() {
      return m_count;
    }
};

} // namespace plugins
} // namespace s2e

#endif // VIOLET_DYNAMIC_SYMBOLIC_TRACKER_H
