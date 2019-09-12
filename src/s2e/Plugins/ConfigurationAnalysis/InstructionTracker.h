//
// Created by yigonghu on 8/23/19.
//

#ifndef S2E_PLUGINS_INSTRTRACKER_H
#define S2E_PLUGINS_INSTRTRACKER_H

// These header files are located in libs2ecore
#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExecutionState.h>
#include <klee/Expr.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>

namespace s2e {
    namespace plugins {

        class InstructionTracker : public Plugin, public IPluginInvoker {
            S2E_PLUGIN
        private:
            uint64_t m_address;
            FunctionMonitor* m_monitor;
            FunctionMonitor::CallSignal* callSignal;
        public:
            InstructionTracker(S2E *s2e) : Plugin(s2e) {}

            void initialize();
            void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc);
            void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
            void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
            int getScore(S2EExecutionState *state);
            void setEntryPoint(S2EExecutionState *state,uint64_t entry_point);
            void slotTranslateBlockStart(ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
            void functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms);
            void functionRetMonitor(S2EExecutionState *state);
        };

    } // namespace plugins
} // namespace s2e

#endif