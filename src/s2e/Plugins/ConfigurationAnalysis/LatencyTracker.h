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

        class LatencyTracker : public Plugin, public IPluginInvoker {
            S2E_PLUGIN
        private:
            uint64_t m_address;
            bool is_profileAll;
            bool is_traceSyscall;
            FunctionMonitor* m_monitor;
            FunctionMonitor::CallSignal* callSignal;
        public:
            LatencyTracker(S2E *s2e) : Plugin(s2e) {
                is_profileAll = false;
                is_traceSyscall = true;
            }

            void initialize();
            void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc);
            void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
            int getScore(S2EExecutionState *state);
            int getCount(S2EExecutionState *state);
            int getSyscall(S2EExecutionState *state);
            void setEntryPoint(S2EExecutionState *state,uint64_t entry_point);
            void functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms);
            void functionRetMonitor(S2EExecutionState *state);
            void functionForEach(S2EExecutionState *state);
            void onSysenter(S2EExecutionState* state, uint64_t pc);
            void onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc, special_instruction_t type);
            void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
            void onException (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc, unsigned exception_idx);
            void onSyscall(S2EExecutionState* state, uint64_t pc, uint32_t sysc_number);
            int getLibraryCall(S2EExecutionState* state, const s2e::ModuleDescriptor& module, uint64_t pc);
        };

    } // namespace plugins
} // namespace s2e

#endif