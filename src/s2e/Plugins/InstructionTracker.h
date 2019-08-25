//
// Created by yigonghu on 8/23/19.
//

#ifndef S2E_PLUGINS_INSTRTRACKER_H
#define S2E_PLUGINS_INSTRTRACKER_H

// These header files are located in libs2ecore
#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/Core/BaseInstructions.h>

namespace s2e {
    namespace plugins {

        class InstructionTracker : public Plugin, public IPluginInvoker {
            S2E_PLUGIN
        private:
            uint64_t m_address;
        public:
            InstructionTracker(S2E *s2e) : Plugin(s2e) {}

            void initialize();
            void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc);
            void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
            void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
        };

    } // namespace plugins
} // namespace s2e

#endif