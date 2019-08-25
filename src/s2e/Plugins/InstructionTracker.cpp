//
// Created by yigonghu on 8/23/19.
//

#include <s2e/S2E.h>
#include <s2e/Utils.h>

#include "InstructionTracker.h"

namespace s2e {
    namespace plugins {
        class InstructionTrackerState : public PluginState{
        private:
            int m_count;

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
        };
        // Define a plugin whose class is InstructionTracker and called "InstructionTracker"
        S2E_DEFINE_PLUGIN(InstructionTracker,                   // Plugin class
        "Tutorial - Tracking instructions",   // Description
        "InstructionTracker",                 // Plugin function name
        // Plugin dependencies would normally go here. However this plugin does not have any dependencies
        );

        void InstructionTracker::initialize() {
            m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
            // This indicates that our plugin is interested in monitoring instruction translation.
            // For this, the plugin registers a callback with the onTranslateInstruction signal.
            s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
                    sigc::mem_fun(*this, &InstructionTracker::onTranslateInstruction));
        }

        void InstructionTracker::onTranslateInstruction(ExecutionSignal *signal,
                                                        S2EExecutionState *state,
                                                        TranslationBlock *tb,
                                                        uint64_t pc) {
            //s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';
            if(m_address == pc) {
                // When we find an interesting address, ask S2E to invoke our callback when the address is actually
                // executed
                signal->connect(sigc::mem_fun(*this, &InstructionTracker::onInstructionExecution));
            }
        }

        // This callback is called only when the instruction at our address is executed.
        // The callback incurs zero overhead for all other instructions
        void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
            // This macro declares the plgState variable of type InstructionTrackerState.
            // It automatically takes care of retrieving the right plugin state attached to the specified execution state
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);

            s2e()->getDebugStream() << "Executing instruction at " << hexval(pc) << '\n';

            // Increment the count
            plgState->increment();
        }

        void InstructionTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);

            getDebugStream(state) << "OnCustomInstruction: Invoking Instruction Tracker " << plgState->get()  << '\n';

            // Increment the count
            plgState->increment();
        }

    } // namespace plugins
} // namespace s2e