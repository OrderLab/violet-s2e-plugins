//
// Created by yigonghu on 8/23/19.
//

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include "InstructionTracker.h"

namespace s2e {
    namespace plugins {
        class InstructionTrackerState : public PluginState{
        private:
            int m_count;
            uint64_t entry_point;
            bool evoked;
            FunctionProfiler* m_plugin;
            bool regiesterd;

        public:
            InstructionTrackerState() {
                m_count = 0;
                entry_point = 0;
                evoked = false;
                regiesterd = false;
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

            void setEvokeState(S2EExecutionState* state, bool evostate) {
                evoked = evostate;
            }

            bool getEvokeState() {
                return evoked;
            }

            void setRegState(bool state) {
                regiesterd = state;
            }
            bool getRegState() {
                return regiesterd;
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
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            uint64_t entryPoint = plgState->getEntryPoint();
            m_monitor = s2e()->getPlugin<FunctionMonitor>();
            /**/
            if(entryPoint) {
                // When we find an interesting address, ask S2E to invoke our callback when the address is actually
                // executed
                //signal->connect(sigc::mem_fun(*this, &InstructionTracker::onInstructionExecution));
                slotTranslateBlockStart(signal, state, tb, pc);

            }
        }

        // This callback is called only when the instruction at our address is executed.
        // The callback incurs zero overhead for all other instructions
        /*void InstructionTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
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
        }*/

        void InstructionTracker::slotTranslateBlockStart(ExecutionSignal* signal,
                                                       S2EExecutionState* state,
                                                       TranslationBlock* tb,
                                                       uint64_t pc){
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            if(plgState->getRegState()) {
                return;
            }
            callSignal = m_monitor->getCallSignal(state, -1, -1);
            callSignal->connect(sigc::mem_fun(*this, &InstructionTracker::functionCallMonitor));

            plgState->setRegState(true);
        }

        void InstructionTracker::functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms) {
            uint64_t addr = state->regs()->getPc();
            FUNCMON_REGISTER_RETURN(state, fms, InstructionTracker::functionRetMonitor);
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            getDebugStream(state) << "Evoke call monitor at state" << state->getID() << " 0x" << hexval(addr) << "\n";
            plgState->setEvokeState(state, true);
        }

        void InstructionTracker::functionRetMonitor(S2EExecutionState *state) {
            // ...
            // Perform here any analysis or state manipulation you wish
            // ...
            uint64_t addr = state->regs()->getPc();
            getDebugStream(state) << "Evoke return monitor at state" << state->getID() << " pc 0x" <<  hexval(addr)  << "\n";
        }

        void InstructionTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            uint64_t addr = state->regs()->getPc();
            getDebugStream(state) << "OnCustomInstruction: Invoking Instruction Tracker at " << hexval(addr) << '\n';


            // Increment the count
            plgState->increment();

            if (plgState->get() > 11) {
                // Kill the current state
                getInfoStream(state) << "Killing state " << state->getID() << '\n';
                getInfoStream(state) << "Terminating state: State was terminated by exceeding the threshold\n";
                s2e()->getExecutor()->terminateState(*state);
            }
        }

        int InstructionTracker::getScore(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            return  plgState->get();
        }

        void InstructionTracker::setEntryPoint(S2EExecutionState *state,uint64_t entry_point) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            getInfoStream(state) << "Set the Entry Point " << hexval(entry_point) << '\n';
            return  plgState->setEntryPoint(entry_point);
        }

    } // namespace plugins
} // namespace s2e
