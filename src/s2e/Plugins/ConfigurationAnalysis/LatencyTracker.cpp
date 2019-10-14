//
// Created by yigonghu on 8/23/19.
//

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include "s2e/Plugins/ExecutionMonitors/LibraryCallMonitor.h"
#include "LatencyTracker.h"
#include <list>
#include <stack>
#include <ctime>
using namespace std;
namespace s2e {
    namespace plugins {
        class LatencyTrackerState : public PluginState{
        private:
            int m_count;
            uint64_t entry_point;
            bool regiesterd;
            stack<pair<uint64_t,clock_t>> call_list;

        public:
            list<pair<uint64_t,double>> call_latency;
            int syscall_count;
            bool test_flag;
            clock_t begin ;
            LatencyTrackerState() {
                m_count = 0;
                syscall_count = 0;
                entry_point = 0;
                regiesterd = false;
                test_flag = false;
            }

            virtual ~LatencyTrackerState() {}

            static PluginState *factory(Plugin*, S2EExecutionState*) {
                return new LatencyTrackerState();
            }

            LatencyTrackerState *clone() const {
                return new LatencyTrackerState(*this);
            }

            void increment() {
                ++m_count;
            }

            int getScore() {
                return m_count;
            }

            void setEntryPoint(uint64_t EntryPoint){
                entry_point = EntryPoint;
            }

            uint64_t getEntryPoint() {
                return entry_point;
            }

            void setRegState(bool state) {
                regiesterd = state;
            }
            bool getRegState() {
                return regiesterd;
            }

            void functionStart(uint64_t addr) {
                clock_t begin = clock();
                call_list.push(make_pair(addr,begin));
            }

            bool functionEnd() {
                if (call_list.empty()) {
                    return false;
                }
                pair<uint64_t,clock_t> temp = call_list.top();
                call_list.pop();
                clock_t end = clock();
                call_latency.push_back(make_pair(temp.first,double(end - temp.second) / (CLOCKS_PER_SEC/1000)));
                return true;
            }

        };
        // Define a plugin whose class is LatencyTracker and called "LatencyTracker"
        S2E_DEFINE_PLUGIN(LatencyTracker,                   // Plugin class
        "Tutorial - Tracking instructions",   // Description
        "LatencyTracker",                 // Plugin function name
        // Plugin dependencies would normally go here. However this plugin does not have any dependencies
        );

        void LatencyTracker::initialize() {
            m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
            is_profileAll = s2e()->getConfig()->getBool(getConfigKey() + ".profileAllFunction");

            is_traceSyscall = s2e()->getConfig()->getBool(getConfigKey() + ".traceSyscall");
            // This indicates that our plugin is interested in monitoring instruction translation.
            // For this, the plugin registers a callback with the onTranslateInstruction signal.
            s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
                    sigc::mem_fun(*this, &LatencyTracker::onTranslateInstruction));

            if (is_traceSyscall) {
                s2e()->getCorePlugin()->onTranslateSoftInterruptStart.connect (sigc::mem_fun(*this, &LatencyTracker::onException));
                s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(sigc::mem_fun(*this, &LatencyTracker::onTranslateSpecialInstructionEnd));
            }
        }

        void LatencyTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state, TranslationBlock *tb, uint64_t pc, special_instruction_t type){

            if (type == SYSENTER || type == SYSCALL) {
                //s2e()->getDebugStream() << "Syscall " << hexval(pc) << " from the sysenter "<<"\n";
                signal->connect(sigc::mem_fun(*this, &LatencyTracker::onSysenter));
            }
        }

        void LatencyTracker::onException (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc, unsigned exception_idx) {
            if (exception_idx == 0x80) {
                // get eax register
                //s2e()->getDebugStream() << "Syscall " << hexval(pc) << " from the exception "<<"\n";
                uint64_t int_num = 0;
                int_num = int_num & 0xffffffff;
                onSyscall (state, pc, int_num);
            }
            return;
        }

        void LatencyTracker::onTranslateInstruction(ExecutionSignal *signal,
                                                        S2EExecutionState *state,
                                                        TranslationBlock *tb,
                                                        uint64_t pc) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            uint64_t entryPoint = plgState->getEntryPoint();

            if(entryPoint) {
                // When we find an interesting address, ask S2E to invoke our callback when the address is actually
                // executed
                signal->connect(sigc::mem_fun(*this, &LatencyTracker::onInstructionExecution));
            }

            /*
            if(is_profileAll) {
                // When s2e starts at the entry of our module, we begin to analyse function
                m_monitor = s2e()->getPlugin<FunctionMonitor>();
                if(plgState->getRegState()) {
                    return;
                }
                callSignal = m_monitor->getCallSignal(state, -1, -1);
                callSignal->connect(sigc::mem_fun(*this, &LatencyTracker::functionCallMonitor));

                plgState->setRegState(true);
            }
             */
        }

        void LatencyTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
            // This macro declares the plgState variable of type InstructionTrackerState.
            // It automatically takes care of retrieving the right plugin state attached to the specified execution state
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);

            // Increment the count
            plgState->increment();
        }


        void LatencyTracker::onSysenter(S2EExecutionState* state, uint64_t pc) {

            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            plgState->syscall_count++;
        }

        void LatencyTracker::onSyscall (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number) {
            DECLARE_PLUGINSTATE (LatencyTrackerState, state);
            plgState->syscall_count++;
            //uint64_t pid = state->getGuid();
            //s2e()->getDebugStream() << "Syscall " << hexval(pc) << " the id is "<< pid<<"\n";
            return;
        }

        void LatencyTracker::functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            uint64_t addr = state->regs()->getPc();
            plgState->functionStart(addr);

            FUNCMON_REGISTER_RETURN(state, fms, LatencyTracker::functionRetMonitor);

        }

        void LatencyTracker::functionRetMonitor(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            if (!plgState->functionEnd()){
                getDebugStream(state) << "No Caller\n";
            }
        }


        int LatencyTracker::getScore(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            return  plgState->getScore();
        }

        int LatencyTracker::getLibraryCall (S2EExecutionState* state, const s2e::ModuleDescriptor& module, uint64_t pc) {
            LibraryCallMonitor *tracker = s2e()->getPlugin<LibraryCallMonitor>();
            return tracker->getLibraryCall(state);
        }

        int LatencyTracker::getSyscall(S2EExecutionState *state)  {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            return plgState->syscall_count;
        }

        void LatencyTracker::functionForEach(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            for (auto iterator = plgState->call_latency.begin(); iterator != plgState->call_latency.end(); ++iterator)
                getInfoStream(state) << "Function " << hexval(iterator->first-plgState->getEntryPoint()+m_address) <<" runs " << iterator->second << "ms\n";
        }

        void LatencyTracker::setEntryPoint(S2EExecutionState *state,uint64_t entry_point) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            getInfoStream(state) << "Set the Entry Point " << hexval(entry_point) << '\n';
            return  plgState->setEntryPoint(entry_point);
        }


        void LatencyTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            m_monitor = s2e()->getPlugin<FunctionMonitor>();
            if(plgState->getRegState())
                return;
            callSignal = m_monitor->getCallSignal(state, -1, -1);
            callSignal->connect(sigc::mem_fun(*this, &LatencyTracker::functionCallMonitor));

            plgState->setRegState(true);
        }

        /*
        void InstructionTracker::registerFunctionProfiler(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);

            m_monitor = s2e()->getPlugin<FunctionMonitor>();
            if(plgState->getRegState()) {
                return;
            }
            callSignal = m_monitor->getCallSignal(state, -1, -1);
            callSignal->connect(sigc::mem_fun(*this, &InstructionTracker::functionCallMonitor));

            plgState->setRegState(true);
        }
*/

    } // namespace plugins
} // namespace s2e
