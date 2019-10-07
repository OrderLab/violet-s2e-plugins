//
// Created by yigonghu on 8/23/19.
//

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include "InstructionTracker.h"
#include <list>
#include <stack>
#include <ctime>
using namespace std;
namespace s2e {
    namespace plugins {
        class InstructionTrackerState : public PluginState{
        private:
            int m_count;
            uint64_t entry_point;
            bool regiesterd;
            stack<pair<uint64_t,clock_t>> call_list;


        public:
            list<pair<uint64_t,double>> call_latency;
            bool test_flag;
            clock_t begin ;
            InstructionTrackerState() {
                m_count = 0;
                entry_point = 0;
                regiesterd = false;
                test_flag = false;
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
        // Define a plugin whose class is InstructionTracker and called "InstructionTracker"
        S2E_DEFINE_PLUGIN(InstructionTracker,                   // Plugin class
        "Tutorial - Tracking instructions",   // Description
        "InstructionTracker",                 // Plugin function name
        // Plugin dependencies would normally go here. However this plugin does not have any dependencies
        );

        void InstructionTracker::initialize() {
            m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
            is_profileAll = s2e()->getConfig()->getBool(getConfigKey() + ".profileAllFunction");
            is_traceSyscall = s2e()->getConfig()->getBool(getConfigKey() + ".traceSyscall");
            // This indicates that our plugin is interested in monitoring instruction translation.
            // For this, the plugin registers a callback with the onTranslateInstruction signal.
            s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
                    sigc::mem_fun(*this, &InstructionTracker::onTranslateInstruction));

            if (is_traceSyscall) {
                s2e()->getCorePlugin()->onException.connect (sigc::mem_fun(*this, &InstructionTracker::onException));
            }
        }

        void InstructionTracker::onTranslateInstruction(ExecutionSignal *signal,
                                                        S2EExecutionState *state,
                                                        TranslationBlock *tb,
                                                        uint64_t pc) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
           // uint64_t entryPoint = plgState->getEntryPoint();

            if(is_profileAll) {
                // When s2e starts at the entry of our module, we begin to analyse function
                m_monitor = s2e()->getPlugin<FunctionMonitor>();
                if(plgState->getRegState()) {
                    return;
                }
                callSignal = m_monitor->getCallSignal(state, -1, -1);
                callSignal->connect(sigc::mem_fun(*this, &InstructionTracker::functionCallMonitor));

                plgState->setRegState(true);
            }
        }

        void InstructionTracker::onException (S2EExecutionState* state, unsigned exception_idx, uint64_t pc) {
            //  s2e()->getDebugStream() << " >> Exception on pc: 0x" << hexval(pc)  << " exception_idx: " <<exception_idx << "(0x" << hexval(exception_idx) << ")\n";
            // 0x80 128d is software interrupt
            //  DECLARE_PLUGINSTATE (SyscallCatchState, state);
            if (exception_idx == 0x80) {
                // get eax register
                uint64_t int_num = 0;
                int_num = int_num & 0xffffffff;
                onSyscall (state, pc, int_num);
            }
            return;
        }

        void InstructionTracker::onSyscall (S2EExecutionState* state, uint64_t pc, uint32_t sysc_number) {
            // the kernel doesn't make system calls, so getPid () is accurate here
            getInfoStream(state) << "Syscall " << hexval(pc) << "\n";
            return;
        }

        void InstructionTracker::functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            uint64_t addr = state->regs()->getPc();
            plgState->functionStart(addr);

            FUNCMON_REGISTER_RETURN(state, fms, InstructionTracker::functionRetMonitor);

        }

        void InstructionTracker::functionRetMonitor(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            if (!plgState->functionEnd()){
                getDebugStream(state) << "No Caller\n";
            }
        }


        int InstructionTracker::getScore(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            return  plgState->get();
        }

        void InstructionTracker::functionForEach(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            for (auto iterator = plgState->call_latency.begin(); iterator != plgState->call_latency.end(); ++iterator)
                getInfoStream(state) << "Function " << hexval(iterator->first-plgState->getEntryPoint()+m_address) <<" runs " << iterator->second << "ms\n";
        }

        void InstructionTracker::setEntryPoint(S2EExecutionState *state,uint64_t entry_point) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            getInfoStream(state) << "Set the Entry Point " << hexval(entry_point) << '\n';
            return  plgState->setEntryPoint(entry_point);
        }


        void InstructionTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
            DECLARE_PLUGINSTATE(InstructionTrackerState, state);
            m_monitor = s2e()->getPlugin<FunctionMonitor>();
            if(plgState->getRegState())
                return;
            callSignal = m_monitor->getCallSignal(state, -1, -1);
            callSignal->connect(sigc::mem_fun(*this, &InstructionTracker::functionCallMonitor));

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
