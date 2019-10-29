//
// Created by yigonghu on 8/23/19.
//

#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include "s2e/Plugins/ExecutionMonitors/LibraryCallMonitor.h"
#include "LatencyTracker.h"
#include <stack>
#include <assert.h>


using namespace std;
namespace s2e {
    namespace plugins {

        // Define a plugin whose class is LatencyTracker and called "LatencyTracker"
        S2E_DEFINE_PLUGIN(LatencyTracker,                   // Plugin class
                          "Tutorial - Tracking instructions",   // Description
                          "LatencyTracker",                 // Plugin function name
        );

        void LatencyTracker::initialize() {
            is_profileAll = s2e()->getConfig()->getBool(getConfigKey() + ".profileAllFunction");
            traceSyscall = s2e()->getConfig()->getBool(getConfigKey() + ".traceSyscall");
            traceInstruction = s2e()->getConfig()->getBool(getConfigKey() + ".traceInstruction");
            entryAddress = (uint64_t)s2e()->getConfig()->getInt(getConfigKey() + ".entryAddress");

            s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
                    sigc::mem_fun(*this, &LatencyTracker::onTranslateInstruction));
            if (traceSyscall) {
                s2e()->getCorePlugin()->onTranslateSoftInterruptStart.connect (sigc::mem_fun(*this, &LatencyTracker::onException));
                s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(sigc::mem_fun(*this, &LatencyTracker::onTranslateSpecialInstructionEnd));
            }
        }

        void LatencyTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                TranslationBlock *tb, uint64_t pc, special_instruction_t type){
            if (type == SYSENTER || type == SYSCALL) {
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

            if(entryPoint && traceInstruction) {
                signal->connect(sigc::mem_fun(*this, &LatencyTracker::onInstructionExecution));
            }


            if(is_profileAll) {
                if(plgState->getRegState()) {
                    return;
                }
                // When s2e starts at the entry of our module, we begin to analyse function
                m_monitor = s2e()->getPlugin<FunctionMonitor>();
                callSignal = m_monitor->getCallSignal(state, -1, -1);
                callSignal->connect(sigc::mem_fun(*this, &LatencyTracker::functionCallMonitor));
                plgState->setRegState(true);
            }

        }

        void LatencyTracker::setEntryPoint(S2EExecutionState *state,uint64_t entry_point) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            getInfoStream(state) << "Set the Entry Point " << hexval(entry_point) << '\n';
            return  plgState->setEntryPoint(entry_point);
        }

        /*Instrument the start point and end point of function tracer*/
        void LatencyTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
            enum_track_command command;
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);

            if (is_profileAll) {
                return;
            }

            if (guestDataSize != sizeof(command)) {
                getWarningsStream(state) << "mismatched S2E_MODULE_MAP_COMMAND size\n";
                exit(-1);
            }

            if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
                getWarningsStream(state) << "could not read transmitted data\n";
                exit(-1);
            }
            switch (command) {
                case TRACK_START:
                    m_monitor = s2e()->getPlugin<FunctionMonitor>();
                    plgState->traceFunction = true;
                    plgState->rootid++;
                    if(plgState->getRegState())
                        return;
                    callSignal = m_monitor->getCallSignal(state, -1, -1);
                    callSignal->connect(sigc::mem_fun(*this, &LatencyTracker::functionCallMonitor));
                    plgState->setRegState(true);
                    break;
                case TRACK_END:
                    plgState->traceFunction = false;
                    break;
            }
        }

        void LatencyTracker::functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            if (is_profileAll || plgState->traceFunction) {
                uint64_t addr = state->regs()->getPc();

                // Read the return address of the function call
                uint64_t esp;
                uint64_t returnAddress;
                bool ok = state->regs()->read(CPU_OFFSET(regs[R_ESP]), &esp, sizeof esp, false);
                if (!ok) {
                    getWarningsStream(state) << "Function call with symbolic ESP!\n"
                                             << "  EIP=" << hexval(state->regs()->getPc())
                                             << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
                    return;
                }
                ok = state->mem()->read(esp,&returnAddress, sizeof returnAddress);
                if (!ok) {
                    getWarningsStream(state) << "Function call with symbolic memory!\n"
                                             << "  EIP=" << hexval(state->regs()->getPc())
                                             << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
                    return;
                }
                plgState->functionStart(addr,returnAddress);

                FUNCMON_REGISTER_RETURN(state, fms, LatencyTracker::functionRetMonitor);
            }
        }

        void LatencyTracker::functionRetMonitor(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            clock_t end = clock();
            if (plgState->keyStack.empty()){
                getDebugStream(state) << "No Caller\n";
            } else {
                // Read the return address of the function call
                uint64_t esp;
                uint64_t returnAddress;

                bool ok = state->regs()->read(CPU_OFFSET(regs[R_ESP]), &esp, sizeof esp, false);
                if (!ok) {
                    getWarningsStream(state) << "Function call with symbolic ESP!\n"
                                                       << "  EIP=" << hexval(state->regs()->getPc())
                                                       << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
                    return;
                }

                ok = state->mem()->read(esp,&returnAddress, sizeof returnAddress);
                if (!ok) {
                    getWarningsStream(state) << "Function call with symbolic memory!\n"
                                             << "  EIP=" << hexval(state->regs()->getPc())
                                             << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
                    return;
                }

                plgState->functionEnd(returnAddress,end);
            }
        }

        void LatencyTracker::functionForEach(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            for (auto iterator = plgState->callList.begin(); iterator != plgState->callList.end(); ++iterator){
                struct FunctionRecord record = iterator->second;
                if (record.caller) {
                    getInfoStream(state) << "Function " << hexval(record.function-plgState->getEntryPoint()+entryAddress)  <<"; caller: "
                                         << hexval(record.caller-plgState->getEntryPoint()+entryAddress) << "; runs " << record.execution_time << "ms;\n";
                } else {
                    getInfoStream(state) << "Function " << hexval(record.function-plgState->getEntryPoint()+entryAddress)  <<"; caller: "
                                         << hexval(record.caller) << "; runs " << record.execution_time << "ms;\n";
                }
            }
        }

        void LatencyTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            plgState->incrementInstructionCount();
        }

        void LatencyTracker::onSysenter(S2EExecutionState* state, uint64_t pc) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            plgState->syscallCount++;
        }

        void LatencyTracker::onSyscall(S2EExecutionState* state, uint64_t pc, uint32_t sysc_number) {
            DECLARE_PLUGINSTATE (LatencyTrackerState, state);
            plgState->syscallCount++;
            return;
        }

        int LatencyTracker::getScore(S2EExecutionState *state) {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            return plgState->getInstructionCount();
        }

        int LatencyTracker::getSyscall(S2EExecutionState *state)  {
            DECLARE_PLUGINSTATE(LatencyTrackerState, state);
            return plgState->syscallCount;
        }

    } // namespace plugins
} // namespace s2e
