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
#include <stack>
#include <ctime>
#include <list>
#include <mutex>

namespace s2e {
    namespace plugins {

        struct FunctionRecord {
            uint64_t function;
            uint64_t caller;
            double execution_time;
            clock_t begin;
        };

        class LatencyTracker : public Plugin, public IPluginInvoker {
            S2E_PLUGIN
        private:
            bool is_profileAll;
            bool traceSyscall;
            bool traceInstruction;
            uint64_t entryAddress;
            FunctionMonitor* m_monitor;
            FunctionMonitor::CallSignal* callSignal;
        public:
            enum enum_track_command {
                TRACK_START,TRACK_END
            };
            std::mutex m;

            LatencyTracker(S2E *s2e) : Plugin(s2e) {
                is_profileAll = false;
                traceSyscall = false;
                traceInstruction = false;
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
        };



        class LatencyTrackerState : public PluginState{
        private:
            int instructionCount;
            uint64_t loadEntry;
            bool regiesterd;

        public:
            std::vector<std::map<uint64_t,  struct FunctionRecord>> callLists;
            std::map<uint64_t,  struct FunctionRecord> callList;
            std::vector<uint64_t> keyStack;
            int syscallCount;
            bool traceFunction;
            int rootid;

            LatencyTrackerState() {
                instructionCount = 0;
                syscallCount = 0;
                loadEntry = 0;
                regiesterd = false;
                traceFunction = false;
                rootid = 0;
            }

            virtual ~LatencyTrackerState() {}

            static PluginState *factory(Plugin*, S2EExecutionState*) {
                return new LatencyTrackerState();
            }

            LatencyTrackerState *clone() const {
                return new LatencyTrackerState(*this);
            }

            void incrementInstructionCount() {
                ++instructionCount;
            }

            int getInstructionCount() {
                return instructionCount;
            }

            void setEntryPoint(uint64_t EntryPoint){
                loadEntry = EntryPoint;
            }

            uint64_t getEntryPoint() {
                return loadEntry;
            }

            void setRegState(bool state) {
                regiesterd = state;
            }
            bool getRegState() {
                return regiesterd;
            }

            void functionStart(uint64_t addr,uint64_t returnAddress) {
                clock_t begin = clock();
                uint64_t callerKey;
                struct FunctionRecord record;
                if (keyStack.empty()) {
                    record.caller = 0;
                    record.function = addr;
                    record.begin = begin;
                    record.execution_time = 0;
                    callList[returnAddress] = record;
                    keyStack.push_back(returnAddress);
                } else {
                    callerKey = keyStack.back();
                    record.caller = callList[callerKey].function;
                    record.function = addr;
                    record.begin = begin;
                    record.execution_time = 0;
                    callList[returnAddress] = record;
                    keyStack.push_back(returnAddress);
                }
            }

            void functionEnd(uint64_t returnAddress,clock_t end) {
                uint64_t key;

                if (keyStack.empty()) {
                    return;
                }

                std::vector<uint64_t>::iterator it = std::find(keyStack.begin(), keyStack.end(), returnAddress);
                if (it == keyStack.end()) {
                    return;
                }
                assert(callList.count(returnAddress) == 1 || callList.count(returnAddress) == 0);

                key = keyStack.back();
                keyStack.pop_back();
                while(key != returnAddress) {
                    key = keyStack.back();
                    keyStack.pop_back();
                }

                struct FunctionRecord &record = callList[key];
                end = clock();
                double execution = double (end - record.begin)/(CLOCKS_PER_SEC/1000);
                record.execution_time = execution;

                return;
            }

        };

    } // namespace plugins
} // namespace s2e

#endif