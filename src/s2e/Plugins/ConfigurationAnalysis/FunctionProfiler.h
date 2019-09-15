#ifndef S2E_PLUGINS_MYMONITOR_H
#define S2E_PLUGINS_MYMONITOR_H

#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutionState.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <s2e/S2E.h>
#include <s2e/S2EExecutor.h>
#include <s2e/Utils.h>

namespace s2e {
    namespace plugins {
        class MyMonitorState;
        class FunctionProfiler : public Plugin {
            S2E_PLUGIN
        public:
            FunctionProfiler(S2E* s2e) : Plugin(s2e) {}
            ~FunctionProfiler() {}
            void initialize();
            void slotTranslateBlockStart(ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock* tb, uint64_t pc);
            void functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms);
            void functionRetMonitor(S2EExecutionState *state);
            void setEntryPoint(S2EExecutionState *state,uint64_t entry_point);

        private:
            FunctionMonitor* m_monitor;
            uint64_t m_address;
            FunctionMonitor::CallSignal* callSignal;
        };

        class MyMonitorState : public PluginState {
            bool evoked;
            FunctionProfiler* m_plugin;
            uint64_t entry_point;
        public:
            MyMonitorState() {
                evoked = false;
                regiesterd = false;
                entry_point = 0;
            }
            virtual ~MyMonitorState() {}
            static PluginState* factory(Plugin* p, S2EExecutionState* s);
            virtual MyMonitorState* clone() const;
            void setEvokeState(S2EExecutionState* state, bool evostate);
            //void CheckHookState(S2EExecutionState* state);

            bool getEvokeState() {
                return evoked;
            }

            void setRegState(bool state) {
                regiesterd = state;
            }
            bool getRegState() {
                return regiesterd;
            }

            void setEntryPoint(uint64_t EntryPoint){
                entry_point = EntryPoint;
            }

            uint64_t getEntryPoint() {
                return entry_point;
            }


        protected:
            friend class FunctionProfiler;
        private:
            bool regiesterd;
        };
    }
}

#endif
