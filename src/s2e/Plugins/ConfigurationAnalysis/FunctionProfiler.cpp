#include <s2e/S2E.h>
#include <s2e/ConfigFile.h>
#include <s2e/Utils.h>
#include "FunctionProfiler.h"

namespace s2e {
    namespace plugins {
    S2E_DEFINE_PLUGIN(FunctionProfiler, "Trace the latency of target function", "function profiler");
   
    void FunctionProfiler::initialize() {
        m_monitor = s2e()->getPlugin<FunctionMonitor>();
        m_address = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".addressToTrack");
        s2e()->getCorePlugin()->onTranslateBlockStart.connect(
                                                            sigc::mem_fun(*this, &FunctionProfiler::slotTranslateBlockStart));
    }

    void FunctionProfiler::slotTranslateBlockStart(ExecutionSignal* signal,
					    S2EExecutionState* state,
					    TranslationBlock* tb, 
					    uint64_t pc){
        DECLARE_PLUGINSTATE(MyMonitorState, state);
        uint64_t entryPoint = plgState->getEntryPoint();
        if(plgState->getRegState()) {
	        return;
        }
        getDebugStream(state) << "The entry point is " << hexval(m_address+entryPoint) << '\n';
        callSignal = m_monitor->getCallSignal(state, m_address+entryPoint, -1);
        callSignal->connect(sigc::mem_fun(*this, &FunctionProfiler::functionCallMonitor));

        plgState->setRegState(true);
    }
    
    void FunctionProfiler::functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms) {
        uint64_t addr = state->regs()->getPc();
        getDebugStream(state) << "Evoke call monitor at state" << state->getID() << " pc 0x" <<  hexval(addr)  << "\n";
        FUNCMON_REGISTER_RETURN(state, fms, FunctionProfiler::functionRetMonitor);
        DECLARE_PLUGINSTATE(MyMonitorState, state);
        plgState->setEvokeState(state, true);
    }

    void FunctionProfiler::functionRetMonitor(S2EExecutionState *state) {
        // ...
        // Perform here any analysis or state manipulation you wish
        // ...
        uint64_t addr = state->regs()->getPc();
        getDebugStream(state) << "Evoke return monitor at state" << state->getID() << " pc 0x" <<  hexval(addr)  << "\n";
    }


    void FunctionProfiler::setEntryPoint(S2EExecutionState *state,uint64_t entry_point) {
        DECLARE_PLUGINSTATE(MyMonitorState, state);
        getInfoStream(state) << "Set the Entry Point " << hexval(entry_point) << '\n';
        return  plgState->setEntryPoint(entry_point);
    }

    MyMonitorState* MyMonitorState::clone() const{
        MyMonitorState *ret = new MyMonitorState(*this);
        //m_plugin->s2e()->getDebugStream() << "Forking MyMonitorState ret=" << std::hex << ret << std::endl;
        return ret;
    }

    PluginState* MyMonitorState::factory(Plugin* p, S2EExecutionState* state) {
        MyMonitorState* ret = new MyMonitorState();
        ret->m_plugin = static_cast<FunctionProfiler*>(p);
        //ret->m_plugin->dm<<"Create MyMonitorState\n" << std::endl;
        // ret->m_plugin->s2e()->getDebugStream() << "Create MyMonitorState ret=" << std::hex << ret << std::endl;
        return ret;
    }
    
    void MyMonitorState::setEvokeState(S2EExecutionState* state, bool evostate) {
        evoked = evostate;
    }
  }
}
