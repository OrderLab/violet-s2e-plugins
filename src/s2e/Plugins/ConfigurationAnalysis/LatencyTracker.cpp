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
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>
#include <string.h>
#include <stdio.h>

using namespace std;
namespace s2e {
namespace plugins {
#define CONFIGURATION 1024

// Define a plugin whose class is LatencyTracker and called "LatencyTracker"
S2E_DEFINE_PLUGIN(LatencyTracker,                   // Plugin class
    "Tracking execution latency and other cost metrics",   // Description
    "LatencyTracker",                 // Plugin function name
    );

void LatencyTracker::initialize() {
  is_profileAll = s2e()->getConfig()->getBool(getConfigKey() + ".profileAllFunction");
  traceFileIO = s2e()->getConfig()->getBool(getConfigKey() + ".traceFileIO");
  traceSyscall = s2e()->getConfig()->getBool(getConfigKey() + ".traceSyscall");
  traceInstruction = s2e()->getConfig()->getBool(getConfigKey() + ".traceInstruction");
  traceFunctionCall = s2e()->getConfig()->getBool(getConfigKey() + ".traceFunctionCall");
  // entryAddress config is deprecated: now we can directly calculate the
  // static entry address from the load bias
  entryAddress = (uint64_t) s2e()->getConfig()->getInt(getConfigKey() + ".entryAddress");
  printTrace = s2e()->getConfig()->getBool(getConfigKey() + ".printTrace");
  traceInputCallstack = s2e()->getConfig()->getBool((getConfigKey() + ".traceInput"));
  createNewTraceFile(false);
  if (traceFileIO) {
    s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
        sigc::mem_fun(*this, &LatencyTracker::onTranslateSpecialInstructionEnd));
  }

  s2e()->getCorePlugin()->onTranslateInstructionStart.connect(
      sigc::mem_fun(*this, &LatencyTracker::onTranslateInstruction));
}

void LatencyTracker::createNewTraceFile(bool append) {
  if (append) {
    assert(m_fileName.size() > 0);
    assert(m_symbolicFileName.size() > 0);
    m_traceFile = fopen(m_fileName.c_str(), "a");
    m_symbolicTraceFile = fopen(m_symbolicFileName.c_str(),"a");
    m_ioTraceFile = fopen(m_ioFileName.c_str(),"a");
  } else {
    m_fileName = s2e()->getOutputFilename("LatencyTracer.dat");
    m_traceFile = fopen(m_fileName.c_str(), "wb");
    m_symbolicFileName = s2e()->getOutputFilename("ConstraintTracer.dat");
    m_symbolicTraceFile = fopen(m_symbolicFileName.c_str(),"wb");
    m_ioFileName = s2e()->getOutputFilename("IOTracer.dat");
    m_ioTraceFile = fopen(m_ioFileName.c_str(), "wb");
  }
  if (!m_traceFile || !m_symbolicTraceFile || !m_ioTraceFile) {
    getWarningsStream() << "Could not create LatencyTracer.dat" << '\n';
    exit(-1);
  }

  if(traceInputCallstack) {
    m_inputFileName = s2e()->getOutputFilename("inputs.txt");
    m_inputFile = fopen(m_inputFileName.c_str(),"w");
    if (!m_inputFile ) {
      getWarningsStream() << "Could not create Callstack.txt" << '\n';
      exit(-1);
    }
  }
}

void LatencyTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
    TranslationBlock *tb, uint64_t pc,
    special_instruction_t type) {
  if (type == SYSENTER || type == SYSCALL) {
    signal->connect(sigc::mem_fun(*this, &LatencyTracker::onSyscall));
  }
}

void LatencyTracker::onInstructionExecution(S2EExecutionState *state, uint64_t pc) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  plgState->addInstructions();
}

void LatencyTracker::countSyscall(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  plgState->syscallCount++;
}

void LatencyTracker::onSyscall(S2EExecutionState *state, uint64_t pc) {
  DECLARE_PLUGINSTATE (LatencyTrackerState, state);

  uint64_t eax, edx, fd;
  uint64_t read = 0, write = 1, pread64 = 17, pwrite64 = 18; // 0x0 sys_read, 0x1 sys_write
  uint64_t std_in = 0, std_out = 1, std_err = 2;

  if (plgState->m_Pid != linuxMonitor->getPid(state))
    return;
  uint64_t current_tid = linuxMonitor->getTid(state);
  if(std::find(plgState->threadList.begin(), plgState->threadList.end(), current_tid) == plgState->threadList.end()) {
    return;
  }

  if (traceSyscall)
    countSyscall(state);

  // get value from eax and edx register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDI]), &fd, sizeof(fd));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from registers\n"; // << "\n";
    return;
  }

  if (fd == std_in || fd == std_out || fd == std_err)
    return;

  if (eax == pread64) {
    plgState->inc_pread(edx);
  } else if (eax == pwrite64) {
    plgState->inc_pwrite(edx);
  }

  if (eax == read) {
    plgState->inc_read(edx);
  } else if (eax == write) {
    plgState->inc_write(edx);
  }
  return;
}

int LatencyTracker::getInstructionNumber(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  return plgState->getInstructions();
}

int LatencyTracker::getSyscall(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  return plgState->syscallCount;
}

void LatencyTracker::onTranslateInstruction(ExecutionSignal *signal,
    S2EExecutionState *state,
    TranslationBlock *tb,
    uint64_t pc) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  uint64_t entryPoint = plgState->getEntryPoint();

  if (entryPoint && traceInstruction) {
    signal->connect(sigc::mem_fun(*this, &LatencyTracker::onInstructionExecution));
  }

  if (is_profileAll) {
    if (plgState->getRegState()) {
      return;
    }
    // When s2e starts at the entry of our module, we begin to analyse function
    functionMonitor = s2e()->getPlugin<FunctionMonitor>();
    if (!functionMonitor) {
      getWarningsStream(state) << "ERROR: Function Monitor plugin could not be found  \n";
      return;
    }
    callSignal = functionMonitor->getCallSignal(state, -1, -1);
    callSignal->connect(sigc::mem_fun(*this, &LatencyTracker::functionCallMonitor));
    plgState->setRegState(true);
  }

}

void LatencyTracker::setEntryPoint(S2EExecutionState *state,
    uint64_t entry_point, uint64_t load_bias) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  getInfoStream(state) << "Set the entry point to " << hexval(entry_point)
    << " with load bias " << hexval(load_bias) << "\n";
  return plgState->setEntryPoint(entry_point, load_bias);
}

/*Instrument the start point and end point of function tracer*/
void LatencyTracker::handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr,
    uint64_t guestDataSize) {
  enum_track_command command;
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  uint64_t current_tid;
  vector<uint64_t >::iterator index;
  if (is_profileAll) {
    return;
  }

  if (guestDataSize != sizeof(command)) {
    if (guestDataSize == CONFIGURATION) {
      if (!state->mem()->read(guestDataPtr, &configuration, guestDataSize)) {
      getWarningsStream(state) << "could not read transmitted data\n";
      exit(-1);
    }
    getInfoStream(state) << "the configuration is " << configuration << "\n";
   } else {
      char in[2048] = "\0";
      if (!state->mem()->read(guestDataPtr, &in, guestDataSize)) {
        getWarningsStream(state) << "could not read transmitted data\n";
        exit(-1);
      }
      input = in;
      getInfoStream(state) << "the input is " << input << "; data size " << guestDataSize << "\n";

    }

    return;
  }

  if (!state->mem()->read(guestDataPtr, &command, guestDataSize)) {
    getWarningsStream(state) << "could not read transmitted data\n";
    exit(-1);
  }
  switch (command) {
    case LOG_ADDRESS:
      getInfoStream(state) << "Get the address at pc = " << hexval(state->regs()->getPc())<< '\n';
      break;
    case TRACK_START:
      functionMonitor = s2e()->getPlugin<FunctionMonitor>();
      linuxMonitor = s2e()->getPlugin<LinuxMonitor>();
      if (!functionMonitor) {
        getWarningsStream(state) << "ERROR: Function Monitor plugin could not be found  \n";
        return;
      }

    //TODO:ADD PID CHECKING
      if(plgState->m_Pid == 0)
        plgState->m_Pid = linuxMonitor->getPid(state);
      plgState->threadList.push_back(linuxMonitor->getTid(state));
      if (plgState->getRegState()) {
        return;
      }

      callSignal = functionMonitor->getCallSignal(state, -1, -1);
      callSignal->connect(sigc::mem_fun(*this, &LatencyTracker::functionCallMonitor));
      plgState->flag = false;
      plgState->setRegState(true);
      break;

    case TRACK_END:
      current_tid = linuxMonitor->getTid(state);
      if (plgState->m_Pid == 0) {
        getWarningsStream(state) << "no pid\n";
        return;
      }

      index = std::find(plgState->threadList.begin(), plgState->threadList.end(), current_tid);
      if(index != plgState->threadList.end()) {
        plgState->IdList[current_tid] = 0;
        plgState->threadList.erase(index);
        if(plgState->threadList.empty())
          plgState->m_Pid = 0;
      } else {
        getWarningsStream(state) << "can't find trace start for tid = " << current_tid << "\n";
        return;
      }

      if (!plgState->callList[current_tid].empty()) {
        getWarningsStream(state) << "check the case\n";
        if(plgState->callList[current_tid].size() == 1 && plgState->returnList[current_tid].empty())
          return;

        plgState->callLists.push_back(plgState->callList[current_tid]);
        plgState->callList[current_tid].clear();
        if(traceInputCallstack || !input.empty()) {
          plgState->inputLists.push_back(input);
        }
      }
      if (!plgState->returnList[current_tid].empty()) {
        plgState->returnLists.push_back(plgState->returnList[current_tid]);
        plgState->returnList[current_tid].clear();
      }
      break;
  }
}

void LatencyTracker::functionCallMonitor(S2EExecutionState *state, FunctionMonitorState *fms) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  if(plgState->flag)
    return;

  if ((is_profileAll || !plgState->threadList.empty()) && (linuxMonitor->getPid(state) == plgState->m_Pid)) {
    uint64_t addr = state->regs()->getPc();
    // Read the return address of the function call
    uint64_t esp;
    uint64_t returnAddress;
    uint64_t current_tid = linuxMonitor->getTid(state);

    if(std::find(plgState->threadList.begin(), plgState->threadList.end(), current_tid) == plgState->threadList.end()) {
      return;
    }

    bool ok = state->regs()->read(CPU_OFFSET(regs[R_ESP]), &esp, sizeof esp, false);
    if (!ok) {
      getWarningsStream(state) << "Function call with symbolic ESP!\n"
        << "  EIP=" << hexval(state->regs()->getPc())
        << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
      return;
    }
    ok = state->mem()->read(esp, &returnAddress, sizeof returnAddress);
    if (!ok) {
      getWarningsStream(state) << "Function call with symbolic memory!\n"
        << "  EIP=" << hexval(state->regs()->getPc())
        << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
      return;
    }

    plgState->functionStart(addr, returnAddress,current_tid);
    plgState->flag = true;

    FUNCMON_REGISTER_RETURN(state, fms, LatencyTracker::functionRetMonitor);
  }
}

void LatencyTracker::functionRetMonitor(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  if (is_profileAll || !plgState->threadList.empty()) {
    uint64_t esp;
    uint64_t returnAddress;
    uint64_t current_tid = linuxMonitor->getTid(state);

    uint64_t addr = state->regs()->getPc();
    bool ok = state->regs()->read(CPU_OFFSET(regs[R_ESP]), &esp, sizeof esp, false);
    if (!ok) {
      getWarningsStream(state) << "Function call with symbolic ESP!\n"
        << "  EIP=" << hexval(state->regs()->getPc())
        << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
      return;
    }

    ok = state->mem()->read(esp, &returnAddress, sizeof returnAddress);
    if (!ok) {
      getWarningsStream(state) << "Function call with symbolic memory!\n"
        << "  EIP=" << hexval(state->regs()->getPc())
        << " CR3=" << hexval(state->regs()->getPageDir()) << '\n';
      return;
    }

    plgState->functionEnd(addr, returnAddress,current_tid);
  }
}

void LatencyTracker::matchParent(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);

  for (auto callList = plgState->callLists.begin(); callList != plgState->callLists.end(); ++callList) {
    for (auto callSignal = callList->begin(); callSignal != callList->end(); ++callSignal) {
      uint64_t distance = UINT64_MAX;
      if (callSignal->second.acticityId == 0)
        continue;
      for (auto it = callList->begin(); it != callList->end(); ++it) {
        if ( callSignal->second.acticityId <= it->second.acticityId)
          continue;
        if ( callSignal->first > it->second.address && (callSignal->first - it->second.address) < distance ) {
          distance = callSignal->first - it->second.address;
          callSignal->second.callerAddress = it->second.address;
          callSignal->second.parentId = it->second.acticityId; // assigen the parent id
        }
      }
    }
  }
}

void LatencyTracker::calculateLatency(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);

  for (auto callList = plgState->callLists.rbegin(); callList != plgState->callLists.rend(); ++callList) {
    std::vector<RetSignal> returnList = plgState->returnLists.back();
    plgState->returnLists.pop_back();
    for (std::vector<struct returnRecord>::iterator returnSignal = returnList.begin();
        returnSignal != returnList.end(); ++returnSignal) {
      if (!callList->count(returnSignal->returnAddress))
        continue;
      CallSignal &callRecord = (*callList)[returnSignal->returnAddress];
      callRecord.execution_time = double(returnSignal->end - callRecord.begin) / (CLOCKS_PER_SEC / 1000);
      callRecord.retAddress = returnSignal->functionEnd;
    }

  }
}

void LatencyTracker::getFunctionTracer(S2EExecutionState *state, const ConcreteInputs &inputs) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  assert(plgState->callLists.size() == plgState->returnLists.size());

  if (traceFileIO) {
    writeIOToTrace(state);
  }

  if(!traceFunctionCall)
    return;

  if (!state->is_valid) {
    getInfoStream(state) << "Invalid path\n";
    return;
  }

  calculateLatency(state);
  matchParent(state);
  functionForEach(state);
  if (!printTrace) {
    writeTestCaseToTrace(state, inputs);
  }
}

void LatencyTracker::functionForEach(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(LatencyTrackerState, state);
  int index = 0;

  for (auto callList = plgState->callLists.begin(); callList != plgState->callLists.end(); ++callList) {
    if(traceInputCallstack) {
      std::string input_string = plgState->inputLists[index];
      size_t position =  input_string.find('\n');
      while(position != std::string::npos) {
        input_string.replace(position, 1, " ");
        position =  input_string.find('\n');
      }
      const char *input = input_string.c_str();
//      if(input) {
//        getDebugStream(state) << "input "  << input << "\n";
//      }
      fprintf(m_inputFile,"%s\n",input);
    }
    for (auto iterator = callList->begin(); iterator != callList->end(); ++iterator) {
      if (printTrace) {
        // Originally, we calculate load_bias from plgState->getEntryPoint() - entryAddress
        // Now, we directly use the load_bias from the kernel
        printCallRecord(state, plgState->getLoadBias(), &(iterator->second));
      }
        writeCallRecord(state, plgState->getLoadBias(), &(iterator->second),index);
    }
    index++;
  }
//  printConstraints(state,plgState->getLoadBias());
}

void LatencyTracker::flush() {
  if (m_traceFile) {
    fflush(m_traceFile);
  }
  if(m_symbolicTraceFile) {
    fflush(m_symbolicTraceFile);
  }
  if(m_inputFile) {
    fflush(m_inputFile);
  }
}

void LatencyTracker::printCallRecord(S2EExecutionState *state, uint64_t loadBias,
    struct callRecord *record) {
//  if(record->acticityId)
//    return;
  if (record->callerAddress) {
    getInfoStream(state) << "Function "
      << hexval(record->address - loadBias)
      << "; activityId " << record->acticityId << "; caller "
      << hexval(record->callerAddress - loadBias)
      << "; parentId " << record->parentId
      << "; runs " << record->execution_time << "ms;\n";
  } else {
    getInfoStream(state) << "Function "
      << hexval(record->address - loadBias)
      << "; activityId " << record->acticityId << "; caller "
      << hexval(record->callerAddress) <<  "; parentId -1; runs " << record->execution_time
      << "ms;\n";
  }
}

void LatencyTracker::printConstraints(S2EExecutionState *state, uint64_t loadBias) {
  getDebugStream(state) << "===== Constraints =====\n";
  for (auto c : state->constraints.constMap) {
    getDebugStream(state) << "Function " << hexval(c.first -loadBias) << ", " << "Constraint " << c.second << "\n";
  }
  getDebugStream(state) << "\n";
}


bool LatencyTracker::writeCallRecord(S2EExecutionState *state, uint64_t loadBias,
    struct callRecord *record, int input) {
  assert(m_traceFile);
  int state_id = 0;
  if (state) {
    state_id = state->getID();
  }

  // always write state id first
  if (!traceInputCallstack) {
    if (fwrite(&state_id, sizeof(int), 1, m_traceFile) != 1) {
      return false;
    }
  } else {
    if (fwrite(&input, sizeof(int), 1, m_traceFile) != 1) {
      return false;
    }
  }

  uint64_t rawAddress = record->address;
  if (loadBias != 0) {
    // only update the address is the entry point was set
    record->address = rawAddress - loadBias;
    record->callerAddress = record->callerAddress - loadBias;
  }
  // the address written to the trace file will be based on the entry
  // address in the ELF file, instead of the dynamic entry point.
  if (fwrite(record, sizeof(callRecord), 1, m_traceFile) != 1) {
    return false;
  }
  // restore the raw address.
  // FIXME: maybe not really necessary to restore it...
  record->address = rawAddress;
  return true;
}

void LatencyTracker::writeTestCaseToTrace(S2EExecutionState *state, const ConcreteInputs &inputs) {
  std::stringstream ss;
  ConcreteInputs::const_iterator it;
  std::string constraints_name;
  assert(m_symbolicTraceFile);
  int state_id = 0;
  if (state) {
    state_id = state->getID();
  }
  for (it = inputs.begin(); it != inputs.end(); ++it) {
    const VarValuePair &vp = *it;
    int64_t valueAsInt = 0;
    struct concreteConstraint pair;
    std::size_t index = vp.first.find("_");
    std::size_t rindex = vp.first.rfind("_");
    pair.constraintsIndex = std::stoi(vp.first.substr(1, (index-1)));
    constraints_name = vp.first.substr(index+1,(rindex-index-1));
    getInfoStream(state) << "the constraints name is " << constraints_name << " the target configuration is " << configuration <<"\n";
    if(!strcmp(constraints_name.c_str(),configuration)) {
      pair.is_target = true;
    } else {
      pair.is_target = false;
    }
//    getInfoStream(state) << "the test configuration is " << constraints_name << "\n";

    for (unsigned i = 0; i < vp.second.size(); ++i) {
      valueAsInt |= ((int64_t) vp.second[i] << (i*8));
    }
    pair.value = valueAsInt;
    pair.id = state_id;

    if (fwrite(&pair, sizeof(struct concreteConstraint), 1, m_symbolicTraceFile) != 1) {
      return ;
    }

    size_t length = vp.second.size();
    if (fwrite(&length, sizeof(size_t), 1, m_symbolicTraceFile) != 1) {
      return ;
    }

////    while (for i = 0; i < length; i++)
////      if (fwrite(vp.second[i], 1, 1, m_symbolicTraceFile) != 1) {
////        return ;
////      }
    if (fwrite(&vp.second[0], sizeof(vector<unsigned char>::value_type), length, m_symbolicTraceFile) != length) {
      return ;
    }

    length = constraints_name.size();
    //getWarningsStream(state) << "the test leng is " << length << "\n";
    if (fwrite(&length, sizeof(size_t), 1, m_symbolicTraceFile) != 1) {
      return ;
    }
    if (fwrite(constraints_name.c_str(), 1, length, m_symbolicTraceFile) != length) {
      return ;
    }
    // getInfoStream(state) << pair.id << " " << pair.constraintsIndex << " " << pair.value << " "<< pair.is_target << "\n";
    getInfoStream(state) << pair.id << " " << pair.constraintsIndex << " " << pair.value << " "<< pair.is_target << "\n";
  }
  flush();
}

void LatencyTracker::writeIOToTrace(S2EExecutionState *state) {

  DECLARE_PLUGINSTATE(LatencyTrackerState, state);

  assert(m_ioTraceFile);
  int state_id = 0;
  if (state) {
    state_id = state->getID();
  }

  getInfoStream(state) << "read " << plgState->get_read_bytes() << " bytes through " << plgState->get_read_cnt() << " read call, "
                       << "read " << plgState->get_pread_bytes() << " bytes through " << plgState->get_pread_cnt() << " pread calls, "
                       << "write " << plgState->get_write_bytes() << " bytes through " << plgState->get_write_cnt()<< " write calls, "
                       << "write " << plgState->get_pwrite_bytes() << " bytes through " << plgState->get_pwrite_cnt() << " pwrite calls\n" ;

  struct ioRecord record;
  record.id = state_id;
  record.read_cnt = plgState->get_read_cnt();
  record.read_bytes = plgState->get_read_bytes();
  record.write_cnt = plgState->get_write_cnt();
  record.write_bytes = plgState->get_write_bytes();
  record.pread_cnt = plgState->get_pread_cnt();
  record.pread_bytes = plgState->get_pread_bytes();
  record.pwrite_cnt = plgState->get_pwrite_cnt();
  record.pwrite_bytes = plgState->get_pwrite_bytes();

  if (fwrite(&record, sizeof(struct ioRecord), 1, m_ioTraceFile) != 1) {
    return ;
  }

}


LatencyTracker::~LatencyTracker() {
  if (m_traceFile) {
    fclose(m_traceFile);
    m_traceFile = nullptr;
  }
  if(m_symbolicTraceFile) {
    fclose(m_symbolicTraceFile);
    m_symbolicTraceFile = nullptr;
  }
  if(m_inputFile) {
    fclose(m_inputFile);
    m_inputFile = nullptr;
  }
}

} // namespace plugins
} // namespace s2e

