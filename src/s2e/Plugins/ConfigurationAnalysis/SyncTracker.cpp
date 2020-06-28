///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement
///

#include <s2e/ConfigFile.h>
#include <s2e/S2E.h>
#include <s2e/Utils.h>
#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/OSMonitors/Support/MemUtils.h>
#include <stdio.h>
#include <TraceEntries.pb.h>
#include "SyncTracker.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(SyncTracker, // Plugin class
    "Tracks Sync Instruction", // Plugin description
    "SyncTracker", // Plugin name
    "LinuxMonitor"
    ); // no dependencies

void SyncTracker::initialize() {
  createNewTraceFile(false);
  s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
      sigc::mem_fun(*this, &SyncTracker::onTranslateSpecialInstructionEnd));
  s2e()->getCorePlugin()->onException.connect(
      sigc::mem_fun(*this, &SyncTracker::onException));

  linuxMonitor = s2e()->getPlugin<LinuxMonitor>();
  linuxMonitor->onProcessLoad.connect(sigc::mem_fun(*this, &SyncTracker::onProcessLoad));
  linuxMonitor->onProcessUnload.connect(sigc::mem_fun(*this, &SyncTracker::onProcessUnload));
  linuxMonitor->onTrap.connect(sigc::mem_fun(*this, &SyncTracker::onTrap));
  linuxMonitor->onSegFault.connect(sigc::mem_fun(*this, &SyncTracker::onSegFault));

  targetProcessName = s2e()->getConfig()->getString(getConfigKey() + ".targetProcessName");
  getWarningsStream() << ">>>>>>>>> target process name : " << targetProcessName << "\n";

}

void SyncTracker::onException(S2EExecutionState *state, unsigned exception_idx, uint64_t pc) {
//  if (targetProcessPid != linuxMonitor->getPid(state)) return;
//  getWarningsStream(state) << "on exception 🌹  " << exception_idx << "\n";
}

void SyncTracker::onTrap(S2EExecutionState *state, uint64_t pid, uint64_t pc, int trapnr) {
//  if (targetProcessPid != pid) return;
//  getWarningsStream(state) << "on trap 🍺 trap number " << trapnr << "\n";
}

void SyncTracker::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
//  if (targetProcessPid != pid) return;
//  getWarningsStream(state) << "on segfault 🈹️ \n";
}

void SyncTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                     TranslationBlock *tb, uint64_t pc,
                                                     special_instruction_t type) {
  if (type != SYSCALL) return;
  signal->connect(sigc::mem_fun(*this, & SyncTracker::onSyscall));
}


void SyncTracker::onSyscall(S2EExecutionState *state, uint64_t pc) {

  if (targetProcessPid != linuxMonitor->getPid(state)) return;

  DECLARE_PLUGINSTATE(SyncTrackerState, state);

  uint64_t eax, uaddr, op, val;//, utime, uaddr2, val3;

  /* sys_futex 202
   * rdi = uaddr, rsi = op, rdx = val, r10 = utime, r8 = uaddr2, r9 = val3
   * 2 operations, PRIVATE WAIT (128) & WAKE (129)
   * TODO count time etc.
   */
  uint64_t sys_futex_call = 202;

  // get value from eax and edx register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from eax register\n";
    return;
  }
  if (eax != sys_futex_call) return;

  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDI]), &uaddr, sizeof(uaddr));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_ESI]), &op, sizeof(op));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &val, sizeof(val));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from registers\n";
    return;
  }

  getWarningsStream(state) << "eax: " << eax << ", " << "uaddr: " << uaddr << ", "
                            << "futex_op: " << op << ", " << "val: " << val << "\n";

  plgState->inc_cnt();

}

void SyncTracker::onProcessLoad(S2EExecutionState *state, uint64_t cr3, uint64_t pid, const std::string &filename) {
  //getWarningsStream(state) << "!!!!!! on process load got!!!!! " << filename << " --- " << pid << "\n";
  if (targetProcessName == filename) {
    targetProcessPid = pid;
//    targetProcessStart = true;
  }
}

void SyncTracker::onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t ReturnCode) {
  //getWarningsStream(state) << "!!!!!! on process exit got!!!!! " << pid << "\n";
//  if (pid == targetProcessPid) {
////    targetProcessStart = false;
//  }
}

//bool SyncTracker::in_readSyscallList(uint64_t syscall_number) {
//  for (auto it = readSyscallList.begin(); it != readSyscallList.end(); ++it) {
//    if (*it == syscall_number)
//      return true;
//  }
//  return false;
//}
//
//bool SyncTracker::in_writeSyscallList(uint64_t syscall_number){
//  for (auto it = writeSyscallList.begin(); it != writeSyscallList.end(); ++it) {
//    if (*it == syscall_number)
//      return true;
//  }
//  return false;
//}


//void SyncTracker::inc_state_read(S2EExecutionState *state, uint64_t length) {
//  if (m_rw.find(state->getID()) != m_rw.end()) {
//    m_rw.at(state->getID()).first += length;
//  } else {
//    m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
//        state->getID(), pair<uint64_t, uint64_t>(length, 0)));
//  }
//}
//
//void SyncTracker::inc_state_write(S2EExecutionState *state, uint64_t length) {
//  if (m_rw.find(state->getID()) != m_rw.end()) {
//    m_rw.at(state->getID()).second += length;
//  } else {
//    m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
//        state->getID(), pair<uint64_t, uint64_t>(0, length)));
//  }
//}

void SyncTracker::getSyncTracer(S2EExecutionState *state) {
  DECLARE_PLUGINSTATE(SyncTrackerState, state);
  printf("State [%d] contains %lu sys_futex operations\n", state->getID(), plgState->get_cnt());
//  fprintf(m_traceFile, "State[%d] read %lu bytes through %lu read calls, write %lu bytes through %lu write calls\n",
//          state->getID(), plgState->get_read_bytes(), plgState->get_read_cnt(), plgState->get_write_bytes(),
//          plgState->get_write_cnt());
}

void SyncTracker::createNewTraceFile(bool append) {
  if (append) {
    assert(m_fileName.size() > 0);
    m_traceFile = fopen(m_fileName.c_str(), "a");
  } else {
    m_fileName = s2e()->getOutputFilename("SyncTracker.result");
    m_traceFile = fopen(m_fileName.c_str(), "w");
  }
  if (!m_traceFile) {
    getWarningsStream() << "Could not create SyncTracker.result" << '\n';
    exit(-1);
  }
}

SyncTracker::~SyncTracker() {
//  // write results to SyncTracker.result
//  map<uint64_t, pair<uint64_t, uint64_t>>::iterator itr;
//  for (itr = m_rw.begin(); itr != m_rw.end(); ++itr) {
//    unsigned long state = itr->first, read = itr->second.first, write = itr->second.second;
//    fprintf(m_traceFile, "State[%lu]  read %lu  write %lu\n", state, read, write);
//  }
  if (!m_traceFile) return;
  fclose (m_traceFile);
  m_traceFile = nullptr;
}

}
}
