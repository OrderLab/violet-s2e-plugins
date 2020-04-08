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
#include "FileIOTracker.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FileIOTracker, // Plugin class
    "Tracks File IO Instruction", // Plugin description
    "FileIOTracker", // Plugin name
    "LinuxMonitor"
    ); // no dependencies

void FileIOTracker::initialize() {
  createNewTraceFile(false);
  s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
      sigc::mem_fun(*this, &FileIOTracker::onTranslateSpecialInstructionEnd));
  s2e()->getCorePlugin()->onException.connect(
      sigc::mem_fun(*this, &FileIOTracker::onException));

  linuxMonitor = s2e()->getPlugin<LinuxMonitor>();
  linuxMonitor->onProcessLoad.connect(sigc::mem_fun(*this, &FileIOTracker::onProcessLoad));
  linuxMonitor->onProcessUnload.connect(sigc::mem_fun(*this, &FileIOTracker::onProcessUnload));
  linuxMonitor->onTrap.connect(sigc::mem_fun(*this, &FileIOTracker::onTrap));
  linuxMonitor->onSegFault.connect(sigc::mem_fun(*this, &FileIOTracker::onSegFault));

  is_trackSize = s2e()->getConfig()->getBool(getConfigKey() + ".trackBufferSize");
  targetProcessName = s2e()->getConfig()->getString(getConfigKey() + ".targetProcessName");
//  targetProcessStart = false;

//  uint64_t b = is_trackSize ? 1 : 0;
//  fwrite(&b, sizeof(uint64_t), 1, m_traceFile);

//  if (is_trackSize) {
//    fprintf(m_traceFile, "Track total buffer size read or written\n");
//  } else {
//    fprintf(m_traceFile, "Track # of read or write syscalls\n");
//  }

}

void FileIOTracker::onException(S2EExecutionState *state, unsigned exception_idx, uint64_t pc) {
  if (targetProcessPid != linuxMonitor->getPid(state)) return;
//  getWarningsStream(state) << "on exception 🌹  " << exception_idx << "\n";
}

void FileIOTracker::onTrap(S2EExecutionState *state, uint64_t pid, uint64_t pc, int trapnr) {
//  if (targetProcessPid != pid) return;
//  getWarningsStream(state) << "on trap 🍺 trap number " << trapnr << "\n";
}

void FileIOTracker::onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc) {
//  if (targetProcessPid != pid) return;
//  getWarningsStream(state) << "on segfault 🈹️ \n";
}

void FileIOTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                     TranslationBlock *tb, uint64_t pc,
                                                     special_instruction_t type) {
  if (type != SYSCALL) return;
  signal->connect(sigc::mem_fun(*this, & FileIOTracker::onSyscall));
}


void FileIOTracker::onSyscall(S2EExecutionState *state, uint64_t pc) {

  DECLARE_PLUGINSTATE(FileIOTrackerState, state);

  uint64_t eax, edx, fd;
  uint64_t read = 0, write = 1; // 0x0 sys_read, 0x1 sys_write
  uint64_t std_in = 0, std_out = 1, std_err = 2;

  // get value from eax and edx register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDI]), &fd, sizeof(fd));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from registers\n"; // << "\n";
    return;
  }

  if (targetProcessPid != linuxMonitor->getPid(state)) return;

  if (eax >> 1) return; // not read or write
//  if (!((fd ? --fd : fd) >> 1)) return; // filter when fd is stdin/out/err

  if (fd == std_in || fd == std_out || fd == std_err)
    return;

  //

  if (eax == read) {
    plgState->inc_read(edx);
    updateMap(state, read);
//    getInfoStream() << "r " << edx << " [";
//    //getWarningsStream() << linuxMonitor->getPid(state) << " " << linuxMonitor->getTid(state) << "]\n";
//    getWarningsStream() << linuxMonitor->getPid(state) << " " << targetProcessPid << "]\n";
//    inc_state_read(state, is_trackSize ? edx : 1);
  } else if (eax == write) {
    plgState->inc_write(edx);
    updateMap(state, write);
//    getInfoStream() << "w " << edx << "\n";
//    inc_state_write(state, is_trackSize ? edx : 1);
  }

}

void FileIOTracker::updateMap(S2EExecutionState *state, uint64_t r_w) {
  DECLARE_PLUGINSTATE(FileIOTrackerState, state);
  uint64_t read = 0, write = 1;
  if (r_w == read) {
    uint64_t n = is_trackSize ? plgState->get_read_bytes() : plgState->get_read_cnt();
    if (m_rw.find(state->getID()) != m_rw.end()) {
      m_rw.at(state->getID()).first = n;
    } else {
      m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
          state->getID(), pair<uint64_t, uint64_t>(n, 0)));
    }
  } else if (r_w == write){
    uint64_t n = is_trackSize ? plgState->get_write_bytes() : plgState->get_write_cnt();
    if (m_rw.find(state->getID()) != m_rw.end()) {
      m_rw.at(state->getID()).second = n;
    } else {
      m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
          state->getID(), pair<uint64_t, uint64_t>(0, n)));
    }
  }
}

void FileIOTracker::onProcessLoad(S2EExecutionState *state, uint64_t cr3, uint64_t pid, const std::string &filename) {
  //getWarningsStream(state) << "!!!!!! on process load got!!!!! " << filename << " --- " << pid << "\n";
  if (targetProcessName == filename) {
    targetProcessPid = pid;
//    targetProcessStart = true;
  }
}

void FileIOTracker::onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t ReturnCode) {
  //getWarningsStream(state) << "!!!!!! on process exit got!!!!! " << pid << "\n";
//  if (pid == targetProcessPid) {
////    targetProcessStart = false;
//  }
}

//void FileIOTracker::inc_state_read(S2EExecutionState *state, uint64_t length) {
//  if (m_rw.find(state->getID()) != m_rw.end()) {
//    m_rw.at(state->getID()).first += length;
//  } else {
//    m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
//        state->getID(), pair<uint64_t, uint64_t>(length, 0)));
//  }
//}
//
//void FileIOTracker::inc_state_write(S2EExecutionState *state, uint64_t length) {
//  if (m_rw.find(state->getID()) != m_rw.end()) {
//    m_rw.at(state->getID()).second += length;
//  } else {
//    m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
//        state->getID(), pair<uint64_t, uint64_t>(0, length)));
//  }
//}

void FileIOTracker::createNewTraceFile(bool append) {
  if (append) {
    assert(m_fileName.size() > 0);
    m_traceFile = fopen(m_fileName.c_str(), "a");
  } else {
    m_fileName = s2e()->getOutputFilename("FileIOTracker.result");
    m_traceFile = fopen(m_fileName.c_str(), "w");
  }
  if (!m_traceFile) {
    getWarningsStream() << "Could not create FileIOTracker.result" << '\n';
    exit(-1);
  }
}

FileIOTracker::~FileIOTracker() {
  // write results to FileIOTracker.result
  map<uint64_t, pair<uint64_t, uint64_t>>::iterator itr;
  for (itr = m_rw.begin(); itr != m_rw.end(); ++itr) {
    unsigned long state = itr->first, read = itr->second.first, write = itr->second.second;
    fprintf(m_traceFile, "State[%lu]  read %lu  write %lu\n", state, read, write);
  }
  if (!m_traceFile) return;
  fclose (m_traceFile);
  m_traceFile = nullptr;
}

}
}
