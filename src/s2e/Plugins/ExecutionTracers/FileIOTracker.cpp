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
    ); // no dependencies

void FileIOTracker::initialize() {
  createNewTraceFile(false);
  s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
      sigc::mem_fun(*this, &FileIOTracker::onTranslateSpecialInstructionEnd));
}


void FileIOTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                     TranslationBlock *tb, uint64_t pc,
                                                     special_instruction_t type) {
  if (type != SYSCALL) return;
  signal->connect(sigc::mem_fun(*this, & FileIOTracker::onSyscall));
}


void FileIOTracker::onSyscall(S2EExecutionState *state, uint64_t pc) {

  uint64_t eax, edx;
  uint64_t read = 0x0, write = 0x1; // 0x0 sys_read, 0x1 sys_write

  // get value from eax and edx register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from registers\n"; // << "\n";
    return;
  }

  if (eax >> 1) return; // not read or write

  // 139392, 139692

  if (eax == read) {
    getInfoStream() << "r " << edx << "\n";
    inc_state_read(state, edx);
  } else if (eax == write) {
    getInfoStream() << "w " << edx << "\n";
    inc_state_write(state, edx);
  }

}

void FileIOTracker::inc_state_read(S2EExecutionState *state, uint64_t length) {
  if (m_rw.find(state->getID()) != m_rw.end()) {
    m_rw.at(state->getID()).first += length;
  } else {
    m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
        state->getID(), pair<uint64_t, uint64_t>(length, 0)));
  }
}

void FileIOTracker::inc_state_write(S2EExecutionState *state, uint64_t length) {
  if (m_rw.find(state->getID()) != m_rw.end()) {
    m_rw.at(state->getID()).second += length;
  } else {
    m_rw.insert(pair<uint64_t, pair<uint64_t, uint64_t>>(
        state->getID(), pair<uint64_t, uint64_t>(0, length)));
  }
}

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
