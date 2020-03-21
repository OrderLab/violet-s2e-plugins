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

  // get value from eax register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from registers\n"; // << "\n";
    return;
  }

  if (eax >> 1) return; // not read or write

  //

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

//void FileIOTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
//                                                    TranslationBlock *tb, uint64_t pc,
//                                                    special_instruction_t type) {
//  if (type != SYSCALL) return;
//
//  uint64_t eax, edx;
//  uint64_t read = 0x0, write = 0x1; // 0x0 sys_read, 0x1 sys_write
//
//  // get value from eax register
//  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
//  if (!ok) {
//    getWarningsStream(state) << "couldn't read from EAX register at PC " << pc << "\n";
//    return;
//  }
//
//  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));
//  if (!ok) {
//    getWarningsStream(state) << "couldn't read from EDX register at PC " << pc << "\n";
//    return;
//  }
//
//  if (eax == read) {
//    if (m_read.find(state->getID()) == m_read.end()) {
//      m_read.insert(pair<uint64_t, uint64_t>(state->getID(), edx));
//    } else {
//      m_read.at(state->getID()) += edx;
//    }
////    getInfoStream(state) << "READ  system call at PC " << pc << "\n";
////    fprintf(m_traceFile, "State[%d] READ  system call at PC 0x%lX\n", state->getID(), (unsigned long)pc);
//  } else if (eax == write) {
//    if (m_write.find(state->getID()) == m_write.end()) {
//      m_write.insert(pair<uint64_t, uint64_t>(state->getID(), edx));
//    } else {
//      m_write.at(state->getID()) += edx;
//    }
//
////    if (!freopen(m_fileName.c_str(), "w", m_traceFile)) {
////      getWarningsStream() << "Could not reopen FileIOTracker.result" << '\n';
////    }
//
//
////    getInfoStream(state) << "WRITE system call at PC " << pc << "\n";
////    fprintf(m_traceFile, "State[%d] WRITE system call at PC 0x%lX\n", state->getID(), (unsigned long)pc);
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

  // write file ....

  for (m_itr = m_rw.begin(); m_itr != m_rw.end(); ++m_itr) {
    unsigned long state = m_itr->first, read = m_itr->second.first, write = m_itr->second.second;
    fprintf(m_traceFile, "State[%lu]  read %lu  write %lu\n", state, read, write);
  }
//  for (m_itr = m_write.begin(); m_itr != m_write.end(); ++m_itr) {
//    state = m_itr->first;
//    if (m_read.find(state) == m_read.end()) {
//      fprintf(m_traceFile, "State[%lu]  write %lu\n", state, m_itr->second);
//    }
////    fprintf(m_traceFile, "State[%lu] write %lu \n", (unsigned long)m_itr->first, (unsigned long)m_itr->second);
//  }


  if (!m_traceFile) return;
  fclose (m_traceFile);
  m_traceFile = nullptr;
}

}
}
