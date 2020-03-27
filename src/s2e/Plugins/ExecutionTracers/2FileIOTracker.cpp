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
//#include <TraceEntries.pb.h>
#include "FileIOTracker.h"


namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FileIOTracker, // Plugin class
  "Tracks File IO Instruction", // Plugin description
  "FileIOTracker", // Plugin name
  ); // no dependencies

void FileIOTracker::initialize() {
//  createNewFile(false);
  s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
      sigc::mem_fun(*this, &FileIOTracker::onTranslateSpecialInstructionEnd));
}

void FileIOTracker::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                    TranslationBlock *tb, uint64_t pc,
                                                    special_instruction_t type) {
  DECLARE_PLUGINSTATE(FileIOTrackerState, state);

  if (type != SYSCALL) return;

  uint64_t eax, edx;
  uint64_t read = 0x0, write = 0x1; // 0x0 sys_read, 0x1 sys_write

  // get value from eax register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  ok &= state->regs()->read(CPU_OFFSET(regs[R_EDX]), &edx, sizeof(edx));


  if (!ok) {
    getWarningsStream(state) << "couldn't read from registers\n"; // << "\n";
    return;
  }

  //if (eax >> 1) return; // not read or write

//  ok &= state->mem()->read(state->regs()->getSp()-64*2, &count, sizeof(count));
//  if (!ok) {
//    getWarningsStream(state) << "couldn't read from memory\n"; // << "\n";
//    return;
//  }

  getInfoStream() << "-------------" << (long)eax << "---------" << (long)edx << "\n";


  if (eax == read) {
 //   getInfoStream() << "r " << edx << "\n";
    plgState->inc_read(edx);
  } else if (eax == write) {
 //   getInfoStream() << "w " << edx << "\n";
    plgState->inc_write(edx);
  }

}

//void FileIOTracker::createNewFile(bool append) {
//  if (append) {
//    assert(m_fileName.size() > 0);
//    m_file = fopen(m_fileName.c_str(), "a");
//  } else {
//    m_fileName = s2e()->getOutputFilename("FileIOTracker.result");
//    m_file = fopen(m_fileName.c_str(), "w");
//  }
//  if (!m_file) {
//    getWarningsStream() << "Could not create FileIOTracker.result" << '\n';
//    exit(-1);
//  }
//}


FileIOTracker::~FileIOTracker() {
}

//FileIOTracker::~FileIOTracker() {
//
//  // write file ....
//  unsigned long state;
//  for (m_itr = m_read.begin(); m_itr != m_read.end(); ++m_itr) {
//    state = m_itr->first;
//    if (m_write.find(state) == m_write.end()) {
//      fprintf(m_file, "State[%lu]  read %lu\n", state, m_itr->second);
//    } else {
//      fprintf(m_file, "State[%lu]  read %lu  write %lu\n", state, m_itr->second, m_write.at(state));
//    }
//  }
//  for (m_itr = m_write.begin(); m_itr != m_write.end(); ++m_itr) {
//    state = m_itr->first;
//    if (m_read.find(state) == m_read.end()) {
//      fprintf(m_file, "State[%lu]  write %lu\n", state, m_itr->second);
//    }
//  }
//
//
//  if (!m_file) return;
//  fclose (m_file);
//  m_file = nullptr;
//}

FileIOTrackerState::~FileIOTrackerState() {

//  // write file ....
//  unsigned long state;
//  for (m_itr = m_read.begin(); m_itr != m_read.end(); ++m_itr) {
//    state = m_itr->first;
//    if (m_write.find(state) == m_write.end()) {
//      fprintf(m_file, "State[%lu]  read %lu\n", state, m_itr->second);
//    } else {
//      fprintf(m_file, "State[%lu]  read %lu  write %lu\n", state, m_itr->second, m_write.at(state));
//    }
//  }
//  for (m_itr = m_write.begin(); m_itr != m_write.end(); ++m_itr) {
//    state = m_itr->first;
//    if (m_read.find(state) == m_read.end()) {
//      fprintf(m_file, "State[%lu]  write %lu\n", state, m_itr->second);
//    }
//  }


//  getInfoStream() << "------------" << m_read << "---" << m_write << "--------------\n";
  printf ("-------%lu-----%lu---------\n", m_read, m_write);
//  if (!m_file) return;
//  fclose (m_file);
//  m_file = nullptr;
}

}
}
