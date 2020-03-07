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
#include "FileIOTracer.h"

namespace s2e {
namespace plugins {

S2E_DEFINE_PLUGIN(FileIOTracer, // Plugin class
    "Traces File IO Instruction", // Plugin description
    "FileIOTracer", // Plugin name
    ); // no dependencies

void FileIOTracer::initialize() {
  createNewTraceFile(false);
  s2e()->getCorePlugin()->onTranslateSpecialInstructionEnd.connect(
      sigc::mem_fun(*this, &FileIOTracer::onTranslateSpecialInstructionEnd));
}

void FileIOTracer::onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,
                                                    TranslationBlock *tb, uint64_t pc,
                                                    special_instruction_t type) {
  if (type != SYSCALL) return;

  uint64_t eax, read = 0x0, write = 0x1; // 0x0 sys_read, 0x1 sys_write
  // get value from eax register
  bool ok = state->regs()->read(CPU_OFFSET(regs[R_EAX]), &eax, sizeof(eax));
  if (!ok) {
    getWarningsStream(state) << "couldn't read from EAX register at PC " << pc << "\n";
    return;
  }


  if (eax == read) {
//    getInfoStream(state) << "READ  system call at PC " << pc << "\n";
    fprintf(m_traceFile, "State[%d] READ  system call at PC 0x%lX\n", state->getID(), (unsigned long)pc);
  } else if (eax == write) {
//    getInfoStream(state) << "WRITE system call at PC " << pc << "\n";
    fprintf(m_traceFile, "State[%d] WRITE system call at PC 0x%lX\n", state->getID(), (unsigned long)pc);
  }
}

void FileIOTracer::createNewTraceFile(bool append) {
  if (append) {
    assert(m_fileName.size() > 0);
    m_traceFile = fopen(m_fileName.c_str(), "a");
  } else {
    m_fileName = s2e()->getOutputFilename("FileIOTracer.result");
    m_traceFile = fopen(m_fileName.c_str(), "w");
  }
  if (!m_traceFile) {
    getWarningsStream() << "Could not create FileIOTracer.result" << '\n';
    exit(-1);
  }
}


FileIOTracer::~FileIOTracer() {
  if (!m_traceFile) return;
  fclose (m_traceFile);
  m_traceFile = nullptr;
}

}
}
