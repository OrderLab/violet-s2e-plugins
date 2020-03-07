///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_FILEIOTRACER_H
#define S2E_PLUGINS_FILEIOTRACER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include "ExecutionTracer.h"

namespace s2e {
namespace plugins {

class FileIOTracer : public Plugin {
  S2E_PLUGIN
 private:

  std::string m_fileName;
  FILE *m_traceFile;

  void onTranslateSpecialInstructionEnd(
      ExecutionSignal *signal,
      S2EExecutionState *state,
      TranslationBlock *tb,
      uint64_t pc,
      special_instruction_t type
  );

 public:
  FileIOTracer(S2E *s2e) : Plugin(s2e) {
  }
  ~FileIOTracer();

  void initialize();

  void createNewTraceFile(bool append);
//  bool writeTraceRecord(S2EExecutionState *state, uint64_t pc);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FILEIOTRACER_H
