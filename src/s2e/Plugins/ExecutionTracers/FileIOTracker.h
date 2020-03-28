///
/// Copyright (C) 2014, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2019, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_FILEIOTRACKER_H
#define S2E_PLUGINS_FILEIOTRACKER_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>
#include "ExecutionTracer.h"

#include <map>
#include <iterator>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>

using namespace std;

namespace s2e {
namespace plugins {

class FileIOTracker : public Plugin {
  S2E_PLUGIN
 private:
  std::string m_fileName;
  FILE *m_traceFile;
  map<uint64_t, pair<uint64_t, uint64_t>> m_rw; // first read, second write
  bool is_trackSize;
  string targetProcessName;
  uint64_t targetProcessPid;
//  bool targetProcessStart;

  LinuxMonitor *linuxMonitor;


  void onTranslateSpecialInstructionEnd(
      ExecutionSignal *signal,
      S2EExecutionState *state,
      TranslationBlock *tb,
      uint64_t pc,
      special_instruction_t type
  );

  void onSyscall(S2EExecutionState *state, uint64_t pc);


 //(void, )
  void onProcessLoad(S2EExecutionState *state, uint64_t cr3, uint64_t pid, const std::string &filename);

  void onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t ReturnCode);

  void inc_state_read(S2EExecutionState *state, uint64_t length);

  void inc_state_write(S2EExecutionState *state, uint64_t length);

 public:
  FileIOTracker(S2E *s2e) : Plugin(s2e) {
  }
  ~FileIOTracker();

  void initialize();

  void createNewTraceFile(bool append);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FILEIOTRACKER_H
