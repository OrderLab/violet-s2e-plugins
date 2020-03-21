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

using namespace std;

namespace s2e {
namespace plugins {

class FileIOTracker : public Plugin {
  S2E_PLUGIN
 private:

  std::string m_fileName;
  FILE *m_traceFile;

  map<uint64_t, pair<uint64_t, uint64_t>> m_rw; // first read, second write
  map<uint64_t, pair<uint64_t, uint64_t>>::iterator m_itr;
//  map<uint64_t, uint64_t> m_read;
//  map<uint64_t, uint64_t> m_write;
//  map<uint64_t, uint64_t> m_tmp_map;
//  map<uint64_t, uint64_t>::iterator m_itr;
//  map<uint64_t, uint64_t>::iterator m_w_itr;

  void onTranslateSpecialInstructionEnd(
      ExecutionSignal *signal,
      S2EExecutionState *state,
      TranslationBlock *tb,
      uint64_t pc,
      special_instruction_t type
  );

  void onSyscall(S2EExecutionState *state, uint64_t pc);

  void inc_state_read(S2EExecutionState *state, uint64_t length);
  void inc_state_write(S2EExecutionState *state, uint64_t length);

 public:
  FileIOTracker(S2E *s2e) : Plugin(s2e) {
  }
  ~FileIOTracker();

  void initialize();

  void createNewTraceFile(bool append);
//  bool writeTraceRecord(S2EExecutionState *state, uint64_t pc);

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FILEIOTRACKER_H
