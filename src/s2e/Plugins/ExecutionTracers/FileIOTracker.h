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

  void onException(S2EExecutionState *state, unsigned exception_idx, uint64_t pc);

  void onTrap(S2EExecutionState *state, uint64_t pid, uint64_t pc, int trapnr);

  void onSegFault(S2EExecutionState *state, uint64_t pid, uint64_t pc);

  void onProcessLoad(S2EExecutionState *state, uint64_t cr3, uint64_t pid, const std::string &filename);

  void onProcessUnload(S2EExecutionState *state, uint64_t cr3, uint64_t pid, uint64_t ReturnCode);

//  void inc_state_read(S2EExecutionState *state, uint64_t length);
//
//  void inc_state_write(S2EExecutionState *state, uint64_t length);

  void updateMap(S2EExecutionState *state, uint64_t r_w);

//  bool write(S2EExecutionState *state, uint64_t loadBias, struct callRecord *record);

 public:
  FileIOTracker(S2E *s2e) : Plugin(s2e) {
  }
  ~FileIOTracker();

  void initialize();

  void createNewTraceFile(bool append);

};


class FileIOTrackerState : public PluginState {
 private:
  uint64_t m_read_cnt;
  uint64_t m_read_bytes;
  uint64_t m_write_cnt;
  uint64_t m_write_bytes;

 public:
  FileIOTrackerState() {
    m_read_cnt = 0;
    m_read_bytes = 0;
    m_write_cnt = 0;
    m_write_bytes = 0;
  }

  virtual ~FileIOTrackerState() {}

  static PluginState *factory(Plugin*, S2EExecutionState*) {
    return new FileIOTrackerState();
  }

  FileIOTrackerState *clone() const {
    return new FileIOTrackerState(*this);
  }

  void inc_read(uint64_t size) {
    ++m_read_cnt;
    m_read_bytes += size;
  }

  void inc_write(uint64_t size) {
    ++m_write_cnt;
    m_write_bytes += size;
  }

  uint64_t get_read_cnt() {
    return m_read_cnt;
  }

  uint64_t get_read_bytes() {
    return m_read_bytes;
  }

  uint64_t get_write_cnt() {
    return m_write_cnt;
  }

  uint64_t get_write_bytes() {
    return m_write_bytes;
  }

};


} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FILEIOTRACKER_H
