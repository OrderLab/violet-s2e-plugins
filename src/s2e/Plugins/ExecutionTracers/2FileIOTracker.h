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

  //std::string m_fileName;
  //FILE *m_file;

  void onTranslateSpecialInstructionEnd(
      ExecutionSignal *signal,
      S2EExecutionState *state,
      TranslationBlock *tb,
      uint64_t pc,
      special_instruction_t type
  );

 public:
  FileIOTracker(S2E *s2e) : Plugin(s2e) {
  }
  ~FileIOTracker();

  void initialize();

  void createNewFile(bool append);

};

class FileIOTrackerState : public PluginState {
 private:
  uint64_t m_read;
  uint64_t m_write;
//  File *m_file;

 public:
  FileIOTrackerState() {
    m_read = 0;
    m_write = 0;
  }

  virtual ~FileIOTrackerState();

  static PluginState *factory(Plugin*, S2EExecutionState*) {
    return new FileIOTrackerState();
  }

  FileIOTrackerState *clone() const {
    return new FileIOTrackerState(*this);
  }

  void inc_read(uint64_t length) {
    m_read += length;
  }

  void inc_write(uint64_t length) {
    m_write += length;
  }

  int get_read() {
    return m_read;
  }

  int get_write() {
    return m_write;
  }
};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_FILEIOTRACKER_H
