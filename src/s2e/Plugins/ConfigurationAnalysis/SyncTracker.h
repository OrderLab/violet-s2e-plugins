#ifndef S2E_PLUGINS_SYNCTRACKE_H
#define S2E_PLUGINS_SYNCTRACKE_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <map>
#include <iterator>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>

using namespace std;

namespace s2e {
namespace plugins {

class SyncTracker : public Plugin {
  S2E_PLUGIN
 private:
  std::string m_fileName;
  FILE *m_traceFile;
  map<uint64_t, pair<uint64_t, uint64_t>> m_rw; // first read, second write
  bool is_trackSize;
  string targetProcessName;
  uint64_t targetProcessPid;
//  bool targetProcessStart;

  vector<uint64_t> readSyscallList;
  vector<uint64_t> writeSyscallList;

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

//  bool in_readSyscallList(uint64_t syscall_number);
//  bool in_writeSyscallList(uint64_t syscall_number);

 public:
  SyncTracker(S2E *s2e) : Plugin(s2e) {
  }
  ~SyncTracker();

  void initialize();

  void createNewTraceFile(bool append);

  void getIOTracer(S2EExecutionState *state);

};


class SyncTrackerState : public PluginState {
 private:
  uint64_t futex_cnt;

 public:
  SyncTrackerState() {
    futex_cnt = 0;
  }

  virtual ~SyncTrackerState() {}

  static PluginState *factory(Plugin*, S2EExecutionState*) {
    return new SyncTrackerState();
  }

  SyncTrackerState *clone() const {
    return new SyncTrackerState(*this);
  }

  void inc_cnt() {
    ++futex_cnt;


};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SYNCTRACKE_H

