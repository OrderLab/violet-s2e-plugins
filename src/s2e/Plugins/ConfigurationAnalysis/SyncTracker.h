#ifndef S2E_PLUGINS_SYNCTRACKE_H
#define S2E_PLUGINS_SYNCTRACKE_H

#include <s2e/CorePlugin.h>
#include <s2e/Plugin.h>
#include <s2e/S2EExecutionState.h>

#include <map>
#include <iterator>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>

// new added
#include <chrono>
#include <queue>
#include <tuple>

typedef std::chrono::time_point<std::chrono::high_resolution_clock> timestamp_t;
typedef std::chrono::duration<double> duration_t;

using namespace std;

namespace s2e {
namespace plugins {

class SyncTracker : public Plugin {
  S2E_PLUGIN
 private:
  std::string m_fileName;
  FILE *m_traceFile;
//  map<uint64_t, partir<uint64_t, uint64_t>> m_rw; // first read, second write
  string targetProcessName;
  uint64_t targetProcessPid;

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

 public:
  SyncTracker(S2E *s2e) : Plugin(s2e) {
  }
  ~SyncTracker();

  void initialize();

  void createNewTraceFile(bool append);

  void getSyncTracer(S2EExecutionState *state);

};


class SyncTrackerState : public PluginState {
 private:
  uint64_t futex_cnt, futex_wake_cnt, futex_wait_cnt;
  // map, <uaddr (mutex), <total duration (s), time stamp, >>

  // uaddr -> total duration, <vector of timestamp>
  map<uint64_t, tuple<duration_t, queue<timestamp_t>, bool>> futex_words;

 public:
  SyncTrackerState() {
    futex_cnt = 0;
    futex_wait_cnt = 0;
    futex_wake_cnt = 0;
  }

  virtual ~SyncTrackerState() {}

  static PluginState *factory(Plugin*, S2EExecutionState*) {
    return new SyncTrackerState();
  }

  SyncTrackerState *clone() const {
    return new SyncTrackerState(*this);
  }

  void inc_futex_cnt() {
    ++futex_cnt;
  }

  void inc_futex_wait_cnt() {
    ++futex_wait_cnt;
  }

  void inc_futex_wake_cnt() {
    ++futex_wake_cnt;
  }

  uint64_t get_futex_cnt() {
    return futex_cnt;
  }

  uint64_t get_futex_wait_cnt() {
    return futex_wait_cnt;
  }

  uint64_t get_futex_wake_cnt() {
    return futex_wake_cnt;
  }

  bool is_new_futex_word(uint64_t uaddr) {
    return futex_words.find(uaddr) == futex_words.end();
  }

  void add_futex_word(uint64_t uaddr) {
    queue<timestamp_t> q;
    futex_words[uaddr] = tuple<duration_t, queue<timestamp_t>, bool>(duration_t::zero(), q, true);
    // std::chrono::high_resolution_clock::now()
  }

  void update_futex_wait(uint64_t uaddr) {
    get<1>(futex_words[uaddr]).push(std::chrono::high_resolution_clock::now());
  }

  void update_futex_wake(uint64_t uaddr) {
    if (futex_words.find(uaddr) == futex_words.end()) {
      return;
    }
    if (get<2>(futex_words[uaddr])) {
      get<2>(futex_words[uaddr]) = false; // ** ignore the first wake for each futex word
      return;
    }
    get<0>(futex_words[uaddr]) += std::chrono::high_resolution_clock::now() - get<1>(futex_words[uaddr]).front();
    get<1>(futex_words[uaddr]).pop();
  }

  duration_t get_futex_word_duration(uint64_t uaddr) {
    return get<0>(futex_words[uaddr]);
  }

  duration_t get_futex_word_duration_all() {
    duration_t d = duration_t::zero();
    for (auto const& a : futex_words) {
      d += get<0>(a.second);
    }
    return d;
  }

  void print_futex_word_duration_each() {
    for (auto const& a : futex_words) {
      printf("lock %lu, duration %f s\n", a.first, get<0>(a.second).count());
    }
  }

  /*
   *  typedef std::chrono::time_point<std::chrono::high_resolution_clock> TimeStamp;
    std::map<int, TimeStamp> m;
    std::chrono::time_point<std::chrono::high_resolution_clock> t0 = std::chrono::high_resolution_clock::now();
    m.insert( std::pair<int, TimeStamp>(1, std::chrono::high_resolution_clock::now()) );
    sleep (2);;
    std::chrono::time_point<std::chrono::high_resolution_clock> t1 = std::chrono::high_resolution_clock::now();
    m.insert( std::pair<int, TimeStamp>(2, std::chrono::high_resolution_clock::now()) );


    std::chrono::duration<double> fs = m[2] - m[1];
   // std::chrono::duration<double> fs = t1 - t0;
    //std::chrono::milliseconds d = std::chrono::duration_cast<std::chrono::milliseconds>(fs);
    //std::chrono::seconds d = std::chrono::duration_cast<std::chrono::seconds>(fs);
    //d += std::chrono::duration_cast<std::chrono::seconds>(fs);
    std::cout << fs.count() << "s\n";
    //std::cout << d.count() << "s\n";
   */

};

} // namespace plugins
} // namespace s2e

#endif // S2E_PLUGINS_SYNCTRACKE_H

