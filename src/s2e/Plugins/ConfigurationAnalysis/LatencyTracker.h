//
// Created by yigonghu on 8/23/19.
//

#ifndef S2E_PLUGINS_INSTRTRACKER_H
#define S2E_PLUGINS_INSTRTRACKER_H

// These header files are located in libs2ecore
#include <s2e/Plugin.h>
#include <s2e/CorePlugin.h>
#include <s2e/S2EExecutor.h>
#include <s2e/S2EExecutionState.h>
#include <klee/Expr.h>
#include <s2e/Plugins/ExecutionMonitors/FunctionMonitor.h>
#include <stack>
#include <ctime>
#include <list>
#include <mutex>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include <s2e/Plugins/ExecutionTracers/TestCaseGenerator.h>
#include <s2e/Plugins/OSMonitors/Linux/LinuxMonitor.h>

namespace s2e {
namespace plugins {

typedef struct callRecord {
  uint64_t address; // function starting address
  uint64_t retAddress;
  uint64_t callerAddress;    // caller's starting address
  double execution_time;
  uint64_t acticityId; // unique id for each function call
  uint64_t parentId;
  clock_t begin;
}CallSignal;

typedef struct returnRecord {
  uint64_t returnAddress;
  uint64_t functionEnd;
  clock_t end;
}RetSignal;

class LatencyTracker : public Plugin, public IPluginInvoker {
  S2E_PLUGIN

  private:
    std::string m_fileName;
    FILE *m_traceFile;
    std::string m_inputFileName;
    FILE *m_inputFile;
    std::string m_symbolicFileName;
    FILE *m_symbolicTraceFile;
    std::string m_ioFileName;
    FILE *m_ioTraceFile;
    bool is_profileAll;
    bool printTrace;
    bool traceFileIO;
    bool traceInstruction;
    bool traceFunctionCall;
    bool traceInputCallstack;
    // @deprecated
    uint64_t entryAddress;
    FunctionMonitor* functionMonitor;
    LinuxMonitor* linuxMonitor;
    FunctionMonitor::CallSignal* callSignal;
    char configuration[1024] = "\0"; // IMPORTANT!! the definition must be consistent with the mysqld
    std::string input;

    struct concreteConstraint {
      int id;
      int constraintsIndex;
      int64_t value;
      bool is_target;
    };

    struct ioRecord {
      int id;
      uint64_t read_cnt;
      uint64_t read_bytes;
      uint64_t write_cnt;
      uint64_t write_bytes;
      uint64_t pread_cnt;
      uint64_t pread_bytes;
      uint64_t pwrite_cnt;
      uint64_t pwrite_bytes;
    };

    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

  public:
    enum enum_track_command {
      TRACK_START,TRACK_END,LOG_ADDRESS
    };

    LatencyTracker(S2E *s2e) : Plugin(s2e) {
      is_profileAll = false;
      traceFileIO = false;
      traceInstruction = false;
      traceInputCallstack = false;
    }

    ~LatencyTracker();
    void initialize();

    void createNewTraceFile(bool append);
    void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc);
    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
    int getInstructionNumber(S2EExecutionState *state);
    int getSyscall(S2EExecutionState *state);
    void setEntryPoint(S2EExecutionState *state, uint64_t entry_point,
        uint64_t load_bias=0);
    void functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms);
    void functionRetMonitor(S2EExecutionState *state);
    void functionForEach(S2EExecutionState *state);
    void onSysenter(S2EExecutionState* state, uint64_t pc);
    void onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc, special_instruction_t type);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
    void onSyscall(S2EExecutionState* state, uint64_t pc);
    void getFunctionTracer(S2EExecutionState* state,const ConcreteInputs &inputs);
    void matchParent(S2EExecutionState *state);
    void calculateLatency(S2EExecutionState *state);

    void printCallRecord(S2EExecutionState *state, uint64_t loadBias, CallSignal *record);
    bool writeCallRecord(S2EExecutionState *state, uint64_t loadBias, CallSignal *record, int input);
    void writeTestCaseToTrace(S2EExecutionState *state, const ConcreteInputs &inputs);
    void writeIOToTrace(S2EExecutionState *state);
    void printConstraints(S2EExecutionState *state, uint64_t loadBias);
    void flush();
};



class LatencyTrackerState : public PluginState {
  private:
    int instructionCount;
    uint64_t loadEntry;
    uint64_t loadBias;
    bool regiesterd;
    uint64_t m_read_cnt;
    uint64_t m_read_bytes;
    uint64_t m_write_cnt;
    uint64_t m_write_bytes;
    uint64_t m_pread_cnt;
    uint64_t m_pread_bytes;
    uint64_t m_pwrite_cnt;
    uint64_t m_pwrite_bytes;


 public:
    typedef std::map<uint64_t, CallSignal> FunctionCallRecord;
    typedef std::vector<RetSignal> FunctionRetRecord;
    typedef uint64_t ThreadId;

    std::vector<FunctionCallRecord> callLists;
    std::vector<std::vector<RetSignal>> returnLists;
    std::vector<std::string> inputLists;
    std::map <ThreadId, FunctionCallRecord> callList;
    std::map <ThreadId, FunctionRetRecord> returnList;
    int syscallCount;
    std::map <ThreadId, uint64_t > IdList;
    uint64_t m_Pid;
    std::vector<uint64_t> threadList;
    bool flag = false;


    LatencyTrackerState() {
      instructionCount = 0;
      syscallCount = 0;
      loadEntry = 0;
      loadBias = 0;
      m_read_cnt = 0;
      m_read_bytes = 0;
      m_write_cnt = 0;
      m_write_bytes = 0;
      m_pread_cnt = 0;
      m_pread_bytes = 0;
      m_pwrite_cnt = 0;
      m_pwrite_bytes = 0;
      regiesterd = false;
    }

    LatencyTrackerState(const LatencyTrackerState &trackerState) {
      loadEntry = trackerState.loadEntry;
      loadBias = trackerState.loadBias;
      regiesterd = trackerState.regiesterd;
      callLists = trackerState.callLists;
      returnLists = trackerState.returnLists;
      syscallCount = trackerState.syscallCount;
      m_Pid = trackerState.m_Pid;
      threadList = trackerState.threadList;
      IdList = trackerState.IdList;
      m_read_cnt = trackerState.m_read_cnt;
      m_read_bytes = trackerState.m_read_bytes;
      m_write_bytes = trackerState.m_write_bytes;
      m_write_cnt = trackerState.m_write_cnt;
      m_pread_cnt = trackerState.m_pread_cnt;
      m_pread_bytes = trackerState.m_pread_bytes;
      m_pwrite_cnt = trackerState.m_pwrite_cnt;
      m_pwrite_bytes = trackerState.m_pwrite_bytes;
    }

    virtual ~LatencyTrackerState() {}

    static PluginState *factory(Plugin*, S2EExecutionState*) {
      return new LatencyTrackerState();
    }

    LatencyTrackerState *clone() const {
      return new LatencyTrackerState(*this);
    }

    void incrementInstructionCount() {
      ++instructionCount;
    }

    inline int getInstructionCount() {
      return instructionCount;
    }

    void setEntryPoint(uint64_t entry_point, uint64_t load_bias){
      loadEntry = entry_point;
      loadBias = load_bias;
    }

    inline uint64_t getEntryPoint() {
      return loadEntry;
    }

    inline uint64_t getLoadBias() {
      return loadBias;
    }

    void setRegState(bool state) {
      regiesterd = state;
    }
    bool getRegState() {
      return regiesterd;
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

    uint64_t get_pread_cnt() {
      return m_pread_cnt;
    }

    uint64_t get_pread_bytes() {
      return m_pread_bytes;
    }

    uint64_t get_pwrite_cnt() {
      return m_pwrite_cnt;
    }

    uint64_t get_pwrite_bytes() {
      return m_pwrite_bytes;
    }

    void inc_pread(uint64_t size) {
      ++m_pread_cnt;
      m_pread_bytes += size;
    }

    void inc_pwrite(uint64_t size) {
      ++m_pwrite_cnt;
      m_pwrite_bytes += size;
    }

    void functionStart(uint64_t addr,uint64_t returnAddress, uint64_t threadId) {
        struct callRecord record;
        record.callerAddress = 0;
        record.address = addr;
        record.begin = clock();
        record.execution_time = 0;
        record.retAddress = addr;
        record.acticityId = IdList[threadId];
        IdList[threadId]++;
        callList[threadId][returnAddress] = record;
      }

    void functionEnd(uint64_t functionEnd,uint64_t returnAddress, uint64_t threadId) {
      struct returnRecord record;
      record.returnAddress = returnAddress;
      record.functionEnd = functionEnd;
      record.end = clock();
      returnList[threadId].push_back(record);
      return;
    }
};

} // namespace plugins
} // namespace s2e

#endif

