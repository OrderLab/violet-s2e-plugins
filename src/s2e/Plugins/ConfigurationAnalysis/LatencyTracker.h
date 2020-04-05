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
    std::string m_symbolicFileName;
    FILE *m_symbolicTraceFile;
    bool is_profileAll;
    bool printTrace;
    bool traceSyscall;
    bool traceInstruction;
    // @deprecated
    uint64_t entryAddress;
    FunctionMonitor* functionMonitor;
    LinuxMonitor* linuxMonitor;
    FunctionMonitor::CallSignal* callSignal;
    char configuration[1024]; // IMPORTANT!! the definition must be consistent with the mysqld

    struct concreteConstraint {
      int id;
      int constraintsIndex;
      int64_t value;
      bool is_target;
    };

    typedef std::pair<std::string, std::vector<unsigned char>> VarValuePair;
    typedef std::vector<VarValuePair> ConcreteInputs;

  public:
    enum enum_track_command {
      TRACK_START,TRACK_END
    };

    LatencyTracker(S2E *s2e) : Plugin(s2e) {
      is_profileAll = false;
      traceSyscall = false;
      traceInstruction = false;

    }

    ~LatencyTracker();
    void initialize();

    void createNewTraceFile(bool append);
    void onTranslateInstruction(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc);
    void onInstructionExecution(S2EExecutionState *state, uint64_t pc);
    int getScore(S2EExecutionState *state);
    int getCount(S2EExecutionState *state);
    int getSyscall(S2EExecutionState *state);
    void setEntryPoint(S2EExecutionState *state, uint64_t entry_point,
        uint64_t load_bias=0);
    void functionCallMonitor(S2EExecutionState* state, FunctionMonitorState* fms);
    void functionRetMonitor(S2EExecutionState *state);
    void functionForEach(S2EExecutionState *state);
    void onSysenter(S2EExecutionState* state, uint64_t pc);
    void onTranslateSpecialInstructionEnd(ExecutionSignal *signal, S2EExecutionState *state,TranslationBlock *tb, uint64_t pc, special_instruction_t type);
    void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize);
    void onException (ExecutionSignal* signal, S2EExecutionState* state, TranslationBlock *tb, uint64_t pc, unsigned exception_idx);
    void onSyscall(S2EExecutionState* state, uint64_t pc, uint32_t sysc_number);
    void getFunctionTracer(S2EExecutionState* state,const ConcreteInputs &inputs);
    void matchParent(S2EExecutionState *state);
    void calculateLatency(S2EExecutionState *state);

    void printCallRecord(S2EExecutionState *state, uint64_t loadBias, CallSignal *record);
    bool writeCallRecord(S2EExecutionState *state, uint64_t loadBias, CallSignal *record);
    void writeTestCaseToTrace(S2EExecutionState *state, const ConcreteInputs &inputs);
    void flush();
};



class LatencyTrackerState : public PluginState {
  private:
    int instructionCount;
    uint64_t loadEntry;
    uint64_t loadBias;
    bool regiesterd;

  public:
    typedef std::map<uint64_t, CallSignal> FunctionCallRecord;
    typedef std::vector<RetSignal> FunctionRetRecord;
    typedef uint64_t ThreadId;

    std::vector<FunctionCallRecord> callLists;
    std::vector<std::vector<RetSignal>> returnLists;
    std::map <ThreadId, FunctionCallRecord> callList;
    std::map <ThreadId, FunctionRetRecord> returnList;
    std::vector<double> latencyList;
    int syscallCount;
    bool traceFunction;
    std::map <ThreadId, uint64_t > IdList;
    uint64_t m_Pid;
    std::vector<uint64_t> threadList;


    LatencyTrackerState() {
      instructionCount = 0;
      syscallCount = 0;
      loadEntry = 0;
      loadBias = 0;
      regiesterd = false;
      traceFunction = false;
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
