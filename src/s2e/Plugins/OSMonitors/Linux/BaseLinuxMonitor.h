///
/// Copyright (C) 2014-2017, Dependable Systems Laboratory, EPFL
/// Copyright (C) 2014-2017, Cyberhaven
/// All rights reserved.
///
/// Licensed under the Cyberhaven Research License Agreement.
///

#ifndef S2E_PLUGINS_BASE_LINUX_MONITOR_H
#define S2E_PLUGINS_BASE_LINUX_MONITOR_H

#include <s2e/Plugin.h>
#include <s2e/S2E.h>
#include <s2e/cpu.h>

#include <s2e/Plugins/Core/BaseInstructions.h>
#include <s2e/Plugins/Core/Vmi.h>
#include <s2e/Plugins/OSMonitors/ModuleDescriptor.h>
#include <s2e/Plugins/OSMonitors/OSMonitor.h>
#include "s2e/Plugins/ConfigurationAnalysis/LatencyTracker.h"
#include "s2e/Plugins/ConfigurationAnalysis/InstructionTracker.h"

#include <map>
#include <sstream>
#include <string.h>
#include<iostream>

extern "C" {
extern CPUX86State *env;
}

using namespace klee;

struct S2E_LINUXMON_COMMAND_MODULE_LOAD;
struct S2E_LINUXMON_COMMAND_PROCESS_LOAD;

namespace s2e {
namespace plugins {

class MemoryMap;

namespace linux_common {

// TODO Get the real stack size from the process memory map
static const uint64_t STACK_SIZE = 16 * 1024 * 1024;

} // namespace linux_common

///
/// \brief Abstract base plugin for X86 Linux monitors, including the Linux and
/// CGC monitors
///
/// This class contains a number of virtual getter methods that return values specific to the kernel in use.
///
class BaseLinuxMonitor : public OSMonitor, public IPluginInvoker {
protected:
    Vmi *m_vmi;

    MemoryMap *m_map;

    /// Start address of the Linux kernel
    uint64_t m_kernelStartAddress;

    /// Offset of the process identifier in the \c task_struct struct (see include/linux/sched.h)
    uint64_t m_taskStructPidOffset;

    /// Terminate if a segment fault occurs
    bool m_terminateOnSegfault;

    uint64_t m_commandVersion;
    uint64_t m_commandSize;

    void loadKernelImage(S2EExecutionState *state, uint64_t kernelStart);

    bool verifyLinuxCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, uint8_t *cmd);

    void handleModuleLoad(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_MODULE_LOAD &modLoad);
    void handleProcessLoad(S2EExecutionState *state, uint64_t pid, const S2E_LINUXMON_COMMAND_PROCESS_LOAD &procLoad);

    template <typename T>
    bool loadSections(S2EExecutionState *state, uint64_t phdr, uint64_t phdr_size,
                      std::vector<SectionDescriptor> &mappedSections) {
        if (phdr_size % sizeof(T)) {
            getWarningsStream(state) << "Invalid phdr_size\n";
            return false;
        }

        auto headers_count = phdr_size / sizeof(T);
        auto headers = std::unique_ptr<T[]>{new T[headers_count]};

        if (!state->mem()->read(phdr, headers.get(), phdr_size)) {
            getWarningsStream(state) << "Could not read headers\n";
            return false;
        }

        for (unsigned i = 0; i < headers_count; ++i) {
            if (headers[i].mmap.address == 0 && headers[i].mmap.size == 0) {
                continue;
            }

            auto sd = SectionDescriptor();
            sd.nativeLoadBase = headers[i].p_vaddr;
            sd.runtimeLoadBase = headers[i].vma + (headers[i].p_vaddr & 0xfff);
            sd.size = headers[i].p_filesz;
            sd.executable = headers[i].mmap.prot & PROT_EXEC;
            sd.readable = headers[i].mmap.prot & PROT_READ;
            sd.writable = headers[i].mmap.prot & PROT_WRITE;
            mappedSections.push_back(sd);
        }

        return true;
    }

public:
    /// Emitted when a segment fault occurs in the kernel
    sigc::signal<void, S2EExecutionState *, uint64_t, /* pid */ uint64_t /* pc */> onSegFault;

    ///
    /// Create a new monitor for the Linux kernel
    ///
    /// \param s2e The global S2E object
    ///
    BaseLinuxMonitor(S2E *s2e) : OSMonitor(s2e) {
    }

    virtual uint64_t getKernelStart() const {
        return m_kernelStartAddress;
    }

    /// Get the base address and size of the stack
    virtual bool getCurrentStack(S2EExecutionState *state, uint64_t *base, uint64_t *size);

    ///
    /// \brief Handle a custom command emitted by the kernel
    ///
    /// This occurs in the following steps:
    ///  - Command is verified
    ///  - The \c onCustomInstruction signal is emitted with \c done set to \c false
    ///  - The command is handled by the specific implementation. Note that the data contained within the command can
    ///    be modified at this point
    ///  - The \c onCustomInstruction signal is emitted with \c done set to \c true
    ///
    virtual void handleOpcodeInvocation(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize) {
        uint8_t cmd[guestDataSize];
        memset(cmd, 0, guestDataSize);

        if (!verifyLinuxCommand(state, guestDataPtr, guestDataSize, cmd)) {
            return;
        }

        handleCommand(state, guestDataPtr, guestDataSize, cmd);
    }

    ///
    /// Handle the given command with the data provided
    ///
    /// \param state The S2E state
    /// \param guestDataPtr Pointer to the raw data emitted by the kernel
    /// \param guestDataSize Size of the raw data emitted by the kernel
    /// \param cmd The custom instruction emitted by the kernel
    ///
    virtual void handleCommand(S2EExecutionState *state, uint64_t guestDataPtr, uint64_t guestDataSize, void *cmd) = 0;

    /// Get the name of the process with the given PID
    virtual bool getProcessName(S2EExecutionState *state, uint64_t pid, std::string &name) {
        return false;
    }

    virtual void handleKernelPanic(S2EExecutionState *state, uint64_t message, uint64_t messageSize) {
        std::string str = "kernel panic";
        state->mem()->readString(message, str, messageSize);
        g_s2e->getExecutor()->terminateState(*state, str);
    }
};

} // namespace plugins
} // namespace s2e

#endif
