#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace dbench {

// The four debug registers plus the control register, read from a thread's
// CONTEXT. Any non-zero Dr0-Dr3 with a matching enable bit in Dr7 is a
// hardware breakpoint.
struct DebugRegisters {
    std::uint64_t dr0 = 0;
    std::uint64_t dr1 = 0;
    std::uint64_t dr2 = 0;
    std::uint64_t dr3 = 0;
    std::uint64_t dr7 = 0;
};

// The answer from NtQuerySystemInformation(SystemKernelDebuggerInformation).
struct KernelDebuggerInfo {
    bool debuggerEnabled = false;
    bool debuggerNotPresent = true;
};

// One loaded module, as the environment checks see it.
struct LoadedModule {
    std::string name; // file name only, lower-cased
    std::string path; // full path, lower-cased, '/' or '\\' as the OS gave it
};

// Everything a check reads from the operating system goes through this
// interface, so the pure decision logic can be driven by a fake in the tests
// with no debugger, no admin and no real process. LiveProbe is the Windows
// implementation; FakeProbe is the test one.
//
// Each method returns a raw reading, not a verdict. Whether a reading means
// "a debugger is here" is decided by the functions in Checks.h, which is what
// the tests exercise.
class SystemProbe {
public:
    virtual ~SystemProbe() = default;

    // --- API class -------------------------------------------------------
    virtual bool isDebuggerPresent() const = 0;           // kernel32!IsDebuggerPresent
    virtual bool checkRemoteDebuggerPresent() const = 0;  // kernel32!CheckRemoteDebuggerPresent on self
    virtual std::uint64_t ntDebugPort() const = 0;        // NtQIP ProcessDebugPort (0x7)
    virtual std::uint32_t ntDebugFlags() const = 0;       // NtQIP ProcessDebugFlags (0x1F); 0 while debugged
    virtual std::uint64_t ntDebugObjectHandle() const = 0; // NtQIP ProcessDebugObjectHandle (0x1E)

    // --- PEB class -------------------------------------------------------
    virtual bool pebBeingDebugged() const = 0;      // PEB.BeingDebugged byte
    virtual std::uint32_t pebNtGlobalFlag() const = 0; // PEB.NtGlobalFlag
    virtual std::uint32_t heapFlags() const = 0;    // default heap Flags
    virtual std::uint32_t heapForceFlags() const = 0; // default heap ForceFlags

    // --- Exception class -------------------------------------------------
    // For each of these, "handler ran" means our own __except received the
    // exception, i.e. no debugger stepped in front of it.
    virtual bool int3HandlerRan() const = 0;        // one-byte int 3 (0xCC)
    virtual bool int3LongHandlerRan() const = 0;    // two-byte int 3 (0xCD 0x03)
    virtual bool singleStepHandlerRan() const = 0;  // trap flag single-step
    virtual bool guardPageHandlerRan() const = 0;   // PAGE_GUARD violation
    virtual bool closeHandleRaised() const = 0;     // CloseHandle(bad) raises only when debugged
    virtual bool outputDebugStringClearedError() const = 0; // legacy GetLastError trick

    // --- Timing class ----------------------------------------------------
    // Cycle or tick deltas across a tiny fixed workload. Large gaps suggest a
    // debugger is stepping, or a slow virtual time source.
    virtual std::uint64_t rdtscDelta() const = 0;
    virtual std::uint64_t rdtscCpuidDelta() const = 0;
    virtual std::uint64_t rdtscpDelta() const = 0;
    virtual std::uint64_t qpcDeltaTicks() const = 0;
    virtual std::uint64_t getTickCountDelta() const = 0;

    // --- Context class ---------------------------------------------------
    virtual DebugRegisters debugRegisters() const = 0;
    virtual bool threadHiddenFromDebugger() const = 0; // ThreadHideFromDebugger flag reads back set

    // --- Environment class -----------------------------------------------
    virtual std::string parentProcessName() const = 0;              // lower-cased image name
    virtual std::vector<std::string> debuggerWindowsFound() const = 0; // matched window class/title tags
    virtual std::vector<std::string> debuggerProcessesFound() const = 0; // matched running image names
    virtual std::vector<std::string> debuggerDevicesFound() const = 0;   // openable \\.\ device objects
    virtual std::vector<LoadedModule> loadedModules() const = 0;
    // Directory prefixes a module may legitimately load from (the Windows
    // directory and the program's own folder), lower-cased with a trailing
    // separator. The allowlist check compares module paths against these.
    virtual std::vector<std::string> allowedModuleDirectories() const = 0;
    virtual bool hypervisorPresentBit() const = 0;   // CPUID.1:ECX[31]
    virtual std::string hypervisorVendor() const = 0; // CPUID leaf 0x40000000 vendor, or empty
    virtual KernelDebuggerInfo kernelDebugger() const = 0;
};

} // namespace dbench
