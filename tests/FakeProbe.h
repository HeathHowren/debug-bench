#pragma once

#include "core/Probe.h"

namespace dbench::test {

// A SystemProbe whose every reading is a public field. Two presets build a
// "clean" machine and a "debugger present" one, so a test can flip a single
// reading and assert one check without a debugger, admin or a real process.
struct FakeProbe final : SystemProbe {
    // API
    bool isDebuggerPresent_ = false;
    bool checkRemote_ = false;
    std::uint64_t ntDebugPort_ = 0;
    std::uint32_t ntDebugFlags_ = 1; // 1 == not debugged
    std::uint64_t ntDebugObjectHandle_ = 0;
    // PEB
    bool pebBeingDebugged_ = false;
    std::uint32_t ntGlobalFlag_ = 0;
    std::uint32_t heapFlags_ = 0x00000002; // HEAP_GROWABLE only
    std::uint32_t heapForceFlags_ = 0;
    // Exceptions
    bool int3Ran_ = true;
    bool int3LongRan_ = true;
    bool singleStepRan_ = true;
    bool guardPageRan_ = true;
    bool closeHandleRaised_ = false;
    bool odsCleared_ = false;
    // Timing (well under the thresholds)
    std::uint64_t rdtsc_ = 200;
    std::uint64_t rdtscCpuid_ = 500;
    std::uint64_t rdtscp_ = 200;
    std::uint64_t qpc_ = 40;
    std::uint64_t tick_ = 0;
    // Context
    DebugRegisters regs_{};
    bool threadHidden_ = false;
    // Environment
    std::string parent_ = "explorer.exe";
    std::vector<std::string> windows_{};
    std::vector<std::string> processes_{};
    std::vector<std::string> devices_{};
    std::vector<LoadedModule> modules_{{"debug-bench.exe", "c:\\program files\\debug-bench\\debug-bench.exe"}};
    std::vector<std::string> allowed_{"c:\\windows\\", "c:\\program files\\debug-bench\\"};
    bool hypervisorBit_ = false;
    std::string hypervisorVendor_{};
    KernelDebuggerInfo kernel_{false, true};

    static FakeProbe clean() { return FakeProbe{}; }

    static FakeProbe debuggerPresent() {
        FakeProbe p;
        p.isDebuggerPresent_ = true;
        p.checkRemote_ = true;
        p.ntDebugPort_ = 0x2F4;
        p.ntDebugFlags_ = 0; // cleared while debugged
        p.ntDebugObjectHandle_ = 0x9C;
        p.pebBeingDebugged_ = true;
        p.ntGlobalFlag_ = 0x70;
        p.heapFlags_ = 0x40000062; // HEAP_VALIDATE_PARAMETERS_ENABLED and friends
        p.heapForceFlags_ = 0x40000060;
        p.int3Ran_ = false;
        p.int3LongRan_ = false;
        p.singleStepRan_ = false;
        p.guardPageRan_ = false;
        p.closeHandleRaised_ = true;
        p.odsCleared_ = true;
        p.rdtsc_ = 5'000'000;
        p.rdtscCpuid_ = 5'000'000;
        p.rdtscp_ = 5'000'000;
        p.qpc_ = 5'000'000;
        p.tick_ = 500;
        p.regs_ = DebugRegisters{0x401000, 0, 0, 0, 0x00000101};
        p.threadHidden_ = true;
        p.parent_ = "x64dbg.exe";
        p.windows_ = {"x64dbg"};
        p.processes_ = {"x64dbg.exe"};
        p.devices_ = {"\\\\.\\TitanHide"};
        p.modules_ = {{"debug-bench.exe", "c:\\program files\\debug-bench\\debug-bench.exe"},
                      {"hook.dll", "c:\\temp\\hook.dll"}};
        p.hypervisorBit_ = true;
        p.hypervisorVendor_ = "VMwareVMware";
        p.kernel_ = KernelDebuggerInfo{true, false};
        return p;
    }

    bool isDebuggerPresent() const override { return isDebuggerPresent_; }
    bool checkRemoteDebuggerPresent() const override { return checkRemote_; }
    std::uint64_t ntDebugPort() const override { return ntDebugPort_; }
    std::uint32_t ntDebugFlags() const override { return ntDebugFlags_; }
    std::uint64_t ntDebugObjectHandle() const override { return ntDebugObjectHandle_; }

    bool pebBeingDebugged() const override { return pebBeingDebugged_; }
    std::uint32_t pebNtGlobalFlag() const override { return ntGlobalFlag_; }
    std::uint32_t heapFlags() const override { return heapFlags_; }
    std::uint32_t heapForceFlags() const override { return heapForceFlags_; }

    bool int3HandlerRan() const override { return int3Ran_; }
    bool int3LongHandlerRan() const override { return int3LongRan_; }
    bool singleStepHandlerRan() const override { return singleStepRan_; }
    bool guardPageHandlerRan() const override { return guardPageRan_; }
    bool closeHandleRaised() const override { return closeHandleRaised_; }
    bool outputDebugStringClearedError() const override { return odsCleared_; }

    std::uint64_t rdtscDelta() const override { return rdtsc_; }
    std::uint64_t rdtscCpuidDelta() const override { return rdtscCpuid_; }
    std::uint64_t rdtscpDelta() const override { return rdtscp_; }
    std::uint64_t qpcDeltaTicks() const override { return qpc_; }
    std::uint64_t getTickCountDelta() const override { return tick_; }

    DebugRegisters debugRegisters() const override { return regs_; }
    bool threadHiddenFromDebugger() const override { return threadHidden_; }

    std::string parentProcessName() const override { return parent_; }
    std::vector<std::string> debuggerWindowsFound() const override { return windows_; }
    std::vector<std::string> debuggerProcessesFound() const override { return processes_; }
    std::vector<std::string> debuggerDevicesFound() const override { return devices_; }
    std::vector<LoadedModule> loadedModules() const override { return modules_; }
    std::vector<std::string> allowedModuleDirectories() const override { return allowed_; }
    bool hypervisorPresentBit() const override { return hypervisorBit_; }
    std::string hypervisorVendor() const override { return hypervisorVendor_; }
    KernelDebuggerInfo kernelDebugger() const override { return kernel_; }
};

} // namespace dbench::test
