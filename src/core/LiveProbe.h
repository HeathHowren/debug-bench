#pragma once

#include "core/Probe.h"

namespace dbench {

// The real Windows implementation of SystemProbe. Every method reads this
// process with a documented anti-debug technique and returns the raw value.
// It is used only by the executable; the tests use FakeProbe instead, so none
// of this Windows code sits between a check's decision logic and its test.
class LiveProbe final : public SystemProbe {
public:
    bool isDebuggerPresent() const override;
    bool checkRemoteDebuggerPresent() const override;
    std::uint64_t ntDebugPort() const override;
    std::uint32_t ntDebugFlags() const override;
    std::uint64_t ntDebugObjectHandle() const override;

    bool pebBeingDebugged() const override;
    std::uint32_t pebNtGlobalFlag() const override;
    std::uint32_t heapFlags() const override;
    std::uint32_t heapForceFlags() const override;

    bool int3HandlerRan() const override;
    bool int3LongHandlerRan() const override;
    bool singleStepHandlerRan() const override;
    bool guardPageHandlerRan() const override;
    bool closeHandleRaised() const override;
    bool outputDebugStringClearedError() const override;

    std::uint64_t rdtscDelta() const override;
    std::uint64_t rdtscCpuidDelta() const override;
    std::uint64_t rdtscpDelta() const override;
    std::uint64_t qpcDeltaTicks() const override;
    std::uint64_t getTickCountDelta() const override;

    DebugRegisters debugRegisters() const override;
    bool threadHiddenFromDebugger() const override;

    std::string parentProcessName() const override;
    std::vector<std::string> debuggerWindowsFound() const override;
    std::vector<std::string> debuggerProcessesFound() const override;
    std::vector<std::string> debuggerDevicesFound() const override;
    std::vector<LoadedModule> loadedModules() const override;
    std::vector<std::string> allowedModuleDirectories() const override;
    bool hypervisorPresentBit() const override;
    std::string hypervisorVendor() const override;
    KernelDebuggerInfo kernelDebugger() const override;
};

} // namespace dbench
