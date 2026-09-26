#pragma once

#include "core/Check.h"
#include "core/Probe.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace dbench {

// One check: its identity, its documentation, and the function that reads the
// system and decides. The catalog holds one of these per check.
struct Check {
    std::string id;
    std::string name;
    CheckClass cls;
    std::string explanation; // what it detects; false positives; how it is neutralized
    Outcome (*run)(const SystemProbe&);
};

// Every check, in table order (grouped by class). This is the whole catalog.
[[nodiscard]] std::vector<Check> catalog();

// Run one check against a probe and fold in its metadata.
[[nodiscard]] CheckResult runCheck(const Check& check, const SystemProbe& probe);

// Run the catalog. If onlyClass is set, only checks of that class run.
[[nodiscard]] std::vector<CheckResult> runAll(const SystemProbe& probe, std::optional<CheckClass> onlyClass = std::nullopt);

// Timing thresholds, in the units the matching probe method returns. These are
// deliberately generous: a debugger that is only attached, not stepping, will
// not cross them, and neither should an idle but healthy machine. They exist so
// a debugger that single-steps the workload, or a slow virtual time source,
// shows up. See the per-check explanations for why timing is the soft class.
namespace threshold {
inline constexpr std::uint64_t kRdtsc = 0x40000;      // 262144 reference cycles
inline constexpr std::uint64_t kRdtscCpuid = 0x80000; // cpuid serializes and can vm-exit
inline constexpr std::uint64_t kRdtscp = 0x40000;
inline constexpr std::uint64_t kQpcTicks = 20000;
inline constexpr std::uint64_t kTickCountMs = 25;
} // namespace threshold

// The pure decisions. Each takes a raw reading and returns whether that reading
// counts as "a debugger is present". These are what the unit tests drive with
// fabricated readings; the check functions call them after reading the probe.
namespace decide {

// A boolean flag that is true when a debugger is present (BeingDebugged,
// IsDebuggerPresent, CheckRemoteDebuggerPresent, hypervisor bit, ...).
[[nodiscard]] bool flagIsSet(bool reading);

// A handle or port that is non-zero when a debugger is attached
// (ProcessDebugPort, ProcessDebugObjectHandle).
[[nodiscard]] bool valueIsNonZero(std::uint64_t reading);

// ProcessDebugFlags is the inverse: the kernel clears it to 0 while a debugger
// is attached, so 0 is the detection.
[[nodiscard]] bool debugFlagsCleared(std::uint32_t flags);

// NtGlobalFlag carries the three heap-debug bits (0x70) when the process was
// created under a debugger.
[[nodiscard]] bool ntGlobalFlagHasDebugBits(std::uint32_t ntGlobalFlag);

// A debugger-created heap has validation bits beyond HEAP_GROWABLE set in
// Flags.
[[nodiscard]] bool heapFlagsSuspicious(std::uint32_t flags);

// ForceFlags is 0 on a normal heap and non-zero on a debug heap.
[[nodiscard]] bool heapForceFlagsSet(std::uint32_t forceFlags);

// For an exception a debugger swallows first (int 3, single-step, guard page):
// detection is that our own handler did NOT run.
[[nodiscard]] bool handlerWasSwallowed(bool handlerRan);

// For an exception that is only raised when a debugger is attached
// (CloseHandle on a bogus handle): detection is that it WAS raised.
[[nodiscard]] bool exceptionOnlyUnderDebugger(bool raised);

// The legacy OutputDebugString trick: a sentinel last-error value that a
// debugger clears.
[[nodiscard]] bool lastErrorWasCleared(bool cleared);

// A timing delta over its threshold.
[[nodiscard]] bool deltaOverThreshold(std::uint64_t delta, std::uint64_t limit);

// Any hardware breakpoint set: a non-zero address register with its enable bit
// in Dr7, or simply any non-zero debug register.
[[nodiscard]] bool anyHardwareBreakpoint(const DebugRegisters& regs);

// A name that appears in a list, case-insensitively (parent process against
// the known-debugger list).
[[nodiscard]] bool nameInList(const std::string& name, const std::vector<std::string>& list);

// A found-list that is not empty (windows, processes, devices).
[[nodiscard]] bool anyFound(const std::vector<std::string>& found);

// A CPUID hypervisor vendor string that names a known VM.
[[nodiscard]] bool vendorIsKnownVm(const std::string& vendor);

// A kernel debugger that is enabled and reported present.
[[nodiscard]] bool kernelDebuggerActive(const KernelDebuggerInfo& info);

// Modules whose path is under none of the allowed directory prefixes. The
// result is the offending module names; an empty result means everything is
// accounted for. Comparison is case-insensitive.
[[nodiscard]] std::vector<std::string> modulesOutsideAllowlist(const std::vector<LoadedModule>& modules,
                                                               const std::vector<std::string>& allowedPrefixes);

} // namespace decide

// The lists the environment checks compare against, exposed so LiveProbe and
// the tests agree on them.
[[nodiscard]] const std::vector<std::string>& knownDebuggerProcessNames();

} // namespace dbench
