#include "core/Checks.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>

namespace dbench {

namespace {

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string hex(std::uint64_t value, int width = 0) {
    char buffer[32];
    if (width > 0) {
        std::snprintf(buffer, sizeof(buffer), "0x%0*llX", width, static_cast<unsigned long long>(value));
    } else {
        std::snprintf(buffer, sizeof(buffer), "0x%llX", static_cast<unsigned long long>(value));
    }
    return buffer;
}

std::string joinNames(const std::vector<std::string>& names) {
    std::string out;
    for (const auto& n : names) {
        if (!out.empty()) {
            out += ", ";
        }
        out += n;
    }
    return out;
}

// HEAP_GROWABLE is the only flag a normal user-mode heap carries.
constexpr std::uint32_t kHeapGrowable = 0x00000002;
// The three heap-debug bits the loader sets in NtGlobalFlag under a debugger.
constexpr std::uint32_t kNtGlobalFlagDebugBits = 0x00000070; // TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS

} // namespace

// ---------------------------------------------------------------------------
// Pure decisions
// ---------------------------------------------------------------------------

bool decide::flagIsSet(bool reading) { return reading; }

bool decide::valueIsNonZero(std::uint64_t reading) { return reading != 0; }

bool decide::debugFlagsCleared(std::uint32_t flags) { return flags == 0; }

bool decide::ntGlobalFlagHasDebugBits(std::uint32_t ntGlobalFlag) { return (ntGlobalFlag & kNtGlobalFlagDebugBits) != 0; }

bool decide::heapFlagsSuspicious(std::uint32_t flags) { return (flags & ~kHeapGrowable) != 0; }

bool decide::heapForceFlagsSet(std::uint32_t forceFlags) { return forceFlags != 0; }

bool decide::handlerWasSwallowed(bool handlerRan) { return !handlerRan; }

bool decide::exceptionOnlyUnderDebugger(bool raised) { return raised; }

bool decide::lastErrorWasCleared(bool cleared) { return cleared; }

bool decide::deltaOverThreshold(std::uint64_t delta, std::uint64_t limit) { return delta > limit; }

bool decide::anyHardwareBreakpoint(const DebugRegisters& regs) {
    return regs.dr0 != 0 || regs.dr1 != 0 || regs.dr2 != 0 || regs.dr3 != 0 || regs.dr7 != 0;
}

bool decide::nameInList(const std::string& name, const std::vector<std::string>& list) {
    const std::string lowered = toLower(name);
    return std::any_of(list.begin(), list.end(), [&](const std::string& item) { return toLower(item) == lowered; });
}

bool decide::anyFound(const std::vector<std::string>& found) { return !found.empty(); }

bool decide::vendorIsKnownVm(const std::string& vendor) {
    static const std::array<const char*, 9> tokens = {"vmware", "kvm", "microsoft hv", "vbox", "xen", "prl", "qemu", "bhyve", "tcg"};
    const std::string lowered = toLower(vendor);
    return std::any_of(tokens.begin(), tokens.end(), [&](const char* t) { return lowered.find(t) != std::string::npos; });
}

bool decide::kernelDebuggerActive(const KernelDebuggerInfo& info) { return info.debuggerEnabled && !info.debuggerNotPresent; }

std::vector<std::string> decide::modulesOutsideAllowlist(const std::vector<LoadedModule>& modules,
                                                         const std::vector<std::string>& allowedPrefixes) {
    std::vector<std::string> offenders;
    std::vector<std::string> loweredPrefixes;
    loweredPrefixes.reserve(allowedPrefixes.size());
    for (const auto& p : allowedPrefixes) {
        loweredPrefixes.push_back(toLower(p));
    }
    for (const auto& module : modules) {
        const std::string path = toLower(module.path);
        const bool allowed = std::any_of(loweredPrefixes.begin(), loweredPrefixes.end(),
                                         [&](const std::string& prefix) { return !prefix.empty() && path.rfind(prefix, 0) == 0; });
        if (!allowed) {
            offenders.push_back(module.name);
        }
    }
    return offenders;
}

// ---------------------------------------------------------------------------
// Class names and parsing
// ---------------------------------------------------------------------------

std::string_view className(CheckClass cls) {
    switch (cls) {
    case CheckClass::Api:
        return "api";
    case CheckClass::Peb:
        return "peb";
    case CheckClass::Exception:
        return "exception";
    case CheckClass::Timing:
        return "timing";
    case CheckClass::Context:
        return "context";
    case CheckClass::Environment:
        return "environment";
    }
    return "api";
}

bool parseClass(std::string_view name, CheckClass& out) {
    for (CheckClass cls : allClasses()) {
        if (className(cls) == name) {
            out = cls;
            return true;
        }
    }
    return false;
}

const std::vector<CheckClass>& allClasses() {
    static const std::vector<CheckClass> classes = {CheckClass::Api,     CheckClass::Peb,     CheckClass::Exception,
                                                    CheckClass::Timing,  CheckClass::Context, CheckClass::Environment};
    return classes;
}

const std::vector<std::string>& knownDebuggerProcessNames() {
    static const std::vector<std::string> names = {
        "x64dbg.exe",   "x32dbg.exe",  "ollydbg.exe",           "windbg.exe",  "windbgx.exe", "cdb.exe",
        "ntsd.exe",     "kd.exe",      "ida.exe",               "ida64.exe",   "idaq.exe",    "idaq64.exe",
        "devenv.exe",   "dbgview.exe", "immunitydebugger.exe",  "procmon.exe", "procmon64.exe"};
    return names;
}

// ---------------------------------------------------------------------------
// The checks. One self-contained function each, called through the catalog.
// The explanation string next to each entry is the authoritative per-check
// documentation; these doc comments restate it for a reader of the source.
// ---------------------------------------------------------------------------

namespace {

// Detects: the kernel32 IsDebuggerPresent flag, which is PEB.BeingDebugged.
// False positives: none in practice. Neutralized: a debugger-hiding plugin
// clears the PEB byte, so the API returns false.
Outcome checkIsDebuggerPresent(const SystemProbe& p) {
    const bool value = p.isDebuggerPresent();
    return {decide::flagIsSet(value), std::string("IsDebuggerPresent() = ") + (value ? "TRUE" : "FALSE")};
}

// Detects: a user-mode debugger via CheckRemoteDebuggerPresent on our own
// handle, which reads the debug port. False positives: none. Neutralized: the
// same debug-port value the flags check below is fed, faked to zero.
Outcome checkRemoteDebugger(const SystemProbe& p) {
    const bool value = p.checkRemoteDebuggerPresent();
    return {decide::flagIsSet(value), std::string("CheckRemoteDebuggerPresent() = ") + (value ? "TRUE" : "FALSE")};
}

// Detects: a non-zero ProcessDebugPort from NtQueryInformationProcess (0x7),
// set while a user-mode debugger is attached. False positives: none.
// Neutralized: the query is hooked to return zero.
Outcome checkDebugPort(const SystemProbe& p) {
    const std::uint64_t value = p.ntDebugPort();
    return {decide::valueIsNonZero(value), "ProcessDebugPort = " + hex(value)};
}

// Detects: ProcessDebugFlags (0x1F) cleared to 0, which the kernel does when a
// debugger attaches (the flag is the inverse of NoDebugInherit). It stays 0
// after the debugger detaches, so it also shows a debugger that has come and
// gone. False positives: none. Neutralized: the query is hooked to return 1.
Outcome checkDebugFlags(const SystemProbe& p) {
    const std::uint32_t value = p.ntDebugFlags();
    return {decide::debugFlagsCleared(value), "ProcessDebugFlags = " + hex(value) + (value == 0 ? " (cleared)" : "")};
}

// Detects: a non-zero ProcessDebugObjectHandle (0x1E), the debug object the
// kernel creates for the debuggee. False positives: none. Neutralized: the
// query is hooked to return a null handle.
Outcome checkDebugObject(const SystemProbe& p) {
    const std::uint64_t value = p.ntDebugObjectHandle();
    return {decide::valueIsNonZero(value), "ProcessDebugObjectHandle = " + hex(value)};
}

// Detects: PEB.BeingDebugged read straight from memory rather than through the
// API. False positives: none. Neutralized: the byte is zeroed, which also
// defeats IsDebuggerPresent.
Outcome checkPebBeingDebugged(const SystemProbe& p) {
    const bool value = p.pebBeingDebugged();
    return {decide::flagIsSet(value), std::string("PEB.BeingDebugged = ") + (value ? "1" : "0")};
}

// Detects: the three heap-debug bits (0x70) the loader writes into
// PEB.NtGlobalFlag when a process is started under a debugger. False
// positives: gflags or Application Verifier set the same bits with no
// debugger. Neutralized: the bits are cleared in the PEB after start-up.
Outcome checkNtGlobalFlag(const SystemProbe& p) {
    const std::uint32_t value = p.pebNtGlobalFlag();
    return {decide::ntGlobalFlagHasDebugBits(value), "NtGlobalFlag = " + hex(value, 8)};
}

// Detects: validation bits beyond HEAP_GROWABLE in the default heap's Flags,
// left by the debug heap. False positives: the same gflags/Verifier settings.
// Neutralized: the flags are reset, or the process opts out of the debug heap.
Outcome checkHeapFlags(const SystemProbe& p) {
    const std::uint32_t value = p.heapFlags();
    return {decide::heapFlagsSuspicious(value), "Heap Flags = " + hex(value, 8)};
}

// Detects: a non-zero ForceFlags on the default heap, which is 0 on a normal
// heap and set on a debug heap. False positives: gflags/Verifier. Neutralized:
// ForceFlags is reset to 0.
Outcome checkHeapForceFlags(const SystemProbe& p) {
    const std::uint32_t value = p.heapForceFlags();
    return {decide::heapForceFlagsSet(value), "Heap ForceFlags = " + hex(value, 8)};
}

// Detects: a debugger that swallows a one-byte int 3 (0xCC) before our own
// __except sees the breakpoint. False positives: none. Neutralized: the
// debugger is told to pass the breakpoint back to the process, or its
// first-chance handling is patched.
Outcome checkInt3(const SystemProbe& p) {
    const bool ran = p.int3HandlerRan();
    return {decide::handlerWasSwallowed(ran), ran ? "our __except caught the breakpoint" : "breakpoint swallowed before our handler"};
}

// Detects: the two-byte int 3 (0xCD 0x03). Some debuggers advance the
// instruction pointer by one byte on a breakpoint and mishandle this form.
// False positives: none. Neutralized: correct instruction-length handling in
// the debugger.
Outcome checkInt3Long(const SystemProbe& p) {
    const bool ran = p.int3LongHandlerRan();
    return {decide::handlerWasSwallowed(ran), ran ? "our __except caught the long breakpoint" : "long breakpoint swallowed"};
}

// Detects: a debugger that consumes the single-step exception raised by the
// trap flag before our handler runs. False positives: none. Neutralized: the
// debugger passes single-step exceptions through.
Outcome checkSingleStep(const SystemProbe& p) {
    const bool ran = p.singleStepHandlerRan();
    return {decide::handlerWasSwallowed(ran), ran ? "our __except caught the single-step" : "single-step swallowed"};
}

// Detects: a debugger that eats a PAGE_GUARD violation. False positives: this
// is the soft one of the exception checks; some legitimate runtime tooling
// also intercepts guard-page faults. Neutralized: the debugger passes the
// guard-page exception through.
Outcome checkGuardPage(const SystemProbe& p) {
    const bool ran = p.guardPageHandlerRan();
    return {decide::handlerWasSwallowed(ran), ran ? "our __except caught the guard-page fault" : "guard-page fault swallowed"};
}

// Detects: CloseHandle on a bogus handle, which raises STATUS_INVALID_HANDLE
// only when a debugger is attached. False positives: none. Neutralized: the
// debugger's invalid-handle raising is turned off (it is off by default in
// some debuggers).
Outcome checkCloseHandle(const SystemProbe& p) {
    const bool raised = p.closeHandleRaised();
    return {decide::exceptionOnlyUnderDebugger(raised), raised ? "CloseHandle(bad) raised an exception" : "CloseHandle(bad) returned quietly"};
}

// Detects: the legacy trick where OutputDebugString clears a sentinel
// last-error value when a debugger is listening. False positives: unreliable
// on modern Windows, where it usually fires neither way. Neutralized: it is
// mostly obsolete already. Kept for completeness and documented as weak.
Outcome checkOutputDebugString(const SystemProbe& p) {
    const bool cleared = p.outputDebugStringClearedError();
    return {decide::lastErrorWasCleared(cleared), cleared ? "last error was cleared by OutputDebugString" : "last error preserved"};
}

// Detects: a large RDTSC gap across a tiny workload, left by stepping or a slow
// virtual time source. False positives: this is the soft class; a scheduler
// preemption, a busy machine or a VM can trip it with no debugger. Neutralized:
// the debugger patches RDTSC, or a plugin normalises the counter.
Outcome checkRdtsc(const SystemProbe& p) {
    const std::uint64_t delta = p.rdtscDelta();
    return {decide::deltaOverThreshold(delta, threshold::kRdtsc), "RDTSC delta = " + std::to_string(delta) + " cycles"};
}

// Detects: an RDTSC gap around a CPUID, which serializes and vm-exits under a
// hypervisor. False positives: as timing.rdtsc, plus a hypervisor with no
// debugger. Neutralized: RDTSC is patched, or CPUID is handled without a heavy
// exit.
Outcome checkRdtscCpuid(const SystemProbe& p) {
    const std::uint64_t delta = p.rdtscCpuidDelta();
    return {decide::deltaOverThreshold(delta, threshold::kRdtscCpuid), "RDTSC-around-CPUID delta = " + std::to_string(delta) + " cycles"};
}

// Detects: an RDTSCP gap, the serializing variant of RDTSC. False positives:
// as timing.rdtsc. Neutralized: RDTSCP is patched alongside RDTSC.
Outcome checkRdtscp(const SystemProbe& p) {
    const std::uint64_t delta = p.rdtscpDelta();
    return {decide::deltaOverThreshold(delta, threshold::kRdtscp), "RDTSCP delta = " + std::to_string(delta) + " cycles"};
}

// Detects: a QueryPerformanceCounter gap across the same workload. False
// positives: as timing.rdtsc. Neutralized: the performance counter is slewed by
// a plugin.
Outcome checkQpc(const SystemProbe& p) {
    const std::uint64_t delta = p.qpcDeltaTicks();
    return {decide::deltaOverThreshold(delta, threshold::kQpcTicks), "QPC delta = " + std::to_string(delta) + " ticks"};
}

// Detects: a GetTickCount64 gap, the coarse wall-clock version of the same
// idea. False positives: as timing.rdtsc, and coarser still. Neutralized: the
// tick source is slewed.
Outcome checkGetTickCount(const SystemProbe& p) {
    const std::uint64_t delta = p.getTickCountDelta();
    return {decide::deltaOverThreshold(delta, threshold::kTickCountMs), "GetTickCount64 delta = " + std::to_string(delta) + " ms"};
}

// Detects: a hardware breakpoint in the thread CONTEXT (Dr0-Dr3 with Dr7
// enables). False positives: a profiler or hardware watchpoint set by other
// tooling. Neutralized: the debug registers are cleared in the CONTEXT the
// query returns, or the thread is hidden so the CONTEXT is not read.
Outcome checkHardwareBreakpoints(const SystemProbe& p) {
    const DebugRegisters regs = p.debugRegisters();
    const bool detected = decide::anyHardwareBreakpoint(regs);
    std::string detail = "Dr0=" + hex(regs.dr0) + " Dr1=" + hex(regs.dr1) + " Dr2=" + hex(regs.dr2) + " Dr3=" + hex(regs.dr3) +
                         " Dr7=" + hex(regs.dr7);
    return {detected, std::move(detail)};
}

// Detects: whether this thread's ThreadHideFromDebugger flag reads back set. A
// thread usually hides itself to blind a debugger, so a set flag here means
// something did. False positives: rare; some protectors set it themselves.
// Neutralized: the flag is not the detection so much as the technique; a
// debugger that intercepts NtSetInformationThread never lets it take.
Outcome checkThreadHide(const SystemProbe& p) {
    const bool hidden = p.threadHiddenFromDebugger();
    return {decide::flagIsSet(hidden), std::string("ThreadHideFromDebugger = ") + (hidden ? "set" : "clear")};
}

// Detects: a parent process whose image name is a known debugger. False
// positives: launching the program from Visual Studio (devenv.exe) fires it
// with no debugger attached to this process. Neutralized: the debugger launches
// the target through an intermediate process so the parent is innocent.
Outcome checkParentProcess(const SystemProbe& p) {
    const std::string parent = p.parentProcessName();
    const bool detected = decide::nameInList(parent, knownDebuggerProcessNames());
    return {detected, "parent = " + (parent.empty() ? std::string("<unknown>") : parent)};
}

// Detects: top-level windows whose class or title matches a known debugger.
// False positives: an unrelated window that happens to match a title tag.
// Neutralized: the debugger renames its window, or runs without a GUI.
Outcome checkDebuggerWindows(const SystemProbe& p) {
    const std::vector<std::string> found = p.debuggerWindowsFound();
    const bool detected = decide::anyFound(found);
    return {detected, found.empty() ? "no debugger windows" : "windows: " + joinNames(found)};
}

// Detects: a running process whose image name is a known debugger, anywhere on
// the machine. False positives: the tool being merely installed and open, not
// attached to this process. Neutralized: the debugger process is renamed.
Outcome checkDebuggerProcesses(const SystemProbe& p) {
    const std::vector<std::string> found = p.debuggerProcessesFound();
    const bool detected = decide::anyFound(found);
    return {detected, found.empty() ? "no debugger processes" : "processes: " + joinNames(found)};
}

// Detects: openable \\.\ device objects published by kernel debuggers and
// anti-anti-debug drivers (for example a TitanHide device). False positives:
// an unrelated driver using a clashing name. Neutralized: the driver hides its
// device object or is not loaded.
Outcome checkDebuggerDevices(const SystemProbe& p) {
    const std::vector<std::string> found = p.debuggerDevicesFound();
    const bool detected = decide::anyFound(found);
    return {detected, found.empty() ? "no debugger devices" : "devices: " + joinNames(found)};
}

// Detects: loaded modules whose file is not under an allowed directory (the
// system directories, WinSxS and the program's own folder). False positives:
// this is broad by nature: antivirus, overlays, input-method editors and RGB
// utilities all inject legitimately. Neutralized: an injector loads from an
// allowed directory, or maps its code without a backing file.
Outcome checkModuleAllowlist(const SystemProbe& p) {
    const std::vector<LoadedModule> modules = p.loadedModules();
    // The allowlist prefixes come from the probe: LiveProbe supplies the
    // Windows directory and the program's own folder, the fake supplies
    // whatever the test needs.
    const std::vector<std::string> offenders = decide::modulesOutsideAllowlist(modules, p.allowedModuleDirectories());
    std::vector<std::string> shown(offenders.begin(), offenders.begin() + std::min<std::size_t>(offenders.size(), 3));
    std::string detail;
    if (offenders.empty()) {
        detail = "all " + std::to_string(modules.size()) + " modules under allowed paths";
    } else {
        detail = std::to_string(offenders.size()) + " outside allowlist: " + joinNames(shown);
        if (offenders.size() > shown.size()) {
            detail += ", ...";
        }
    }
    return {!offenders.empty(), std::move(detail)};
}

// Detects: the hypervisor-present bit, CPUID.1:ECX[31]. False positives: this
// is a VM/sandbox signal, not a debugger. A developer VM sets it, and so does a
// physical PC running Windows virtualization-based security, WSL 2 or Docker,
// because Windows itself then runs on Hyper-V. Neutralized: the hypervisor
// masks the bit.
Outcome checkHypervisorBit(const SystemProbe& p) {
    const bool bit = p.hypervisorPresentBit();
    return {decide::flagIsSet(bit), std::string("CPUID.1:ECX[31] = ") + (bit ? "1" : "0")};
}

// Detects: a known VM vendor string in CPUID leaf 0x40000000. False positives:
// as env.hypervisorbit; naming the hypervisor does not mean a debugger is
// present. Neutralized: the vendor leaf is spoofed or cleared.
Outcome checkHypervisorVendor(const SystemProbe& p) {
    const std::string vendor = p.hypervisorVendor();
    return {decide::vendorIsKnownVm(vendor), "hypervisor vendor = " + (vendor.empty() ? std::string("<none>") : vendor)};
}

// Detects: an active kernel debugger from NtQuerySystemInformation
// (SystemKernelDebuggerInformation). False positives: none in normal use.
// Neutralized: the query is hooked, or kernel debugging is disabled.
Outcome checkKernelDebugger(const SystemProbe& p) {
    const KernelDebuggerInfo info = p.kernelDebugger();
    const bool detected = decide::kernelDebuggerActive(info);
    std::string detail = std::string("KdDebuggerEnabled=") + (info.debuggerEnabled ? "1" : "0") +
                         " KdDebuggerNotPresent=" + (info.debuggerNotPresent ? "1" : "0");
    return {detected, std::move(detail)};
}

} // namespace

// ---------------------------------------------------------------------------
// The catalog
// ---------------------------------------------------------------------------

std::vector<Check> catalog() {
    return {
        {"api.isdebuggerpresent", "IsDebuggerPresent", CheckClass::Api,
         "The kernel32 flag, which is PEB.BeingDebugged. No false positives. A debugger-hiding plugin clears the PEB byte.",
         &checkIsDebuggerPresent},
        {"api.remotedebugger", "CheckRemoteDebuggerPresent", CheckClass::Api,
         "Reads the debug port for our own process. No false positives. Neutralized by faking the debug port to zero.",
         &checkRemoteDebugger},
        {"api.debugport", "NtQIP ProcessDebugPort", CheckClass::Api,
         "A non-zero ProcessDebugPort (0x7) from NtQueryInformationProcess means a user-mode debugger is attached. No false "
         "positives. Neutralized by hooking the query to return zero.",
         &checkDebugPort},
        {"api.debugflags", "NtQIP ProcessDebugFlags", CheckClass::Api,
         "ProcessDebugFlags (0x1F) is cleared to 0 when a debugger attaches, and stays 0 after it detaches. No false positives. "
         "Neutralized by hooking the query to return 1.",
         &checkDebugFlags},
        {"api.debugobject", "NtQIP ProcessDebugObjectHandle", CheckClass::Api,
         "A non-zero ProcessDebugObjectHandle (0x1E) is the kernel's debug object for this process. No false positives. "
         "Neutralized by hooking the query to return a null handle.",
         &checkDebugObject},

        {"peb.beingdebugged", "PEB BeingDebugged", CheckClass::Peb,
         "Reads PEB.BeingDebugged directly rather than through the API. No false positives. Clearing the byte defeats this and "
         "IsDebuggerPresent together.",
         &checkPebBeingDebugged},
        {"peb.ntglobalflag", "PEB NtGlobalFlag", CheckClass::Peb,
         "The heap-debug bits (0x70) the loader sets when started under a debugger. gflags and Application Verifier set the same "
         "bits with no debugger. Neutralized by clearing the bits after start-up.",
         &checkNtGlobalFlag},
        {"peb.heapflags", "Heap Flags", CheckClass::Peb,
         "Validation bits beyond HEAP_GROWABLE in the default heap Flags, left by the debug heap. Same gflags/Verifier false "
         "positives. Neutralized by resetting the flags.",
         &checkHeapFlags},
        {"peb.heapforceflags", "Heap ForceFlags", CheckClass::Peb,
         "ForceFlags is 0 on a normal heap and non-zero on a debug heap. Same gflags/Verifier false positives. Neutralized by "
         "resetting ForceFlags to 0.",
         &checkHeapForceFlags},

        {"exception.int3", "INT 3 (0xCC)", CheckClass::Exception,
         "A one-byte int 3 a debugger swallows before our __except sees it. No false positives. Neutralized by telling the "
         "debugger to pass the breakpoint back to the process.",
         &checkInt3},
        {"exception.int3long", "INT 3 long (0xCD 0x03)", CheckClass::Exception,
         "The two-byte int 3, which some debuggers mishandle by advancing the instruction pointer one byte. No false positives. "
         "Neutralized by correct instruction-length handling.",
         &checkInt3Long},
        {"exception.singlestep", "Single-step trap flag", CheckClass::Exception,
         "A debugger that consumes the single-step exception raised by the trap flag. No false positives. Neutralized by passing "
         "single-step exceptions through.",
         &checkSingleStep},
        {"exception.guardpage", "Guard page (PAGE_GUARD)", CheckClass::Exception,
         "A debugger that eats a PAGE_GUARD violation. The soft one of the exception checks: some runtime tooling also intercepts "
         "guard-page faults. Neutralized by passing the exception through.",
         &checkGuardPage},
        {"exception.closehandle", "CloseHandle invalid handle", CheckClass::Exception,
         "CloseHandle on a bogus handle raises STATUS_INVALID_HANDLE only when a debugger is attached. No false positives. "
         "Neutralized by turning off the debugger's invalid-handle raising.",
         &checkCloseHandle},
        {"exception.outputdebugstring", "OutputDebugString last-error", CheckClass::Exception,
         "The legacy trick where OutputDebugString clears a sentinel last-error value under a listening debugger. Unreliable on "
         "modern Windows and usually fires neither way. Largely obsolete; kept and documented as weak.",
         &checkOutputDebugString},

        {"timing.rdtsc", "RDTSC delta", CheckClass::Timing,
         "A large RDTSC gap across a tiny workload from stepping or a slow virtual clock. The soft class: preemption, a busy "
         "machine or a VM can trip it with no debugger. Neutralized by patching RDTSC.",
         &checkRdtsc},
        {"timing.rdtsccpuid", "RDTSC around CPUID", CheckClass::Timing,
         "An RDTSC gap around a serializing CPUID, which vm-exits under a hypervisor. Same soft-timing false positives, plus a "
         "hypervisor with no debugger. Neutralized by patching RDTSC or lightening CPUID handling.",
         &checkRdtscCpuid},
        {"timing.rdtscp", "RDTSCP delta", CheckClass::Timing,
         "The serializing RDTSCP variant of the RDTSC gap. Same soft-timing false positives. Neutralized by patching RDTSCP "
         "alongside RDTSC.",
         &checkRdtscp},
        {"timing.qpc", "QueryPerformanceCounter delta", CheckClass::Timing,
         "A QueryPerformanceCounter gap across the same workload. Same soft-timing false positives. Neutralized by slewing the "
         "performance counter.",
         &checkQpc},
        {"timing.gettickcount", "GetTickCount64 delta", CheckClass::Timing,
         "A GetTickCount64 gap, the coarse wall-clock version. Same soft-timing false positives, coarser still. Neutralized by "
         "slewing the tick source.",
         &checkGetTickCount},

        {"context.hardwarebreakpoints", "Hardware breakpoints (Dr0-Dr7)", CheckClass::Context,
         "A hardware breakpoint in the thread CONTEXT: a non-zero Dr0-Dr3 with Dr7 enables. A profiler or watchpoint from other "
         "tooling is a false positive. Neutralized by clearing the debug registers in the returned CONTEXT.",
         &checkHardwareBreakpoints},
        {"context.threadhide", "ThreadHideFromDebugger", CheckClass::Context,
         "Whether this thread's ThreadHideFromDebugger flag reads back set, meaning something hid the thread. Rarely a false "
         "positive from a protector. A debugger that intercepts NtSetInformationThread never lets the flag take.",
         &checkThreadHide},

        {"environment.parentprocess", "Parent process", CheckClass::Environment,
         "A parent process whose image name is a known debugger. Launching from Visual Studio (devenv.exe) fires it with no "
         "debugger attached. Neutralized by launching through an innocent intermediate process.",
         &checkParentProcess},
        {"environment.debuggerwindows", "Debugger windows", CheckClass::Environment,
         "Top-level windows whose class or title matches a known debugger. An unrelated window matching a title tag is a false "
         "positive. Neutralized by renaming the window or running headless.",
         &checkDebuggerWindows},
        {"environment.debuggerprocesses", "Debugger processes", CheckClass::Environment,
         "A running process anywhere on the machine whose image name is a known debugger. The tool being merely open, not "
         "attached, is a false positive. Neutralized by renaming the debugger process.",
         &checkDebuggerProcesses},
        {"environment.debuggerdevices", "Debugger device objects", CheckClass::Environment,
         "Openable \\\\.\\ device objects published by kernel debuggers and anti-anti-debug drivers. An unrelated driver with a "
         "clashing name is a false positive. Neutralized by the driver hiding its device object.",
         &checkDebuggerDevices},
        {"environment.moduleallowlist", "Loaded-module allowlist", CheckClass::Environment,
         "Loaded modules whose file is not under the system directories, WinSxS or the program's own folder. Broad by nature: "
         "antivirus, overlays, IMEs and RGB utilities inject legitimately. Neutralized by injecting from an allowed path or "
         "mapping code with no backing file.",
         &checkModuleAllowlist},
        {"environment.hypervisorbit", "Hypervisor present bit", CheckClass::Environment,
         "The hypervisor-present bit CPUID.1:ECX[31]. A VM/sandbox signal, not a debugger. A developer VM sets it, and so does a "
         "physical PC running virtualization-based security, WSL 2 or Docker. Neutralized by the hypervisor masking the bit.",
         &checkHypervisorBit},
        {"environment.hypervisorvendor", "Hypervisor vendor", CheckClass::Environment,
         "A known VM vendor string in CPUID leaf 0x40000000. As the hypervisor bit, naming the host is not a debugger. "
         "Neutralized by spoofing or clearing the vendor leaf.",
         &checkHypervisorVendor},
        {"environment.kerneldebugger", "Kernel debugger", CheckClass::Environment,
         "An active kernel debugger from NtQuerySystemInformation. No false positives in normal use. Neutralized by hooking the "
         "query or disabling kernel debugging.",
         &checkKernelDebugger},
    };
}

CheckResult runCheck(const Check& check, const SystemProbe& probe) {
    Outcome outcome = check.run(probe);
    CheckResult result;
    result.id = check.id;
    result.name = check.name;
    result.cls = check.cls;
    result.detected = outcome.detected;
    result.detail = std::move(outcome.detail);
    result.explanation = check.explanation;
    return result;
}

std::vector<CheckResult> runAll(const SystemProbe& probe, std::optional<CheckClass> onlyClass) {
    std::vector<CheckResult> results;
    for (const Check& check : catalog()) {
        if (onlyClass && check.cls != *onlyClass) {
            continue;
        }
        results.push_back(runCheck(check, probe));
    }
    return results;
}

} // namespace dbench
