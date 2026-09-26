#include "FakeProbe.h"

#include "core/Checks.h"
#include "core/Report.h"

#include <catch2/catch_test_macros.hpp>

#include <set>

using namespace dbench;
using dbench::test::FakeProbe;

TEST_CASE("every check reads clean on a clean machine and fires under a debugger", "[checks]") {
    const FakeProbe clean = FakeProbe::clean();
    const FakeProbe present = FakeProbe::debuggerPresent();

    const std::vector<CheckResult> cleanResults = runAll(clean);
    const std::vector<CheckResult> presentResults = runAll(present);

    REQUIRE(cleanResults.size() == presentResults.size());
    REQUIRE(cleanResults.size() == catalog().size());

    for (std::size_t i = 0; i < cleanResults.size(); ++i) {
        INFO("check " << cleanResults[i].id);
        CHECK_FALSE(cleanResults[i].detected);
        CHECK(presentResults[i].detected);
    }
}

TEST_CASE("no check fires on the clean fake, all fire on the debugger fake", "[checks]") {
    CHECK(detectedCount(runAll(FakeProbe::clean())) == 0);
    CHECK(detectedCount(runAll(FakeProbe::debuggerPresent())) == catalog().size());
}

TEST_CASE("check ids are unique and every check is fully documented", "[checks]") {
    std::set<std::string> ids;
    for (const Check& check : catalog()) {
        INFO("check " << check.id);
        CHECK(ids.insert(check.id).second); // false if already present
        CHECK_FALSE(check.id.empty());
        CHECK_FALSE(check.name.empty());
        CHECK_FALSE(check.explanation.empty());
    }
    CHECK(ids.size() == catalog().size());
}

TEST_CASE("every result carries a non-empty detail line", "[checks]") {
    for (const CheckResult& r : runAll(FakeProbe::clean())) {
        INFO("check " << r.id);
        CHECK_FALSE(r.detail.empty());
        CHECK_FALSE(r.explanation.empty());
    }
}

TEST_CASE("the catalog spans every class and --only filters to one", "[checks]") {
    std::set<CheckClass> seen;
    for (const Check& check : catalog()) {
        seen.insert(check.cls);
    }
    CHECK(seen.size() == allClasses().size());

    for (CheckClass cls : allClasses()) {
        const std::vector<CheckResult> filtered = runAll(FakeProbe::clean(), cls);
        CHECK_FALSE(filtered.empty());
        for (const CheckResult& r : filtered) {
            CHECK(r.cls == cls);
        }
    }
}

// --- the pure decisions, driven directly with fabricated readings ----------

TEST_CASE("boolean-flag decisions", "[decide]") {
    CHECK(decide::flagIsSet(true));
    CHECK_FALSE(decide::flagIsSet(false));
}

TEST_CASE("non-zero handle and port decisions", "[decide]") {
    CHECK(decide::valueIsNonZero(0x2F4));
    CHECK_FALSE(decide::valueIsNonZero(0));
}

TEST_CASE("ProcessDebugFlags is inverted", "[decide]") {
    CHECK(decide::debugFlagsCleared(0));      // cleared while debugged
    CHECK_FALSE(decide::debugFlagsCleared(1)); // set when not
}

TEST_CASE("NtGlobalFlag needs the three heap-debug bits", "[decide]") {
    CHECK(decide::ntGlobalFlagHasDebugBits(0x70));
    CHECK(decide::ntGlobalFlagHasDebugBits(0x00000078));
    CHECK_FALSE(decide::ntGlobalFlagHasDebugBits(0));
    CHECK_FALSE(decide::ntGlobalFlagHasDebugBits(0x00000008)); // only one unrelated bit
}

TEST_CASE("heap flags are suspicious beyond HEAP_GROWABLE", "[decide]") {
    CHECK_FALSE(decide::heapFlagsSuspicious(0x00000002)); // HEAP_GROWABLE only
    CHECK(decide::heapFlagsSuspicious(0x40000062));
    CHECK(decide::heapForceFlagsSet(0x40000060));
    CHECK_FALSE(decide::heapForceFlagsSet(0));
}

TEST_CASE("swallowed vs debugger-only exceptions have opposite polarity", "[decide]") {
    CHECK(decide::handlerWasSwallowed(false));  // our handler did not run -> debugger ate it
    CHECK_FALSE(decide::handlerWasSwallowed(true));
    CHECK(decide::exceptionOnlyUnderDebugger(true)); // CloseHandle raised -> debugger
    CHECK_FALSE(decide::exceptionOnlyUnderDebugger(false));
    CHECK(decide::lastErrorWasCleared(true));
    CHECK_FALSE(decide::lastErrorWasCleared(false));
}

TEST_CASE("timing decisions compare against the threshold", "[decide]") {
    CHECK(decide::deltaOverThreshold(threshold::kRdtsc + 1, threshold::kRdtsc));
    CHECK_FALSE(decide::deltaOverThreshold(threshold::kRdtsc, threshold::kRdtsc));
    CHECK_FALSE(decide::deltaOverThreshold(10, threshold::kRdtsc));
}

TEST_CASE("hardware breakpoint decision sees any set register", "[decide]") {
    CHECK_FALSE(decide::anyHardwareBreakpoint(DebugRegisters{}));
    CHECK(decide::anyHardwareBreakpoint(DebugRegisters{0x401000, 0, 0, 0, 0x101}));
    CHECK(decide::anyHardwareBreakpoint(DebugRegisters{0, 0, 0, 0, 0x400})); // Dr7 alone
}

TEST_CASE("name-in-list is case-insensitive", "[decide]") {
    const std::vector<std::string> list = {"x64dbg.exe", "windbg.exe"};
    CHECK(decide::nameInList("X64DBG.EXE", list));
    CHECK(decide::nameInList("windbg.exe", list));
    CHECK_FALSE(decide::nameInList("explorer.exe", list));
    CHECK_FALSE(decide::nameInList("", list));
}

TEST_CASE("found-lists and vendor and kernel-debugger decisions", "[decide]") {
    CHECK(decide::anyFound({"x64dbg"}));
    CHECK_FALSE(decide::anyFound({}));

    CHECK(decide::vendorIsKnownVm("VMwareVMware"));
    CHECK(decide::vendorIsKnownVm("Microsoft Hv"));
    CHECK(decide::vendorIsKnownVm("KVMKVMKVM"));
    CHECK_FALSE(decide::vendorIsKnownVm(""));
    CHECK_FALSE(decide::vendorIsKnownVm("GenuineIntel"));

    CHECK(decide::kernelDebuggerActive({true, false}));
    CHECK_FALSE(decide::kernelDebuggerActive({true, true}));  // enabled but reported not present
    CHECK_FALSE(decide::kernelDebuggerActive({false, false}));
}

TEST_CASE("module allowlist reports only paths outside the allowed prefixes", "[decide]") {
    const std::vector<std::string> allowed = {"c:\\windows\\", "c:\\program files\\debug-bench\\"};
    const std::vector<LoadedModule> modules = {
        {"ntdll.dll", "c:\\windows\\system32\\ntdll.dll"},
        {"debug-bench.exe", "c:\\program files\\debug-bench\\debug-bench.exe"},
        {"hook.dll", "c:\\temp\\hook.dll"},
        {"overlay.dll", "d:\\games\\overlay.dll"},
    };
    const std::vector<std::string> offenders = decide::modulesOutsideAllowlist(modules, allowed);
    REQUIRE(offenders.size() == 2);
    CHECK(offenders[0] == "hook.dll");
    CHECK(offenders[1] == "overlay.dll");

    CHECK(decide::modulesOutsideAllowlist({}, allowed).empty());
    // With no allowlist, everything is an offender.
    CHECK(decide::modulesOutsideAllowlist(modules, {}).size() == modules.size());
}
