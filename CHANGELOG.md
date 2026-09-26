# Changelog

All notable changes to debug-bench are recorded here. This project follows
[Semantic Versioning](https://semver.org/). Check ids, class names, the
`--json` field names and the command-line options are the interface other
tools script against; a change to any of them is a 2.0.

## [1.0.0] - 2026-09-25

The first release.

### Added

- **Thirty detection checks in six classes.** API (IsDebuggerPresent,
  CheckRemoteDebuggerPresent, and the ProcessDebugPort, ProcessDebugFlags and
  ProcessDebugObjectHandle queries), PEB (BeingDebugged, NtGlobalFlag, and the
  heap Flags and ForceFlags), exceptions (one- and two-byte int 3, single-step,
  guard page, CloseHandle and OutputDebugString), timing (RDTSC, RDTSC around
  CPUID, RDTSCP, QueryPerformanceCounter and GetTickCount64), context (hardware
  breakpoints and ThreadHideFromDebugger) and environment (parent process,
  debugger windows, processes and device objects, a loaded-module allowlist,
  the hypervisor bit and vendor, and the kernel debugger).
- **A documented result for every check.** Each check is one function that
  returns `{id, name, class, detected, detail}`, with a doc comment and a
  stored explanation of what it detects, its false positives and how it is
  commonly neutralized.
- **Three output modes.** An aligned table grouped by class by default, a JSON
  array with `--json`, and `--loop [ms]` to re-run on an interval so you can
  attach a debugger and watch checks flip.
- **A class filter.** `--only <class>` runs one of api, peb, exception, timing,
  context or environment.
- **Decision logic split from the operating system.** Every OS reading sits
  behind an interface, so the pure "is this detected?" logic is unit-tested
  against fabricated clean and debugger-present readings with no debugger.
- **x64 and Win32 executables** built from one configure, with the C runtime
  linked statically.
