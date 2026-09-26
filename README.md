<p align="center">
  <img src="docs/logo.svg" width="96" alt="debug-bench logo">
</p>

# debug-bench

A test target that runs the standard catalog of Windows anti-debug and
anti-injection checks against itself and reports which ones fire.

[![CI](https://github.com/HeathHowren/debug-bench/actions/workflows/ci.yml/badge.svg)](https://github.com/HeathHowren/debug-bench/actions/workflows/ci.yml)

debug-bench is a self-test, not a bypass. It runs about thirty well-documented
detection checks against its own process and prints which ones fire, with the
raw value each one read and a plain explanation of what it detects, when it
gives a false positive, and how it is commonly neutralized. Point a
debugger-hiding tool such as ScyllaHide or TitanHide, or your own plugin, at it
and watch the checks that used to fire go quiet. It does not touch any other
process and it changes nothing on the system.

debug-bench is written by Heath Howren
([Cyborg Elf](https://www.youtube.com/cyborgelf)) of
[Game Reversal Club](https://gamereversal.club) as a companion to
[*The Game Hacker's Handbook*](https://gamereversal.club/books/game-hackers-handbook/),
whose chapters on anti-debugging list these techniques. It is a small, scriptable
target for checking that a debugger stays hidden, including the debugger built
into Pointer Lab.

```
api
  clean     api.isdebuggerpresent          IsDebuggerPresent() = FALSE
  clean     api.remotedebugger             CheckRemoteDebuggerPresent() = FALSE
  clean     api.debugport                  ProcessDebugPort = 0x0
  clean     api.debugflags                 ProcessDebugFlags = 0x1
  clean     api.debugobject                ProcessDebugObjectHandle = 0x0

peb
  clean     peb.beingdebugged              PEB.BeingDebugged = 0
  clean     peb.ntglobalflag               NtGlobalFlag = 0x00000000
  clean     peb.heapflags                  Heap Flags = 0x00000002
  clean     peb.heapforceflags             Heap ForceFlags = 0x00000000

exception
  clean     exception.int3                 our __except caught the breakpoint
  clean     exception.int3long             our __except caught the long breakpoint
  clean     exception.singlestep           our __except caught the single-step
  clean     exception.guardpage            our __except caught the guard-page fault
  clean     exception.closehandle          CloseHandle(bad) returned quietly
  clean     exception.outputdebugstring    last error preserved

timing
  clean     timing.rdtsc                   RDTSC delta = 230 cycles
  clean     timing.rdtsccpuid              RDTSC-around-CPUID delta = 1052 cycles
  clean     timing.rdtscp                  RDTSCP delta = 122 cycles
  clean     timing.qpc                     QPC delta = 1 ticks
  clean     timing.gettickcount            GetTickCount64 delta = 0 ms

context
  clean     context.hardwarebreakpoints    Dr0=0x0 Dr1=0x0 Dr2=0x0 Dr3=0x0 Dr7=0x0
  clean     context.threadhide             ThreadHideFromDebugger = clear

environment
  clean     environment.parentprocess      parent = bash.exe
  clean     environment.debuggerwindows    no debugger windows
  clean     environment.debuggerprocesses  no debugger processes
  clean     environment.debuggerdevices    no debugger devices
  clean     environment.moduleallowlist    all 12 modules under allowed paths
  DETECTED  environment.hypervisorbit      CPUID.1:ECX[31] = 1
  DETECTED  environment.hypervisorvendor   hypervisor vendor = Microsoft Hv
  clean     environment.kerneldebugger     KdDebuggerEnabled=0 KdDebuggerNotPresent=1

2 of 30 checks fired.
```

*Real output from a 64-bit Release build, run with no debugger attached. The
two environment checks fire on a physical PC because Windows runs its
virtualization-based security on Hyper-V, which sets the hypervisor bit. That is
not a debugger. It is the false positive their explanations describe.*

## Under x64dbg

Real results with plain x64dbg 2026.05.27, no hiding plugin, on Windows 10
19045. The test used x64dbg's `headless.exe`, so it could be scripted and the
output captured. "Yes" means the check fired.

| Check | Attached while running | Attached before the first instruction | After detach |
|---|---|---|---|
| `api.isdebuggerpresent` | Yes | Yes | No |
| `api.remotedebugger` | Yes | Yes | No |
| `api.debugport` | Yes | Yes | No |
| `api.debugflags` | Yes | Yes | **Yes** |
| `api.debugobject` | Yes | Yes | No |
| `peb.beingdebugged` | Yes | Yes | No |
| `peb.ntglobalflag` | No | Yes | No |
| `peb.heapflags` | No | Yes | No |
| `peb.heapforceflags` | No | Yes | No |
| `exception.closehandle` | Yes | Yes | No |

The heap and global-flag checks fire only when the debugger is there as the
process starts, because Windows sets those flags while it loads the process.
`api.debugflags` stays set after the debugger detaches, so it also shows a
debugger that has come and gone.

The int3, single-step and `OutputDebugString` checks did not fire. x64dbg
stopped on each exception, and when it resumed, the program's own handler still
ran. The debugger-window check did not fire because the headless build has no
window; the x64dbg GUI would trip it. The two hypervisor checks fired in every
run, as above.

## What it does

- **Thirty checks in six classes.** API (`IsDebuggerPresent`,
  `CheckRemoteDebuggerPresent`, and the `NtQueryInformationProcess`
  ProcessDebugPort, ProcessDebugFlags and ProcessDebugObjectHandle queries), PEB
  (BeingDebugged, NtGlobalFlag, and the heap Flags and ForceFlags), exceptions
  (one- and two-byte `int 3`, single-step, guard page, CloseHandle and
  OutputDebugString), timing (RDTSC, RDTSC around CPUID, RDTSCP,
  QueryPerformanceCounter and GetTickCount64), context (hardware breakpoints and
  ThreadHideFromDebugger) and environment (parent process, debugger windows,
  processes and device objects, a loaded-module allowlist, the hypervisor bit
  and vendor, and the kernel debugger).
- **A documented result for each check.** Every check is one function that
  returns `{id, name, class, detected, detail}`. The detail line shows the raw
  value it read, and each check carries an explanation of what it detects, its
  false positives, and how it is commonly neutralized. Read the explanations in
  the `--json` output or in `src/core/Checks.cpp`.
- **Three ways to read the results.** An aligned table grouped by class by
  default, a JSON array with `--json` for scripts, and `--loop [ms]` to re-run
  on an interval so you can attach a debugger and watch checks flip live.
- **A class filter.** `--only <class>` runs one class at a time.
- **Honest about the soft checks.** The timing class fires on stepping or a slow
  virtual clock, not on a debugger that is only attached, and the environment
  class flags a VM and injected modules that may have nothing to do with a
  debugger. Each such check says so.
- **x64 and 32-bit builds**, with the C runtime linked statically, so a released
  binary runs on a clean Windows install.

## The checks are a test target, not a bypass

debug-bench only reads its own process. It does not attach to, read or modify
any other program, and it writes nothing to the registry or disk. The point is
to have a small, per-check-documented process to aim a debugger-hiding tool at,
so you can see which detections that tool still leaves showing. The techniques
themselves are the published catalog covered by
[al-khaser](https://github.com/LordNoteworthy/al-khaser) and the anti-debugging
literature; debug-bench is the smaller, scriptable, documented sibling.

## Download

Get the latest zip from
[Releases](https://github.com/HeathHowren/debug-bench/releases) and extract it
anywhere:

```
release\x64\debug-bench.exe    64-bit
release\x32\debug-bench.exe    32-bit
DebugBench\                    license, notices and the changelog
```

The binaries are unsigned. Antivirus software may flag a program that reads its
own PEB and raises breakpoints; build from source if you would rather not take a
binary on trust. Nothing here needs Administrator, and running as a normal user
is the intended case.

## Quick start

Run it with no arguments for the table:

```powershell
debug-bench.exe
```

Attach a debugger and watch the results change:

```powershell
debug-bench.exe --loop 1000
```

Then attach your debugger, or run debug-bench from inside one. Which checks fire
depends on the debugger and on when it attached. With plain x64dbg attached to
the running process, the API checks, `peb.beingdebugged` and
`exception.closehandle` fire. The heap and global-flag checks fire only when the
process starts under the debugger. See [Under x64dbg](#under-x64dbg) for the
full results. Turn on a debugger-hiding plugin and watch them go clean again.

## Usage

```
debug-bench [options]

  --json            emit the results as a JSON array
  --loop [ms]       re-run every ms (default 1000); Ctrl+C to stop
  --only <class>    run one class: api, peb, exception, timing,
                    context, environment
  --version         print the version and exit
  -h, --help        print this help and exit
```

The JSON array carries the same fields as the table, plus each check's full
explanation, so a script can record exactly what fired and why:

```json
{
  "id": "api.isdebuggerpresent",
  "name": "IsDebuggerPresent",
  "class": "api",
  "detected": false,
  "detail": "IsDebuggerPresent() = FALSE",
  "explanation": "The kernel32 flag, which is PEB.BeingDebugged. No false positives. A debugger-hiding plugin clears the PEB byte."
}
```

## Build

**Requirements:** Visual Studio 2022 with the C++ workload (MSVC v143) and CMake
3.28 or newer. The CMake that ships with Visual Studio is recent enough.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

One configure builds both executables: the 64-bit one directly, and the 32-bit
one through a nested Win32 build of the same source tree. The first configure
downloads Catch2, pinned by tag, for the tests only.

The decision logic behind each check is separated from the operating system.
Every OS reading sits behind an interface, so the pure "is this reading a
debugger?" logic is unit-tested against fabricated clean and debugger-present
readings, with no debugger, no Administrator and no target process. The tests
run in both a 64-bit and a 32-bit test binary. They never run a real debugger.
The results in [Under x64dbg](#under-x64dbg) come from a manual run, not from
the test suite.

To produce the release zip:

```powershell
cpack --config build/CPackConfig.cmake -C Release -B build/package
```

## Intended use

debug-bench is for studying software **you own or are authorized to analyze**,
and for testing your own debugger and anti-debug tooling. It is a target you run
yourself. Using a debugger against online or competitive games will very likely
trip anti-cheat software and get the account banned. That decision is yours;
this tool does not make it for you.

## License

MIT; see [LICENSE](LICENSE). debug-bench bundles no third-party code in its
binary. The tests use Catch2 (Boost Software License 1.0); details are in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
