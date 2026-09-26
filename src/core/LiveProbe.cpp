#include "core/LiveProbe.h"
#include "core/Checks.h"

#include <windows.h>
#include <winternl.h>
#include <tlhelp32.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <intrin.h>

// The two things MSVC C++ cannot express for x64 (no inline asm), supplied by
// asm_x64.asm / asm_x86.asm.
extern "C" void db_set_trap_flag(void);
extern "C" void db_int3_long(void);

#ifndef STATUS_GUARD_PAGE_VIOLATION
#define STATUS_GUARD_PAGE_VIOLATION ((DWORD)0x80000001L)
#endif
#ifndef EXCEPTION_INVALID_HANDLE
#define EXCEPTION_INVALID_HANDLE ((DWORD)0xC0000008L)
#endif

namespace dbench {

namespace {

// NtQueryInformationProcess information classes we use but winternl.h does not
// name.
constexpr ULONG kProcessDebugPort = 7;
constexpr ULONG kProcessDebugObjectHandle = 30; // 0x1E
constexpr ULONG kProcessDebugFlags = 31;        // 0x1F
constexpr ULONG kThreadHideFromDebugger = 0x11;
constexpr ULONG kSystemKernelDebuggerInformation = 0x23;

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQueryInformationThreadFn = NTSTATUS(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(ULONG, PVOID, ULONG, PULONG);

NtQueryInformationProcessFn ntQueryInformationProcess() {
    static auto fn = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    return fn;
}

NtQueryInformationThreadFn ntQueryInformationThread() {
    static auto fn = reinterpret_cast<NtQueryInformationThreadFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return fn;
}

NtQuerySystemInformationFn ntQuerySystemInformation() {
    static auto fn = reinterpret_cast<NtQuerySystemInformationFn>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));
    return fn;
}

BYTE* pebBase() {
#ifdef _WIN64
    return reinterpret_cast<BYTE*>(__readgsqword(0x60));
#else
    return reinterpret_cast<BYTE*>(__readfsdword(0x30));
#endif
}

#ifdef _WIN64
constexpr std::size_t kNtGlobalFlagOffset = 0xBC;
constexpr std::size_t kHeapFlagsOffset = 0x70;
constexpr std::size_t kHeapForceFlagsOffset = 0x74;
#else
constexpr std::size_t kNtGlobalFlagOffset = 0x68;
constexpr std::size_t kHeapFlagsOffset = 0x40;
constexpr std::size_t kHeapForceFlagsOffset = 0x44;
#endif

std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string narrowLower(const wchar_t* wide) {
    std::string out;
    for (const wchar_t* p = wide; p && *p; ++p) {
        out += static_cast<char>(std::tolower(static_cast<unsigned char>(*p < 128 ? *p : '?')));
    }
    return out;
}

// The smallest of several samples of a timing workload. A single sample is
// noisy; the minimum is close to the un-instrumented cost, so a clean run stays
// well under the threshold and only real interference pushes it over.
template <typename Sampler> std::uint64_t minSample(Sampler sampler, int samples = 8) {
    std::uint64_t best = ~0ull;
    for (int i = 0; i < samples; ++i) {
        best = std::min(best, sampler());
    }
    return best;
}

// A tiny fixed workload the timing checks measure across.
unsigned spin() {
    volatile unsigned x = 0;
    for (unsigned i = 0; i < 64; ++i) {
        x += i;
    }
    return x;
}

bool int3Ran() {
    __try {
        __debugbreak();
        return false;
    } __except (GetExceptionCode() == EXCEPTION_BREAKPOINT ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
}

bool int3LongRan() {
    __try {
        db_int3_long();
        return false;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return true;
    }
}

bool singleStepRan() {
    __try {
        db_set_trap_flag();
        return false;
    } __except (GetExceptionCode() == EXCEPTION_SINGLE_STEP ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
}

bool guardPageRan() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    BYTE* page = static_cast<BYTE*>(VirtualAlloc(nullptr, si.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    if (page == nullptr) {
        return true; // cannot test; report as clean (handler would have run)
    }
    bool ran = false;
    DWORD oldProtect = 0;
    if (VirtualProtect(page, si.dwPageSize, PAGE_READWRITE | PAGE_GUARD, &oldProtect)) {
        __try {
            volatile BYTE value = *page;
            (void)value;
        } __except (GetExceptionCode() == STATUS_GUARD_PAGE_VIOLATION ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
            ran = true;
        }
    }
    VirtualFree(page, 0, MEM_RELEASE);
    return ran;
}

bool closeHandleRaisedException() {
    __try {
        CloseHandle(reinterpret_cast<HANDLE>(static_cast<ULONG_PTR>(0xDEADBEEF)));
        return false;
    } __except (GetExceptionCode() == EXCEPTION_INVALID_HANDLE ? EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        return true;
    }
}

std::uint32_t parentProcessId() {
    auto fn = ntQueryInformationProcess();
    if (fn == nullptr) {
        return 0;
    }
    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returned = 0;
    if (fn(GetCurrentProcess(), 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &returned) != 0) {
        return 0;
    }
    return static_cast<std::uint32_t>(reinterpret_cast<ULONG_PTR>(pbi.Reserved3)); // InheritedFromUniqueProcessId slot
}

BOOL CALLBACK collectWindow(HWND hwnd, LPARAM lparam) {
    auto* found = reinterpret_cast<std::vector<std::string>*>(lparam);
    char title[256] = {0};
    const int length = GetWindowTextA(hwnd, title, static_cast<int>(sizeof(title)));
    if (length <= 0) {
        return TRUE;
    }
    static const std::array<const char*, 6> tags = {"x64dbg", "x32dbg", "ollydbg", "windbg", "ida -", "immunity debugger"};
    const std::string lowered = toLower(std::string(title, static_cast<std::size_t>(length)));
    for (const char* tag : tags) {
        if (lowered.find(tag) != std::string::npos &&
            std::find(found->begin(), found->end(), std::string(tag)) == found->end()) {
            found->push_back(tag);
        }
    }
    return TRUE;
}

} // namespace

bool LiveProbe::isDebuggerPresent() const { return ::IsDebuggerPresent() != FALSE; }

bool LiveProbe::checkRemoteDebuggerPresent() const {
    BOOL present = FALSE;
    ::CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != FALSE;
}

std::uint64_t LiveProbe::ntDebugPort() const {
    auto fn = ntQueryInformationProcess();
    if (fn == nullptr) {
        return 0;
    }
    ULONG_PTR port = 0;
    ULONG returned = 0;
    fn(GetCurrentProcess(), kProcessDebugPort, &port, sizeof(port), &returned);
    return static_cast<std::uint64_t>(port);
}

std::uint32_t LiveProbe::ntDebugFlags() const {
    auto fn = ntQueryInformationProcess();
    if (fn == nullptr) {
        return 1; // the not-debugged value, so a missing API does not false-positive
    }
    ULONG flags = 1;
    ULONG returned = 0;
    fn(GetCurrentProcess(), kProcessDebugFlags, &flags, sizeof(flags), &returned);
    return flags;
}

std::uint64_t LiveProbe::ntDebugObjectHandle() const {
    auto fn = ntQueryInformationProcess();
    if (fn == nullptr) {
        return 0;
    }
    ULONG_PTR handle = 0;
    ULONG returned = 0;
    fn(GetCurrentProcess(), kProcessDebugObjectHandle, &handle, sizeof(handle), &returned);
    return static_cast<std::uint64_t>(handle);
}

bool LiveProbe::pebBeingDebugged() const { return *(pebBase() + 0x02) != 0; }

std::uint32_t LiveProbe::pebNtGlobalFlag() const { return *reinterpret_cast<std::uint32_t*>(pebBase() + kNtGlobalFlagOffset); }

std::uint32_t LiveProbe::heapFlags() const {
    BYTE* heap = static_cast<BYTE*>(GetProcessHeap());
    return *reinterpret_cast<std::uint32_t*>(heap + kHeapFlagsOffset);
}

std::uint32_t LiveProbe::heapForceFlags() const {
    BYTE* heap = static_cast<BYTE*>(GetProcessHeap());
    return *reinterpret_cast<std::uint32_t*>(heap + kHeapForceFlagsOffset);
}

bool LiveProbe::int3HandlerRan() const { return int3Ran(); }
bool LiveProbe::int3LongHandlerRan() const { return int3LongRan(); }
bool LiveProbe::singleStepHandlerRan() const { return singleStepRan(); }
bool LiveProbe::guardPageHandlerRan() const { return guardPageRan(); }
bool LiveProbe::closeHandleRaised() const { return closeHandleRaisedException(); }

bool LiveProbe::outputDebugStringClearedError() const {
    SetLastError(0x1234ABCD);
    OutputDebugStringA("debug-bench self-test");
    return GetLastError() == 0;
}

std::uint64_t LiveProbe::rdtscDelta() const {
    return minSample([] {
        const unsigned long long a = __rdtsc();
        const unsigned workload = spin();
        const unsigned long long b = __rdtsc();
        (void)workload;
        return static_cast<std::uint64_t>(b - a);
    });
}

std::uint64_t LiveProbe::rdtscCpuidDelta() const {
    return minSample([] {
        int regs[4] = {0, 0, 0, 0};
        const unsigned long long a = __rdtsc();
        __cpuid(regs, 0);
        const unsigned long long b = __rdtsc();
        return static_cast<std::uint64_t>(b - a);
    });
}

std::uint64_t LiveProbe::rdtscpDelta() const {
    return minSample([] {
        unsigned aux = 0;
        const unsigned long long a = __rdtscp(&aux);
        const unsigned workload = spin();
        const unsigned long long b = __rdtscp(&aux);
        (void)workload;
        return static_cast<std::uint64_t>(b - a);
    });
}

std::uint64_t LiveProbe::qpcDeltaTicks() const {
    return minSample([] {
        LARGE_INTEGER a, b;
        QueryPerformanceCounter(&a);
        const unsigned workload = spin();
        QueryPerformanceCounter(&b);
        (void)workload;
        return static_cast<std::uint64_t>(b.QuadPart - a.QuadPart);
    });
}

std::uint64_t LiveProbe::getTickCountDelta() const {
    return minSample([] {
        const ULONGLONG a = GetTickCount64();
        const unsigned workload = spin();
        const ULONGLONG b = GetTickCount64();
        (void)workload;
        return static_cast<std::uint64_t>(b - a);
    });
}

DebugRegisters LiveProbe::debugRegisters() const {
    DebugRegisters regs;
    CONTEXT ctx;
    SecureZeroMemory(&ctx, sizeof(ctx));
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        regs.dr0 = static_cast<std::uint64_t>(ctx.Dr0);
        regs.dr1 = static_cast<std::uint64_t>(ctx.Dr1);
        regs.dr2 = static_cast<std::uint64_t>(ctx.Dr2);
        regs.dr3 = static_cast<std::uint64_t>(ctx.Dr3);
        regs.dr7 = static_cast<std::uint64_t>(ctx.Dr7);
    }
    return regs;
}

bool LiveProbe::threadHiddenFromDebugger() const {
    auto fn = ntQueryInformationThread();
    if (fn == nullptr) {
        return false;
    }
    BOOLEAN hidden = FALSE;
    ULONG returned = 0;
    fn(GetCurrentThread(), kThreadHideFromDebugger, &hidden, sizeof(hidden), &returned);
    return hidden != FALSE;
}

std::string LiveProbe::parentProcessName() const {
    const std::uint32_t parent = parentProcessId();
    if (parent == 0) {
        return {};
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return {};
    }
    std::string name;
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == parent) {
                name = narrowLower(entry.szExeFile);
                break;
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return name;
}

std::vector<std::string> LiveProbe::debuggerWindowsFound() const {
    std::vector<std::string> found;
    EnumWindows(&collectWindow, reinterpret_cast<LPARAM>(&found));
    return found;
}

std::vector<std::string> LiveProbe::debuggerProcessesFound() const {
    std::vector<std::string> found;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return found;
    }
    const std::vector<std::string>& known = knownDebuggerProcessNames();
    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Process32FirstW(snapshot, &entry)) {
        do {
            const std::string name = narrowLower(entry.szExeFile);
            if (decide::nameInList(name, known) && std::find(found.begin(), found.end(), name) == found.end()) {
                found.push_back(name);
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return found;
}

std::vector<std::string> LiveProbe::debuggerDevicesFound() const {
    std::vector<std::string> found;
    static const std::array<const char*, 5> devices = {"\\\\.\\TitanHide", "\\\\.\\SICE", "\\\\.\\NTICE", "\\\\.\\SIWVID",
                                                        "\\\\.\\ScyllaHide"};
    for (const char* device : devices) {
        HANDLE handle = CreateFileA(device, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
        if (handle != INVALID_HANDLE_VALUE) {
            found.push_back(device);
            CloseHandle(handle);
        }
    }
    return found;
}

std::vector<LoadedModule> LiveProbe::loadedModules() const {
    std::vector<LoadedModule> modules;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (snapshot == INVALID_HANDLE_VALUE) {
        return modules;
    }
    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);
    if (Module32FirstW(snapshot, &entry)) {
        do {
            modules.push_back({narrowLower(entry.szModule), narrowLower(entry.szExePath)});
        } while (Module32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return modules;
}

std::vector<std::string> LiveProbe::allowedModuleDirectories() const {
    std::vector<std::string> dirs;

    wchar_t windowsDir[MAX_PATH] = {0};
    if (GetWindowsDirectoryW(windowsDir, MAX_PATH) > 0) {
        dirs.push_back(narrowLower(windowsDir) + "\\");
    }

    wchar_t modulePath[MAX_PATH] = {0};
    if (GetModuleFileNameW(nullptr, modulePath, MAX_PATH) > 0) {
        std::string exePath = narrowLower(modulePath);
        const std::size_t slash = exePath.find_last_of('\\');
        if (slash != std::string::npos) {
            dirs.push_back(exePath.substr(0, slash + 1));
        }
    }
    return dirs;
}

bool LiveProbe::hypervisorPresentBit() const {
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 1);
    return (static_cast<unsigned>(regs[2]) & (1u << 31)) != 0;
}

std::string LiveProbe::hypervisorVendor() const {
    if (!hypervisorPresentBit()) {
        return {};
    }
    int regs[4] = {0, 0, 0, 0};
    __cpuid(regs, 0x40000000);
    char vendor[13] = {0};
    std::memcpy(vendor + 0, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);
    return vendor;
}

KernelDebuggerInfo LiveProbe::kernelDebugger() const {
    KernelDebuggerInfo info;
    auto fn = ntQuerySystemInformation();
    if (fn == nullptr) {
        return info;
    }
    struct KernelDebuggerBlock {
        BOOLEAN enabled;
        BOOLEAN notPresent;
    } block{FALSE, TRUE};
    ULONG returned = 0;
    if (fn(kSystemKernelDebuggerInformation, &block, sizeof(block), &returned) == 0) {
        info.debuggerEnabled = block.enabled != FALSE;
        info.debuggerNotPresent = block.notPresent != FALSE;
    }
    return info;
}

} // namespace dbench
