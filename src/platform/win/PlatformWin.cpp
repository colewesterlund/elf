// Windows implementation of Platform.h.
#define WIN32_LEAN_AND_MEAN
#include "Platform.h"
#include "Console.h"
#include "EventQueryCollector.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <csignal>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <typeinfo>

#pragma comment(lib, "ws2_32.lib")

namespace elf {

// --- Paths and environment ---

std::string platformExeDir() {
    char exeBuf[MAX_PATH] = {0};
    if (GetModuleFileNameA(nullptr, exeBuf, MAX_PATH) > 0) {
        std::string exePath(exeBuf);
        auto lastSlash = exePath.find_last_of("\\/");
        if (lastSlash != std::string::npos) return exePath.substr(0, lastSlash + 1);
    }
    return "";
}

// %ProgramData%\ELFAgent\: the exe lives in Program Files (read-only for the
// service account), so all writable state goes here.
std::string platformDefaultDataDir() {
    std::string p = platformGetEnv("ProgramData");
    if (p.empty()) return platformExeDir();
    if (p.back() != '\\') p += '\\';
    p += "ELFAgent\\";
    std::error_code ec;
    std::filesystem::create_directories(p, ec);
    return p;
}

std::string platformGetEnv(const std::string& name) {
    char buf[4096] = {0};
    DWORD n = GetEnvironmentVariableA(name.c_str(), buf, sizeof(buf));
    if (n == 0 || n >= sizeof(buf)) return "";
    return std::string(buf, n);
}

bool platformIsAbsolutePath(const std::string& path) {
    if (path.empty()) return false;
    if (path.size() >= 3 && std::isalpha(static_cast<unsigned char>(path[0])) &&
        path[1] == ':' && (path[2] == '\\' || path[2] == '/')) return true;   // drive letter
    if (path.size() >= 2 && path[0] == '\\' && path[1] == '\\') return true;  // UNC
    return path[0] == '/' || path[0] == '\\';
}

const char* platformPathSep() { return "\\"; }

// --- Host identity ---

const char* platformSigmaProduct() { return "windows"; }

std::string platformConfigPath() { return platformExeDir() + "config.ini"; }

std::string platformHostname() {
    wchar_t buf[MAX_COMPUTERNAME_LENGTH + 1] = {0};
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (GetComputerNameW(buf, &size)) return wideToUtf8(buf);
    return "unknown-host";
}

// The address the host would use to reach a public destination: a UDP
// "connect" selects the outbound interface without sending a packet.
std::string platformIpAddress() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) return "unknown";
    std::string result = "unknown";
    SOCKET s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s != INVALID_SOCKET) {
        sockaddr_in target = {};
        target.sin_family = AF_INET;
        target.sin_port = htons(53);
        target.sin_addr.s_addr = inet_addr("8.8.8.8");
        if (connect(s, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 0) {
            sockaddr_in local = {};
            int len = sizeof(local);
            if (getsockname(s, reinterpret_cast<sockaddr*>(&local), &len) == 0) {
                result = inet_ntoa(local.sin_addr);
            }
        }
        closesocket(s);
    }
    WSACleanup();
    return result;
}

// RtlGetVersion is the version call that does not lie under manifest-based
// versioning; the registry ProductName supplies the edition.
std::string platformOsName() {
    using RtlGetVersion_t = LONG(WINAPI*)(OSVERSIONINFOEXW*);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (!ntdll) return "Windows";
    auto pRtlGetVersion = reinterpret_cast<RtlGetVersion_t>(GetProcAddress(ntdll, "RtlGetVersion"));
    if (!pRtlGetVersion) return "Windows";
    OSVERSIONINFOEXW osvi = {};
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    if (pRtlGetVersion(&osvi) != 0) return "Windows";
    std::string product;
    DWORD build = osvi.dwBuildNumber;
    if (osvi.dwMajorVersion == 10) product = build >= 22000 ? "Windows 11" : "Windows 10";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 3) product = "Windows 8.1";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 2) product = "Windows 8";
    else if (osvi.dwMajorVersion == 6 && osvi.dwMinorVersion == 1) product = "Windows 7";
    else product = "Windows";
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                      0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t edition[256] = {0};
        DWORD sz = sizeof(edition);
        DWORD type = 0;
        if (RegQueryValueExW(hKey, L"ProductName", nullptr, &type,
                             reinterpret_cast<LPBYTE>(edition), &sz) == ERROR_SUCCESS && type == REG_SZ) {
            product = wideToUtf8(edition);
        }
        RegCloseKey(hKey);
    }
    return product + " (build " + std::to_string(build) + ")";
}

// --- Text and time ---

std::wstring utf8ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], n);
    if (n > 0 && out.back() == L'\0') out.pop_back();
    return out;
}

// A plain std::string(w.begin(), w.end()) narrowing would corrupt every
// non-ASCII character; this encodes properly.
std::string wideToUtf8(const std::wstring& s) {
    if (s.empty()) return "";
    int n = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(n, '\0');
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &out[0], n, nullptr, nullptr);
    if (n > 0 && out.back() == '\0') out.pop_back();
    return out;
}

bool platformGmTime(std::time_t t, std::tm& out) { return gmtime_s(&out, &t) == 0; }
bool platformLocalTime(std::time_t t, std::tm& out) { return localtime_s(&out, &t) == 0; }
std::time_t platformTimeGm(std::tm& tm) { return _mkgmtime(&tm); }

// --- Process hooks ---

static std::string sehCodeString(DWORD code) {
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION: return "EXCEPTION_ACCESS_VIOLATION";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: return "EXCEPTION_ARRAY_BOUNDS_EXCEEDED";
        case EXCEPTION_DATATYPE_MISALIGNMENT: return "EXCEPTION_DATATYPE_MISALIGNMENT";
        case EXCEPTION_FLT_DENORMAL_OPERAND: return "EXCEPTION_FLT_DENORMAL_OPERAND";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO: return "EXCEPTION_FLT_DIVIDE_BY_ZERO";
        case EXCEPTION_FLT_INEXACT_RESULT: return "EXCEPTION_FLT_INEXACT_RESULT";
        case EXCEPTION_FLT_INVALID_OPERATION: return "EXCEPTION_FLT_INVALID_OPERATION";
        case EXCEPTION_FLT_OVERFLOW: return "EXCEPTION_FLT_OVERFLOW";
        case EXCEPTION_FLT_STACK_CHECK: return "EXCEPTION_FLT_STACK_CHECK";
        case EXCEPTION_FLT_UNDERFLOW: return "EXCEPTION_FLT_UNDERFLOW";
        case EXCEPTION_ILLEGAL_INSTRUCTION: return "EXCEPTION_ILLEGAL_INSTRUCTION";
        case EXCEPTION_IN_PAGE_ERROR: return "EXCEPTION_IN_PAGE_ERROR";
        case EXCEPTION_INT_DIVIDE_BY_ZERO: return "EXCEPTION_INT_DIVIDE_BY_ZERO";
        case EXCEPTION_INT_OVERFLOW: return "EXCEPTION_INT_OVERFLOW";
        case EXCEPTION_INVALID_DISPOSITION: return "EXCEPTION_INVALID_DISPOSITION";
        case EXCEPTION_NONCONTINUABLE_EXCEPTION: return "EXCEPTION_NONCONTINUABLE_EXCEPTION";
        case EXCEPTION_PRIV_INSTRUCTION: return "EXCEPTION_PRIV_INSTRUCTION";
        case EXCEPTION_STACK_OVERFLOW: return "EXCEPTION_STACK_OVERFLOW";
        default: return "code " + std::to_string(code);
    }
}

// Structured exceptions (access violation, stack overflow, ...) bypass the
// C++ runtime; this filter writes the report before the process dies.
static LONG WINAPI unhandledExceptionFilter(EXCEPTION_POINTERS* ep) {
    DWORD code = ep ? ep->ExceptionRecord->ExceptionCode : 0;
    void* addr = ep && ep->ExceptionRecord ? ep->ExceptionRecord->ExceptionAddress : nullptr;
    std::ostringstream oss;
    oss << sehCodeString(code) << " at address " << addr;
    if (code == EXCEPTION_ACCESS_VIOLATION && ep && ep->ExceptionRecord &&
        ep->ExceptionRecord->NumberParameters >= 2) {
        oss << " (attempted to "
            << (ep->ExceptionRecord->ExceptionInformation[0] == 0 ? "read" : "write")
            << " address "
            << reinterpret_cast<void*>(ep->ExceptionRecord->ExceptionInformation[1]) << ")";
    }
    writeCrashReport("Unhandled SEH exception", oss.str());
    return EXCEPTION_EXECUTE_HANDLER;
}

static void pureCallHandler() {
    writeCrashReport("Pure virtual function call", "");
}

void installCrashHandlers() {
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
    SetUnhandledExceptionFilter(unhandledExceptionFilter);
    installThreadCrashHandlers();
    _set_purecall_handler(pureCallHandler);
    std::signal(SIGABRT, [](int) {
        writeCrashReport("SIGABRT (abort())", "");
        std::_Exit(3);
    });
}

// QuickEdit is on by default: a click in the console window enters text
// selection and pauses every thread writing to the console until a key is
// pressed. Clearing it keeps clicks from stalling the agent; Ctrl+C still
// delivers SIGINT. No console (service mode) means nothing to configure.
void disableConsoleQuickEdit() {
    HANDLE hIn = GetStdHandle(STD_INPUT_HANDLE);
    if (hIn == INVALID_HANDLE_VALUE || hIn == nullptr) return;
    DWORD mode = 0;
    if (!GetConsoleMode(hIn, &mode)) return;
    mode &= ~ENABLE_QUICK_EDIT_MODE;
    mode &= ~ENABLE_MOUSE_INPUT;
    mode |= ENABLE_EXTENDED_FLAGS;
    SetConsoleMode(hIn, mode);
}

// --- On-demand historical collection ---

size_t platformCollectHistory(const std::string& startTimeIsoUtc,
                              const std::function<void(const std::wstring& xml)>& cb) {
    return EventQueryCollector::collect(startTimeIsoUtc, cb);
}

} // namespace elf
