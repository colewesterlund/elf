// Windows entry point: a hybrid executable that runs as a Windows service
// (no arguments, started by the Service Control Manager) or as a console
// program (--debug), plus the --install/--uninstall/--start/--stop helpers
// the install script uses. The agent itself is runAgent() in AgentRuntime.
#include "AgentRuntime.h"
#include "Console.h"
#include "Platform.h"

#include <windows.h>
#include <winsvc.h>
#include <algorithm>
#include <cctype>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <string>

#pragma comment(lib, "advapi32.lib")

using namespace elf;

static constexpr const char* kServiceName    = "ELFAgent";
static constexpr const char* kServiceDisplay = "Efficient Log Forwarder Agent";
static constexpr const char* kServiceAccount = ".\\ELFAgent";  // local user created by the installer

// One stop signal shared by the service stop handler and the console
// Ctrl+C handler; runAgent waits on it.
static StopSignal g_stop;

static void signalHandler(int) { g_stop.request(); }

// --- Service Control Manager helpers (--install / --uninstall) ---

// Create the service: auto-start, dedicated low-privilege account, restart
// on crash after 30 s, 30 s, then 60 s.
static bool installService() {
    std::string exeDir = platformExeDir();
    if (exeDir.empty()) {
        std::cerr << "Could not determine exe directory.\n";
        return false;
    }
    std::string exePath = exeDir + "efficient_log_forwarder.exe";
    if (!std::filesystem::exists(exePath)) {
        std::cerr << "Exe not found at " << exePath << "\n";
        return false;
    }
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::cerr << "OpenSCManager failed (err " << GetLastError() << "). Run as Administrator.\n";
        return false;
    }
    std::string cmdLine = "\"" + exePath + "\"";
    SC_HANDLE hSvc = CreateServiceA(
        hSCM, kServiceName, kServiceDisplay,
        SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
        SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        cmdLine.c_str(), nullptr, nullptr, nullptr,
        kServiceAccount, "");
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_EXISTS) std::cerr << "Service already exists. Use --uninstall first.\n";
        else std::cerr << "CreateService failed (err " << err << ").\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    SERVICE_FAILURE_ACTIONSA fa = {};
    fa.dwResetPeriod = 86400;
    fa.cActions = 3;
    SC_ACTION actions[3] = {};
    actions[0].Type = SC_ACTION_RESTART;  actions[0].Delay = 30000;
    actions[1].Type = SC_ACTION_RESTART;  actions[1].Delay = 30000;
    actions[2].Type = SC_ACTION_RESTART;  actions[2].Delay = 60000;
    fa.lpsaActions = actions;
    ChangeServiceConfig2A(hSvc, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    SERVICE_DESCRIPTIONA desc = {};
    desc.lpDescription = const_cast<char*>(
        "Efficient Log Forwarder: collects Windows events, applies "
        "correlation rules locally, and forwards only relevant events to "
        "the management server. Runs with least privilege.");
    ChangeServiceConfig2A(hSvc, SERVICE_CONFIG_DESCRIPTION, &desc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    std::cout << "Service '" << kServiceName << "' installed successfully.\n"
              << "  Exe:       " << exePath << "\n"
              << "  Account:   " << kServiceAccount << "\n"
              << "  Start:      Auto (boot)\n"
              << "  Recovery:  Restart (30s, 30s, 60s)\n"
              << "\nEnsure the ELFAgent local user exists and has "
              << "SeServiceLogonRight + SeSecurityPrivilege + Event Log Readers.\n";
    return true;
}

// Stop and delete the service. A hung agent never reports STOPPED and the
// SCM never force-kills it, so after a short grace period the process is
// terminated before the service is deleted (otherwise the exe stays locked
// and a re-install cannot replace it).
static bool uninstallService() {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        std::cerr << "OpenSCManager failed (err " << GetLastError() << "). Run as Administrator.\n";
        return false;
    }
    SC_HANDLE hSvc = OpenServiceA(hSCM, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE);
    if (!hSvc) {
        DWORD err = GetLastError();
        if (err == ERROR_SERVICE_DOES_NOT_EXIST) std::cerr << "Service does not exist.\n";
        else std::cerr << "OpenService failed (err " << err << ").\n";
        CloseServiceHandle(hSCM);
        return false;
    }
    DWORD svcPid = 0;
    SERVICE_STATUS_PROCESS ssp = {};
    DWORD needed = 0;
    if (QueryServiceStatusEx(hSvc, SC_STATUS_PROCESS_INFO,
                             reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
        svcPid = ssp.dwProcessId;
    }
    SERVICE_STATUS st = {};
    ControlService(hSvc, SERVICE_CONTROL_STOP, &st);
    bool stopped = false;
    for (int i = 0; i < 10; ++i) {
        if (QueryServiceStatus(hSvc, &st) && st.dwCurrentState == SERVICE_STOPPED) { stopped = true; break; }
        Sleep(500);
    }
    if (!stopped && svcPid != 0) {
        HANDLE hProc = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, svcPid);
        if (hProc) {
            std::cerr << "Service did not stop in time; killing pid " << svcPid << ".\n";
            TerminateProcess(hProc, 1);
            WaitForSingleObject(hProc, 10000);
            CloseHandle(hProc);
        }
        for (int i = 0; i < 10; ++i) {
            if (QueryServiceStatus(hSvc, &st) && st.dwCurrentState == SERVICE_STOPPED) { stopped = true; break; }
            Sleep(500);
        }
    }
    BOOL ok = DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    if (!ok) {
        std::cerr << "DeleteService failed (err " << GetLastError() << ").\n";
        return false;
    }
    std::cout << "Service '" << kServiceName << "' uninstalled.\n";
    return true;
}

static bool startServiceCmd() {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { std::cerr << "OpenSCManager failed.\n"; return false; }
    SC_HANDLE hSvc = OpenServiceA(hSCM, kServiceName, SERVICE_START);
    if (!hSvc) { CloseServiceHandle(hSCM); std::cerr << "Service not found.\n"; return false; }
    BOOL ok = StartServiceA(hSvc, 0, nullptr);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    if (!ok) { std::cerr << "StartService failed (err " << GetLastError() << ").\n"; return false; }
    std::cout << "Service started.\n";
    return true;
}

static bool stopServiceCmd() {
    SC_HANDLE hSCM = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!hSCM) { std::cerr << "OpenSCManager failed.\n"; return false; }
    SC_HANDLE hSvc = OpenServiceA(hSCM, kServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hSvc) { CloseServiceHandle(hSCM); std::cerr << "Service not found.\n"; return false; }
    SERVICE_STATUS st = {};
    BOOL ok = ControlService(hSvc, SERVICE_CONTROL_STOP, &st);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    if (!ok) { std::cerr << "ControlService failed (err " << GetLastError() << ").\n"; return false; }
    std::cout << "Service stop requested.\n";
    return true;
}

// --- Service dispatch (ServiceMain + HandlerEx) ---

static SERVICE_STATUS        g_svcStatus = {};
static SERVICE_STATUS_HANDLE g_svcHandle = nullptr;

static void reportSvcState(DWORD state, DWORD exitCode = 0, DWORD waitHint = 0) {
    g_svcStatus.dwCurrentState  = state;
    g_svcStatus.dwWin32ExitCode = exitCode;
    g_svcStatus.dwWaitHint      = waitHint;
    g_svcStatus.dwCheckPoint    = 0;
    if (state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING)
        g_svcStatus.dwCheckPoint = 1;
    SetServiceStatus(g_svcHandle, &g_svcStatus);
}

static DWORD WINAPI svcHandlerEx(DWORD ctrl, DWORD eventType, LPVOID eventData, LPVOID context) {
    (void)eventType; (void)eventData; (void)context;
    switch (ctrl) {
        case SERVICE_CONTROL_STOP:
        case SERVICE_CONTROL_SHUTDOWN:
            reportSvcState(SERVICE_STOP_PENDING, 0, 15000);
            g_stop.request();
            return NO_ERROR;
        case SERVICE_CONTROL_INTERROGATE:
            return NO_ERROR;
        default:
            return ERROR_CALL_NOT_IMPLEMENTED;
    }
}

static VOID WINAPI svcMain(DWORD argc, LPSTR* argv) {
    (void)argc; (void)argv;
    g_svcHandle = RegisterServiceCtrlHandlerExA(kServiceName, svcHandlerEx, nullptr);
    if (!g_svcHandle) return;
    // Services have no console; log files only.
    suppressConsole();
    g_svcStatus.dwServiceType      = SERVICE_WIN32_OWN_PROCESS;
    g_svcStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    reportSvcState(SERVICE_START_PENDING, 0, 5000);
    // RUNNING is reported once config and logging are ready, before the
    // subscription phase, which can exceed the SCM's 30 s start timeout.
    runAgent(g_stop, []() { reportSvcState(SERVICE_RUNNING); });
    reportSvcState(SERVICE_STOPPED);
}

// --- Console entry point ---

#ifndef ELF_AGENT_VERSION
#define ELF_AGENT_VERSION "dev"
#endif

static void printUsage() {
    std::cout <<
        "Efficient Log Forwarder Agent " << ELF_AGENT_VERSION << "\n"
        "\n"
        "Usage:\n"
        "  efficient_log_forwarder.exe              Run as a Windows service\n"
        "  efficient_log_forwarder.exe --debug      Run in the console (foreground)\n"
        "  efficient_log_forwarder.exe --install    Install the Windows service (admin)\n"
        "  efficient_log_forwarder.exe --uninstall  Uninstall the service (admin)\n"
        "  efficient_log_forwarder.exe --start      Start the service\n"
        "  efficient_log_forwarder.exe --stop       Stop the service\n"
        "  efficient_log_forwarder.exe --version    Print the version\n"
        "  efficient_log_forwarder.exe --help       Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string arg = (argc > 1) ? argv[1] : "";
    std::transform(arg.begin(), arg.end(), arg.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (arg == "--help" || arg == "-h" || arg == "/?") { printUsage(); return 0; }
    if (arg == "--version" || arg == "-v") { std::cout << "ELF Agent " << ELF_AGENT_VERSION << "\n"; return 0; }
    if (arg == "--install")   return installService()   ? 0 : 1;
    if (arg == "--uninstall") return uninstallService() ? 0 : 1;
    if (arg == "--start")     return startServiceCmd()  ? 0 : 1;
    if (arg == "--stop")      return stopServiceCmd()   ? 0 : 1;

    if (arg == "--debug") {
        std::signal(SIGINT, signalHandler);
        std::signal(SIGTERM, signalHandler);
        return runAgent(g_stop);
    }
    if (!arg.empty()) {
        std::cerr << "Unknown argument: " << argv[1] << "\n\n";
        printUsage();
        return 1;
    }

    SERVICE_TABLE_ENTRYA dispatchTable[] = {
        { const_cast<char*>(kServiceName), svcMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherA(dispatchTable)) {
        DWORD err = GetLastError();
        if (err == ERROR_FAILED_SERVICE_CONTROLLER_CONNECT)
            std::cerr << "Not running as a service. Use --debug for console mode.\n";
        else
            std::cerr << "StartServiceCtrlDispatcher failed (err " << err << ").\n";
        return 1;
    }
    return 0;
}
