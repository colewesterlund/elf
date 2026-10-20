// Linux entry point: a plain daemon driven by systemd (no arguments) or a
// console program (--debug). The agent itself is runAgent() in
// AgentRuntime; service installation is the install script's job.
#include "AgentRuntime.h"
#include "Console.h"

#include <algorithm>
#include <cctype>
#include <csignal>
#include <iostream>
#include <string>

using namespace elf;

#ifndef ELF_AGENT_VERSION
#define ELF_AGENT_VERSION "dev"
#endif

static StopSignal g_stop;

// Runs on whichever thread takes the signal; only the lock-free path is
// safe here.
static void signalHandler(int) { g_stop.requestFromSignal(); }

static void printUsage() {
    std::cout <<
        "Efficient Log Forwarder Agent " << ELF_AGENT_VERSION << "\n"
        "\n"
        "Usage:\n"
        "  elf-agent              Run in the foreground (what the systemd unit does)\n"
        "  elf-agent --debug      Run in the foreground with console output\n"
        "  elf-agent --version    Print the version\n"
        "  elf-agent --help       Show this help\n";
}

int main(int argc, char* argv[]) {
    std::string arg = (argc > 1) ? argv[1] : "";
    std::transform(arg.begin(), arg.end(), arg.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    if (arg == "--help" || arg == "-h") { printUsage(); return 0; }
    if (arg == "--version" || arg == "-v") { std::cout << "ELF Agent " << ELF_AGENT_VERSION << "\n"; return 0; }
    if (!arg.empty() && arg != "--debug") {
        std::cerr << "Unknown argument: " << argv[1] << "\n\n";
        printUsage();
        return 1;
    }
    // Console output stays on: under systemd it is the journal, which is
    // where an operator looks first when the unit fails to start. Only
    // notices and errors go there; the agent log holds everything.
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    return runAgent(g_stop);
}
