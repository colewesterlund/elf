#pragma once

// The agent's body, shared by every entry point (the Windows service, the
// Linux daemon, and --debug console mode on both): load config, start the
// collector, run the rule engine and the server client, wait for a stop
// request, shut down cleanly.

#include <atomic>
#include <condition_variable>
#include <functional>
#include <mutex>

namespace elf {

// Set by a service stop handler or a signal handler; waited on by runAgent.
class StopSignal {
public:
    // From a normal thread (the Windows service control handler).
    void request();
    // From a POSIX signal handler: only stores a flag, no lock, no wakeup;
    // wait() notices it within its poll interval.
    void requestFromSignal() { m_fromSignal.store(true, std::memory_order_relaxed); }
    void wait();
    bool requested() const;
private:
    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    bool m_requested = false;
    std::atomic<bool> m_fromSignal{false};
};

// True until a stop was requested; worker threads poll it once a second.
bool agentRunning();

// Run the agent until `stop` is requested. `reportRunning` (optional) is
// called once configuration and logging are ready, before the slow event
// subscription phase, so a service manager can mark the service started.
// Returns 0 on a clean shutdown, 1 when startup failed (bad config).
int runAgent(StopSignal& stop, const std::function<void()>& reportRunning = {});

} // namespace elf
