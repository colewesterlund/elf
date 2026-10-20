#pragma once

#include <cstdint>

#include "HttpClient.h"
#include <string>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <map>
#include <set>
#include <atomic>
#include <chrono>
#include <thread>
#include <utility>
#include <vector>

namespace elf {

// Disk-backed FIFO queue for pending HTTP POSTs (management server mirror
// and SIEM destinations).
//
// The agent's rule engine calls reportAlert/reportEvent/reportLogs
// synchronously; the actual HTTP POST is enqueued here and sent on a
// background worker thread. This guarantees the rule engine never blocks
// on network I/O (a slow/downed server would otherwise freeze the agent).
//
// Disk-backed persistence: each enqueued POST is written to a numbered file
// in the spool directory so pending requests survive an agent restart or
// crash. On startup, load() reads any existing spool files back into the
// in-memory deque so they're re-sent. This means events/alerts are never
// lost even if the agent dies with the server unreachable.
//
// Ack-after-success: dequeue() hands an entry to the worker but leaves its
// file on disk; the worker calls ack() once the POST succeeded (file
// removed) or requeue() when it failed (entry goes back to the FRONT so
// FIFO order is kept and it is retried first). A crash while a POST is in
// flight therefore re-sends the entry on the next start (at-least-once),
// instead of losing it the way a delete-before-send would.
//
// Bounded size: the total spool size is capped at maxBytes. When the cap
// is exceeded, the OLDEST entries are evicted (dropped); this is the right
// eviction policy for a forwarder because the oldest events are the least
// valuable (the analyst has already moved past them) and we'd rather drop
// old data than new. Without a cap, a long network outage could fill the
// disk. A single body larger than half the cap is refused outright: it
// would evict every other pending entry to make room for itself.
//
// File format (v2):
//   "ELF2"                        4-byte magic
//   [4-byte big-endian len][URL]
//   [4-byte big-endian len][headers: "Name: value\r\n" lines, may be empty]
//   [4-byte big-endian len][body]
// v1 files (no magic: [len][URL][len][body]) written by older builds are
// still read; the first four bytes are either the magic or a URL length,
// and 0x454C4632 (1.16 GB) can never be a real length because enqueue
// refuses anything over half the spool cap.
// The filename is a monotonic sequence number (zero-padded) so the FIFO
// order is preserved across restarts. A .tmp suffix is used during write,
// then renamed to the final name for atomicity (a crash mid-write leaves
// a .tmp file that's deleted on load).
//
// Thread safety: all public methods take an internal mutex. The worker
// thread blocks on a condition variable until work arrives or stop() is
// called. The disk I/O happens under the lock so two threads can't corrupt
// the directory; this is acceptable because the operations are small and
// the worker is the only consumer.
class SpoolQueue {
public:
    SpoolQueue() = default;
    ~SpoolQueue();

    // Set the spool directory and size cap. Call once at startup, before
    // enqueue()/load(). Creates the directory if it doesn't exist.
    //   dir:      e.g. %ProgramData%\ELFAgent\spool\
    //   maxBytes: max total spool size; 0 = unbounded (not recommended
    //               for a long-running service).
    void setDirectory(const std::string& dir, size_t maxBytes);

    // Load any existing spool files from disk into the in-memory queue.
    // Call once at startup, after setDirectory(), before the worker
    // thread starts. Returns the number of entries loaded. Entries that
    // were in flight when the previous process died are loaded too (they
    // are re-sent, at-least-once delivery).
    int load();

    // Enqueue a POST (url + optional header block + body). Writes it to
    // disk immediately so it survives a crash. If the spool is at capacity,
    // evicts the oldest entries (and their files) first. Wakes the worker
    // thread. Returns false (and logs) when the entry was refused: empty
    // url, no spool directory, body larger than half the cap, or a disk
    // write failure.
    bool enqueue(std::string url, std::string headers, std::string body);
    bool enqueue(std::string url, std::string body);   // no extra headers

    // Dequeue the next pending POST without removing it from disk. Blocks
    // until one is available or stop() is called. Returns false if stopped
    // (worker should exit). On success `id` identifies the entry for
    // ack()/requeue(). Unreadable or corrupt entries are deleted and
    // skipped internally; this never returns an entry with an empty url.
    bool dequeue(uint64_t& id, std::string& url, std::string& headers, std::string& body);
    bool dequeue(uint64_t& id, std::string& url, std::string& body);   // headers discarded

    // Convenience: dequeue + ack in one step (delete-before-send). Kept
    // for callers/tests that don't need the ack model.
    bool dequeue(std::string& url, std::string& body);

    // The POST for `id` succeeded: remove its file and forget it.
    void ack(uint64_t id);

    // The POST for `id` failed transiently: put it back at the front of
    // the queue so it is retried first (keeps FIFO; a stuck entry is also
    // the first one evicted when the cap is hit).
    void requeue(uint64_t id);

    // Signal the worker to stop. Wakes a blocked dequeue().
    void stop();

    // Number of pending entries, including any currently in flight
    // (dequeued but not yet acked).
    size_t size() const;

private:
    // Evict the oldest queued entries until the total spool size is
    // <= maxBytes. Called under m_mutex. Removes the files from disk and
    // logs one summary line per eviction batch.
    void evictIfNeeded();

    // Remove one entry's file and subtract its size from the running total.
    // Called under m_mutex. Returns the number of bytes released.
    size_t removeFile(uint64_t seq);

    // Build the full path for a sequence number.
    std::string filePath(uint64_t seq) const;

    mutable std::mutex m_mutex;
    std::condition_variable m_cv;
    std::deque<uint64_t> m_seqQueue;   // sequence numbers of pending files
    std::set<uint64_t>   m_inFlight;   // dequeued, awaiting ack/requeue
    std::string m_dir;
    size_t      m_maxBytes = 0;
    size_t      m_curBytes = 0;
    uint64_t    m_nextSeq = 1;         // monotonic filename counter
    std::atomic<bool> m_stopping{false};
};

// OAuth2 client-credentials source for a destination (Microsoft Sentinel's
// Logs Ingestion API). The token is fetched and cached by the worker thread
// at send time, never stored in the spool, since it expires.
struct OAuthSpec {
    std::string tokenUrl;      // https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
    std::string clientId;
    std::string clientSecret;
    std::string scope;         // https://monitor.azure.com/.default
};

// A SpoolQueue plus the background thread that drains it. Owns the retry
// policy so every producer (server mirror, http:// destinations) behaves
// the same way:
//   - 2xx                → ack (entry deleted).
//   - permanent 4xx      → logged once with the server's response, then
//                          acked (dropped). Retrying a request the server
//                          has rejected as malformed/oversized/unauthorized
//                          can never succeed, and with a single worker it
//                          would block every entry behind it: one oversized
//                          batch would stall every alert queued after it.
//   - transport / 5xx    → requeue + exponential backoff (1s → 60s, reset
//                          on the next success).
// The bearer token is sent only to URLs under `tokenUrlPrefix` so an
// enrollment token can never leak to a third-party SIEM destination.
// Per-entry headers (Content-Type, Splunk/ApiKey tokens, the lab-only
// insecure flag) ride along in the spool record; OAuth-protected URLs get
// their bearer token from registerOAuth() at send time (one refresh on a
// 401 before the entry counts as permanently rejected).
class PostWorker {
public:
    PostWorker() = default;
    ~PostWorker();

    // Configure the spool dir/cap and start the drain thread. Loads any
    // entries left by a previous run first. Safe to call at most once.
    void start(const std::string& spoolDir, size_t maxBytes,
               const std::string& tokenUrlPrefix = "",
               const std::string& token = "");

    // Queue a POST. `headerBlob` is the "Name: value\r\n" block produced by
    // makeHeaderBlock(). Returns false when the entry was refused (see
    // SpoolQueue::enqueue) or the worker was never started.
    bool enqueue(std::string url, std::string body, std::string headerBlob = "");

    // Register an OAuth2 client-credentials source for every URL starting
    // with `urlPrefix`. Idempotent (re-registering replaces the spec).
    void registerOAuth(const std::string& urlPrefix, OAuthSpec spec);

    // Stop the drain thread and join it. Entries still on disk are kept
    // for the next start.
    void stop();

    // Pending entries, including the one in flight.
    size_t pending() const { return m_spool.size(); }

    // Serialize request options into the spool header block, and back.
    // Content-Type travels as a header line; the insecure flag as the
    // pseudo-header "X-ELF-Insecure: 1" (stripped before sending).
    static std::string makeHeaderBlock(const std::string& contentType,
                                       const std::vector<std::pair<std::string, std::string>>& headers,
                                       bool insecure);
    static HttpRequestOptions parseHeaderBlock(const std::string& blob);

    // POST timeout per attempt. Short on purpose: the worker is single
    // threaded, so a slow server must not hold the queue for long.
    static constexpr int POST_TIMEOUT_MS = 5000;

private:
    void loop();
    // Returns a valid bearer token for `spec` (cached until shortly before
    // expiry), or "" with `err` set.
    std::string oauthToken(const std::string& prefix, const OAuthSpec& spec, std::string& err);

    SpoolQueue  m_spool;
    std::thread m_thread;
    std::string m_tokenUrlPrefix;
    std::string m_token;
    bool        m_started = false;
    std::atomic<bool> m_stopRequested{false};

    struct CachedToken {
        std::string token;
        std::chrono::steady_clock::time_point expiresAt;
    };
    std::mutex m_authMutex;
    std::vector<std::pair<std::string, OAuthSpec>> m_oauth;   // prefix → spec
    std::map<std::string, CachedToken> m_tokens;              // prefix → token
};

} // namespace elf
