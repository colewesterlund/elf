#include "SpoolQueue.h"
#include "Console.h"
#include "HttpClient.h"
#include "Platform.h"
#include <nlohmann/json.hpp>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <cctype>
#include <cstring>

namespace elf {

SpoolQueue::~SpoolQueue() {
    stop();
}

void SpoolQueue::setDirectory(const std::string& dir, size_t maxBytes) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_dir = dir;
    if (!m_dir.empty() && m_dir.back() != '\\' && m_dir.back() != '/') {
        m_dir += platformPathSep();
    }
    m_maxBytes = maxBytes;
    std::error_code ec;
    std::filesystem::create_directories(m_dir, ec);
    if (ec) {
        logError("[SpoolQueue] Could not create spool directory '" +
                 m_dir + "': " + ec.message());
    }
}

std::string SpoolQueue::filePath(uint64_t seq) const {
    // Zero-pad to 20 digits so filenames sort lexicographically in the
    // same order as the sequence numbers (important for load()).
    char name[32];
    std::snprintf(name, sizeof(name), "%020llu.spool",
                  static_cast<unsigned long long>(seq));
    return m_dir + name;
}

// Write a 4-byte big-endian length + the bytes to an ostream.
static void writeLenPrefixed(std::ofstream& f, const std::string& s) {
    uint32_t len = static_cast<uint32_t>(s.size());
    char hdr[4];
    hdr[0] = (len >> 24) & 0xFF;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8)  & 0xFF;
    hdr[3] =  len        & 0xFF;
    f.write(hdr, 4);
    if (len) f.write(s.data(), len);
}

// Read a 4-byte big-endian length, then that many bytes, from an istream.
static bool readLenPrefixed(std::ifstream& f, std::string& out) {
    char hdr[4];
    f.read(hdr, 4);
    if (!f || f.gcount() != 4) return false;
    uint32_t len = (static_cast<uint8_t>(hdr[0]) << 24) |
                  (static_cast<uint8_t>(hdr[1]) << 16) |
                  (static_cast<uint8_t>(hdr[2]) << 8)  |
                   static_cast<uint8_t>(hdr[3]);
    out.resize(len);
    if (len) {
        f.read(&out[0], len);
        if (!f || f.gcount() != static_cast<std::streamsize>(len)) return false;
    }
    return true;
}

int SpoolQueue::load() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dir.empty()) return 0;
    int loaded = 0;
    std::error_code ec;
    std::vector<std::filesystem::path> files;
    for (auto& entry : std::filesystem::directory_iterator(m_dir, ec)) {
        auto ext = entry.path().extension();
        if (ext == ".spool") {
            files.push_back(entry.path());
        } else if (ext == ".tmp") {
            // A crash mid-enqueue leaves a half-written temp file. It was
            // never queued, so it's safe (and tidy) to delete.
            std::filesystem::remove(entry.path(), ec);
        }
    }
    // Sort by filename (which sorts by sequence number because of zero-pad).
    std::sort(files.begin(), files.end());
    for (const auto& path : files) {
        uint64_t seq = 0;
        try {
            seq = std::stoull(path.stem().string());
        } catch (...) {
            // Not a valid spool file; skip.
            continue;
        }
        m_seqQueue.push_back(seq);
        m_curBytes += static_cast<size_t>(
            std::filesystem::file_size(path, ec));
        ++loaded;
        if (seq >= m_nextSeq) m_nextSeq = seq + 1;
    }
    if (loaded > 0) {
        logInfo("[SpoolQueue] Loaded " + std::to_string(loaded) +
                " pending POST(s) from disk (" +
                std::to_string(m_curBytes / 1024) + " KB).");
    }
    return loaded;
}

size_t SpoolQueue::removeFile(uint64_t seq) {
    std::string path = filePath(seq);
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    size_t bytes = ec ? 0 : static_cast<size_t>(sz);
    std::filesystem::remove(path, ec);
    if (ec) {
        // The file could not be deleted (e.g. an AV scanner holds it open).
        // Still release its bytes from the running total: otherwise the
        // eviction loop would keep evicting other entries to make room for
        // a file it can never remove, draining the whole spool.
        logError("[SpoolQueue] Could not remove spool file '" + path +
                 "': " + ec.message());
    }
    m_curBytes = (m_curBytes >= bytes) ? m_curBytes - bytes : 0;
    return bytes;
}

void SpoolQueue::evictIfNeeded() {
    if (m_maxBytes == 0) return;  // unbounded
    size_t evicted = 0, evictedBytes = 0;
    while (m_curBytes > m_maxBytes && !m_seqQueue.empty()) {
        uint64_t oldest = m_seqQueue.front();
        m_seqQueue.pop_front();
        evictedBytes += removeFile(oldest);
        ++evicted;
    }
    if (evicted > 0) {
        // One line per batch, not per entry: an outage that evicts
        // thousands of entries must not also flood the error log.
        logError("[SpoolQueue] Evicted " + std::to_string(evicted) +
                 " oldest pending POST(s) (" + std::to_string(evictedBytes / 1024) +
                 " KB) to stay under the " + std::to_string(m_maxBytes / (1024 * 1024)) +
                 " MB spool cap.");
    }
}

static const char kSpoolMagic[4] = {'E', 'L', 'F', '2'};

bool SpoolQueue::enqueue(std::string url, std::string body) {
    return enqueue(std::move(url), std::string(), std::move(body));
}

bool SpoolQueue::enqueue(std::string url, std::string headers, std::string body) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_dir.empty()) return false;
    if (url.empty()) {
        logError("[SpoolQueue] Refusing to spool a POST with an empty URL.");
        return false;
    }
    // magic + three length-prefixed fields
    size_t entryBytes = 4 + url.size() + headers.size() + body.size() + 12;
    if (m_maxBytes > 0 && entryBytes > m_maxBytes / 2) {
        // A body this large would evict every other pending entry to make
        // room for itself (and might not fit at all). Drop it loudly; the
        // producers chunk their batches so this should never happen.
        logError("[SpoolQueue] Refusing to spool a " + std::to_string(entryBytes / 1024) +
                 " KB POST to " + url + " (larger than half the " +
                 std::to_string(m_maxBytes / (1024 * 1024)) + " MB cap); dropped.");
        return false;
    }
    uint64_t seq = m_nextSeq++;
    std::string path = filePath(seq);
    std::string tmp = path + ".tmp";
    {
        std::ofstream f(tmp, std::ios::out | std::ios::binary | std::ios::trunc);
        if (!f.is_open()) {
            logError("[SpoolQueue] Could not open spool temp '" + tmp + "'.");
            return false;
        }
        f.write(kSpoolMagic, 4);
        writeLenPrefixed(f, url);
        writeLenPrefixed(f, headers);
        writeLenPrefixed(f, body);
    }
    // Atomic rename so a crash never leaves a half-written spool file that
    // load() would try to parse.
    std::error_code ec;
    std::filesystem::rename(tmp, path, ec);
    if (ec) {
        // rename can fail if the target exists on some filesystems; fall
        // back to copy + remove.
        std::filesystem::copy_file(tmp, path,
            std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            logError("[SpoolQueue] Failed to finalize spool file: " +
                     ec.message());
            std::filesystem::remove(tmp, ec);
            return false;
        }
        std::filesystem::remove(tmp, ec);
    }
    m_curBytes += entryBytes;
    m_seqQueue.push_back(seq);
    evictIfNeeded();
    m_cv.notify_one();
    return true;
}

// Read exactly `len` bytes.
static bool readBytes(std::ifstream& f, uint32_t len, std::string& out) {
    out.resize(len);
    if (len) {
        f.read(&out[0], len);
        if (!f || f.gcount() != static_cast<std::streamsize>(len)) return false;
    }
    return true;
}

bool SpoolQueue::dequeue(uint64_t& id, std::string& url, std::string& headers,
                         std::string& body) {
    std::unique_lock<std::mutex> lock(m_mutex);
    while (true) {
        m_cv.wait(lock, [this] { return m_stopping || !m_seqQueue.empty(); });
        // Stopping wins even with work queued: the entries are on disk and
        // will be sent on the next start. Draining first would make a
        // shutdown with the server down never finish (every failed POST
        // re-queues its entry), and the SCM would hard-kill the service.
        if (m_stopping) return false;
        uint64_t seq = m_seqQueue.front();
        m_seqQueue.pop_front();
        std::string path = filePath(seq);
        // Read the file under the lock. The file is small (a POST body),
        // so holding the lock for the read is fine.
        std::ifstream f(path, std::ios::in | std::ios::binary);
        bool ok = f.is_open();
        headers.clear();
        if (ok) {
            char head[4] = {0};
            f.read(head, 4);
            ok = f && f.gcount() == 4;
            if (ok && std::memcmp(head, kSpoolMagic, 4) == 0) {
                // v2: magic, url, headers, body
                ok = readLenPrefixed(f, url) && readLenPrefixed(f, headers) &&
                     readLenPrefixed(f, body);
            } else if (ok) {
                // v1 (older build): the 4 bytes are the URL length.
                uint32_t len = (static_cast<uint8_t>(head[0]) << 24) |
                               (static_cast<uint8_t>(head[1]) << 16) |
                               (static_cast<uint8_t>(head[2]) << 8)  |
                                static_cast<uint8_t>(head[3]);
                ok = readBytes(f, len, url) && readLenPrefixed(f, body);
            }
            f.close();
        }
        if (!ok || url.empty()) {
            // Unreadable, corrupt, or malformed (empty URL): nothing we can
            // ever send. Delete it and move on to the next entry. Returning
            // it would make the worker POST to "" forever.
            logError("[SpoolQueue] Dropping unreadable/corrupt spool entry '" +
                     path + "'.");
            removeFile(seq);
            url.clear();
            headers.clear();
            body.clear();
            continue;
        }
        m_inFlight.insert(seq);
        id = seq;
        return true;
    }
}

bool SpoolQueue::dequeue(uint64_t& id, std::string& url, std::string& body) {
    std::string headers;
    return dequeue(id, url, headers, body);
}

bool SpoolQueue::dequeue(std::string& url, std::string& body) {
    uint64_t id = 0;
    if (!dequeue(id, url, body)) return false;
    ack(id);
    return true;
}

void SpoolQueue::ack(uint64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_inFlight.erase(id) == 0) return;  // unknown id: nothing to do
    removeFile(id);
}

void SpoolQueue::requeue(uint64_t id) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_inFlight.erase(id) == 0) return;
    // Front, not back: the entry keeps its place in FIFO order, is retried
    // first, and (being the oldest) is the first evicted if the cap is hit
    // while the server stays down.
    m_seqQueue.push_front(id);
    m_cv.notify_one();
}

void SpoolQueue::stop() {
    m_stopping.store(true);
    m_cv.notify_all();
}

size_t SpoolQueue::size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_seqQueue.size() + m_inFlight.size();
}

// --- PostWorker -------------------------------------------------------------

PostWorker::~PostWorker() {
    stop();
}

void PostWorker::start(const std::string& spoolDir, size_t maxBytes,
                       const std::string& tokenUrlPrefix,
                       const std::string& token) {
    if (m_started) return;
    m_tokenUrlPrefix = tokenUrlPrefix;
    m_token = token;
    m_spool.setDirectory(spoolDir, maxBytes);
    m_spool.load();
    m_started = true;
    m_thread = std::thread([this] {
        runGuarded("post-worker", [this] { loop(); });
    });
}

bool PostWorker::enqueue(std::string url, std::string body, std::string headerBlob) {
    if (!m_started) return false;
    return m_spool.enqueue(std::move(url), std::move(headerBlob), std::move(body));
}

void PostWorker::registerOAuth(const std::string& urlPrefix, OAuthSpec spec) {
    std::lock_guard<std::mutex> lock(m_authMutex);
    for (auto& p : m_oauth) {
        if (p.first == urlPrefix) {
            p.second = std::move(spec);
            m_tokens.erase(urlPrefix);
            return;
        }
    }
    m_oauth.emplace_back(urlPrefix, std::move(spec));
}

std::string PostWorker::makeHeaderBlock(
        const std::string& contentType,
        const std::vector<std::pair<std::string, std::string>>& headers,
        bool insecure) {
    std::string blob;
    if (!contentType.empty()) blob += "Content-Type: " + contentType + "\r\n";
    for (const auto& kv : headers) {
        if (kv.first.empty()) continue;
        blob += kv.first + ": " + kv.second + "\r\n";
    }
    if (insecure) blob += "X-ELF-Insecure: 1\r\n";
    return blob;
}

HttpRequestOptions PostWorker::parseHeaderBlock(const std::string& blob) {
    HttpRequestOptions o;
    size_t pos = 0;
    while (pos < blob.size()) {
        size_t eol = blob.find("\r\n", pos);
        std::string line = blob.substr(pos, eol == std::string::npos ? std::string::npos : eol - pos);
        pos = (eol == std::string::npos) ? blob.size() : eol + 2;
        auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        std::string name = line.substr(0, colon);
        std::string value = line.substr(colon + 1);
        while (!value.empty() && value.front() == ' ') value.erase(value.begin());
        std::string lower = name;
        std::transform(lower.begin(), lower.end(), lower.begin(),
            [](unsigned char c) { return static_cast<char>(::tolower(c)); });
        if (lower == "content-type") o.contentType = value;
        else if (lower == "x-elf-insecure") o.insecure = (value == "1");
        else o.headers.emplace_back(name, value);
    }
    return o;
}

static std::string formEncode(const std::string& s) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    for (unsigned char c : s) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') out += static_cast<char>(c);
        else { out += '%'; out += hex[c >> 4]; out += hex[c & 15]; }
    }
    return out;
}

std::string PostWorker::oauthToken(const std::string& prefix, const OAuthSpec& spec,
                                   std::string& err) {
    {
        std::lock_guard<std::mutex> lock(m_authMutex);
        auto it = m_tokens.find(prefix);
        if (it != m_tokens.end() && std::chrono::steady_clock::now() < it->second.expiresAt) {
            return it->second.token;
        }
    }
    // Client-credentials grant. Runs on the worker thread only.
    std::string form = "grant_type=client_credentials&client_id=" + formEncode(spec.clientId) +
                       "&client_secret=" + formEncode(spec.clientSecret) +
                       "&scope=" + formEncode(spec.scope);
    HttpRequestOptions o;
    o.contentType = "application/x-www-form-urlencoded";
    std::string resp;
    int status = 0;
    if (!HttpClient::post(spec.tokenUrl, form, o, resp, err, 10000, &status)) {
        err = "OAuth token request failed (" + err + "): " + resp.substr(0, 200);
        return "";
    }
    try {
        auto j = nlohmann::json::parse(resp);
        std::string tok = j.value("access_token", "");
        long long ttl = j.value("expires_in", 3600LL);
        if (tok.empty()) { err = "OAuth response had no access_token"; return ""; }
        std::lock_guard<std::mutex> lock(m_authMutex);
        // Refresh five minutes early so a token never expires mid-batch.
        m_tokens[prefix] = {tok, std::chrono::steady_clock::now() +
                                     std::chrono::seconds((std::max)(ttl - 300, 60LL))};
        return tok;
    } catch (const std::exception& e) {
        err = std::string("OAuth response parse failed: ") + e.what();
        return "";
    }
}

void PostWorker::stop() {
    m_stopRequested.store(true);
    m_spool.stop();
    if (m_thread.joinable()) m_thread.join();
}

void PostWorker::loop() {
    using namespace std::chrono;
    int backoffMs = 1000;
    uint64_t authRetriedId = 0;   // entry that already got one token refresh
    while (true) {
        uint64_t id = 0;
        std::string url, headerBlob, body;
        if (!m_spool.dequeue(id, url, headerBlob, body)) return;  // stopped
        HttpRequestOptions opts = parseHeaderBlock(headerBlob);
        // Only the management server gets the enrollment token; a SIEM
        // destination must never see it.
        const bool sendToken = !m_token.empty() && !m_tokenUrlPrefix.empty() &&
                               url.rfind(m_tokenUrlPrefix, 0) == 0;
        if (sendToken) opts.headers.emplace_back("Authorization", "Bearer " + m_token);
        // OAuth-protected destination (Sentinel): bearer token at send time.
        std::string oauthPrefix;
        OAuthSpec oauthSpec;
        {
            std::lock_guard<std::mutex> lock(m_authMutex);
            for (const auto& p : m_oauth) {
                if (url.rfind(p.first, 0) == 0) { oauthPrefix = p.first; oauthSpec = p.second; break; }
            }
        }
        if (!oauthPrefix.empty()) {
            std::string authErr;
            std::string tok = oauthToken(oauthPrefix, oauthSpec, authErr);
            if (tok.empty()) {
                // Can't authenticate right now (IdP unreachable, bad
                // secret): transient from the queue's point of view.
                logError("[PostWorker] " + authErr + " (retry in " +
                         std::to_string(backoffMs / 1000) + "s)");
                m_spool.requeue(id);
                for (int waited = 0; waited < backoffMs && !m_stopRequested.load(); waited += 100) {
                    std::this_thread::sleep_for(milliseconds(100));
                }
                backoffMs = (std::min)(backoffMs * 2, 60000);
                continue;
            }
            opts.headers.emplace_back("Authorization", "Bearer " + tok);
        }
        std::string resp, err;
        int status = 0;
        if (HttpClient::post(url, body, opts, resp, err, POST_TIMEOUT_MS, &status)) {
            m_spool.ack(id);
            backoffMs = 1000;  // success: reset backoff
            continue;
        }
        if (status == 401 && !oauthPrefix.empty() && authRetriedId != id) {
            // The cached token may have been revoked: fetch a fresh one and
            // retry this entry exactly once before treating 401 as permanent.
            { std::lock_guard<std::mutex> lock(m_authMutex); m_tokens.erase(oauthPrefix); }
            authRetriedId = id;
            m_spool.requeue(id);
            continue;
        }
        if (HttpClient::isPermanentFailure(status)) {
            // The server has rejected this exact request; it will never
            // succeed. Log enough to diagnose (status + the server's own
            // explanation) and drop it so the queue keeps moving.
            logError("[PostWorker] Dropping POST to " + url + ": HTTP " +
                     std::to_string(status) + " (body " +
                     std::to_string(body.size()) + " B); response: " +
                     resp.substr(0, 200));
            m_spool.ack(id);
            continue;
        }
        logError("[PostWorker] POST failed: " + err + " (retry in " +
                 std::to_string(backoffMs / 1000) + "s)");
        m_spool.requeue(id);
        // Sleep in short ticks so stop() interrupts a 60 s backoff.
        for (int waited = 0; waited < backoffMs && !m_stopRequested.load(); waited += 100) {
            std::this_thread::sleep_for(milliseconds(100));
        }
        backoffMs = (std::min)(backoffMs * 2, 60000);  // cap at 60s
    }
}

} // namespace elf
