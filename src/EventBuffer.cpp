#include "EventBuffer.h"

namespace elf {

void EventBuffer::push(const std::wstring& xml) {
    push(xml, std::chrono::system_clock::now());
}

void EventBuffer::push(const std::wstring& xml,
                       std::chrono::system_clock::time_point receivedAt) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_events.push_back({receivedAt, xml});
    // Track cumulative metrics: every event the host generates is pushed
    // here, so this is the denominator for the savings ratio. The byte count
    // uses the UTF-8 length of the XML (each wchar_t in the wide string is
    // encoded as 1-4 UTF-8 bytes).
    m_eventsCreated.fetch_add(1, std::memory_order_relaxed);
    // Approximate UTF-8 byte length: for typical Windows event XML (mostly
    // ASCII), the wide-string length is a close lower bound. We use the exact
    // byte count for ASCII chars and 2-4 for non-ASCII, computed cheaply.
    size_t bytes = 0;
    for (wchar_t c : xml) {
        if (c < 0x80) bytes += 1;
        else if (c < 0x800) bytes += 2;
        else if (c < 0x10000) bytes += 3;
        else bytes += 4;
    }
    m_bytesCreated.fetch_add(bytes, std::memory_order_relaxed);
}

void EventBuffer::trimTo(size_t maxEvents) {
    if (maxEvents == 0) return;  // 0 = unlimited
    std::lock_guard<std::mutex> lock(m_mutex);
    while (m_events.size() > maxEvents) {
        m_events.pop_front();
        m_frontPopped.fetch_add(1, std::memory_order_relaxed);
    }
}

void EventBuffer::cleanup(int retentionSeconds) {
    auto now = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(m_mutex);
    while (!m_events.empty()) {
        auto age = std::chrono::duration_cast<std::chrono::seconds>(
            now - m_events.front().receivedAt).count();
        if (age > retentionSeconds) {
            m_events.pop_front();
            m_frontPopped.fetch_add(1, std::memory_order_relaxed);
        } else {
            break;
        }
    }
}

std::vector<BufferedEvent> EventBuffer::snapshot() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::vector<BufferedEvent>(m_events.begin(), m_events.end());
}

std::vector<BufferedEvent> EventBuffer::snapshotFrom(size_t from, size_t& total) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    total = m_events.size();
    if (from >= m_events.size()) return {};
    return std::vector<BufferedEvent>(m_events.begin() + from, m_events.end());
}

std::vector<BufferedEvent> EventBuffer::snapshotFromAbsolute(uint64_t absFrom, uint64_t& absEnd,
                                                             bool trackEvicted) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    // Convert the absolute stream index to a live deque index by subtracting
    // the number of events popped from the front. If absFrom is below the
    // oldest surviving event, clamp to 0 (process everything still present)
    // and record how many events were lost before evaluation.
    uint64_t popped = m_frontPopped.load(std::memory_order_relaxed);
    absEnd = popped + m_events.size();
    if (trackEvicted && absFrom < popped) {
        m_evictedUnevaluated.fetch_add(popped - absFrom, std::memory_order_relaxed);
    }
    uint64_t liveFrom = (absFrom > popped) ? (absFrom - popped) : 0;
    if (liveFrom >= m_events.size()) return {};
    return std::vector<BufferedEvent>(m_events.begin() + static_cast<size_t>(liveFrom),
                                      m_events.end());
}

size_t EventBuffer::size() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_events.size();
}

} // namespace elf
