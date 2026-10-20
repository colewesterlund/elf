#include "EventQueryCollector.h"
#include "EventRender.h"
#include "HttpClient.h"
#include "Console.h"
#include <iostream>
#include <vector>

#pragma comment(lib, "wevtapi.lib")

namespace elf {

// Page size for EvtNext. 100 balances memory and the number of round-trips
// for large pulls.
static constexpr DWORD QUERY_PAGE_SIZE = 100;

size_t EventQueryCollector::collectChannel(const std::wstring& channelPath,
                                           const std::wstring& xpathQuery,
                                           EventCallback& cb) {
    EVT_HANDLE hQuery = EvtQuery(nullptr, channelPath.c_str(), xpathQuery.c_str(),
                                 EvtQueryChannelPath | EvtQueryForwardDirection);
    if (!hQuery) {
        DWORD err = GetLastError();
        // A malformed XPath fails on EVERY channel with ERROR_EVT_INVALID_QUERY
        // (15031). That's a bug in our query string, not a per-channel issue, so
        // log it once so it shows up in error.log instead of failing silently
        // across all channels. Per-channel rejections (analytic/debug channels
        // that must be enabled first, access denied, channel not found) stay
        // silent like the push subscriber.
        if (err == ERROR_EVT_INVALID_QUERY) {
            logError("[EventQueryCollector] EvtQuery rejected XPath as invalid on "
                     "channel '" + wideToUtf8(channelPath) + "' (err=" +
                     std::to_string(err) + "): " + wideToUtf8(xpathQuery));
        }
        return 0;
    }

    size_t count = 0;
    std::vector<EVT_HANDLE> events(QUERY_PAGE_SIZE);
    while (true) {
        DWORD returned = 0;
        BOOL ok = EvtNext(hQuery, QUERY_PAGE_SIZE, events.data(), 0, 0, &returned);
        if (!ok) {
            DWORD err = GetLastError();
            if (err == ERROR_NO_MORE_ITEMS) break;
            if (err == ERROR_INSUFFICIENT_BUFFER) {
                // Should not happen with INFINITE timeout, but grow if it does.
                continue;
            }
            // Other errors: abort this channel.
            break;
        }
        for (DWORD i = 0; i < returned; ++i) {
            std::wstring xml = renderEventXml(events[i]);
            if (!xml.empty()) {
                cb(xml);
                ++count;
            }
            EvtClose(events[i]);
        }
    }
    EvtClose(hQuery);
    return count;
}

size_t EventQueryCollector::collect(const std::string& startTimeIsoUtc,
                                    EventCallback cb) {
    // Build the time-bounded XPath. Windows Event Log SystemTime is UTC, so
    // the caller must pass a UTC ISO-8601 string. The query matches every
    // event whose TimeCreated is >= the start time.
    // e.g. *[System[TimeCreated[@SystemTime >= '2026-10-01T00:00:00.000Z']]]
    // Three opening '[' must be balanced by three closing ']'.
    std::wstring startWide(startTimeIsoUtc.begin(), startTimeIsoUtc.end());
    std::wstring xpath = L"*[System[TimeCreated[@SystemTime >= '"
                        + startWide + L"']]]";


    // Enumerate all channels (same pattern as EventCollector::subscribeAll)
    // and run the query against each.
    EVT_HANDLE hChannels = EvtOpenChannelEnum(nullptr, 0);
    if (!hChannels) {
        logError("[EventQueryCollector] EvtOpenChannelEnum failed: " +
                 std::to_string(GetLastError()));
        return 0;
    }

    size_t total = 0;
    int channels = 0;
    int channelsWithEvents = 0;
    LPWSTR path = nullptr;
    DWORD bufSize = 0, bufUsed = 0;

    while (true) {
        if (!EvtNextChannelPath(hChannels, bufSize, path, &bufUsed)) {
            DWORD err = GetLastError();
            if (err == ERROR_INSUFFICIENT_BUFFER) {
                bufSize = bufUsed;
                free(path);
                path = (LPWSTR)malloc(bufSize * sizeof(WCHAR));
                if (!path) break;
                continue;
            }
            break;
        }
        ++channels;
        size_t got = collectChannel(std::wstring(path), xpath, cb);
        if (got > 0) ++channelsWithEvents;
        total += got;
        free(path);
        path = nullptr;
        bufSize = 0;
    }
    if (path) free(path);
    EvtClose(hChannels);

    logInfo("[EventQueryCollector] Collected " + std::to_string(total) +
            " event(s) from " + std::to_string(channelsWithEvents) + "/" +
            std::to_string(channels) + " channel(s) (start=" + startTimeIsoUtc +
            ").");
    return total;
}

} // namespace elf
