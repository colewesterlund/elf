#pragma once

#include "Platform.h"   // wideToUtf8 / utf8ToWide live with the platform layer
#include <string>
#include <map>
#include <utility>
#include <vector>

namespace elf {

// Per-request options for the generic POST path (SIEM destinations).
//   contentType: e.g. application/json, application/x-ndjson,
//                 application/x-www-form-urlencoded
//   headers:     extra headers (Authorization: Splunk <t>, ApiKey, ...)
//   insecure:    ignore TLS certificate errors (self-signed lab SIEMs).
//                 Lab-only; the caller logs when it is enabled.
struct HttpRequestOptions {
    std::string contentType = "application/json";
    std::vector<std::pair<std::string, std::string>> headers;
    bool insecure = false;
};

// Minimal HTTP client, implemented per platform (WinHTTP on Windows, libcurl
// on Linux). Supports GET and POST with a JSON body. Used by AgentClient to
// talk to the management server and by the Forwarder for http:// destinations.
//
// All methods are synchronous. The agent calls them from worker threads, so
// blocking briefly is acceptable. Timeouts are conservative so a downed
// server doesn't hang the agent.
class HttpClient {
public:
    // Generic POST with explicit content type / headers / TLS options.
    // Used by the destination spool for SIEM endpoints and for OAuth token
    // requests. Status semantics as for post() below.
    static bool post(const std::string& url, const std::string& body,
                     const HttpRequestOptions& opts,
                     std::string& responseBody, std::string& errorMsg,
                     int timeoutMs = 15000, int* httpStatus = nullptr);

    // Build the CRLF-separated header block a request would send (exposed
    // for unit tests; the Authorization line is included verbatim).
    static std::string buildHeaderBlock(const HttpRequestOptions& opts, bool hasBody);
    // Perform a GET request. Returns the response body (UTF-8). On failure
    // sets `errorMsg` and returns false. `authToken` (optional) sends an
    // `Authorization: Bearer <token>` header for agent enrollment auth.
    // `httpStatus` (optional) receives the HTTP status code (0 when the
    // failure happened before a response arrived: DNS, connect, timeout).
    // Callers use it to tell a permanent rejection (4xx) from a transient
    // transport failure, which need opposite retry policies.
    static bool get(const std::string& url, std::string& responseBody,
                    std::string& errorMsg, int timeoutMs = 15000,
                    const std::string& authToken = "",
                    int* httpStatus = nullptr);

    // Perform a POST request with a JSON body. Returns the response body.
    // `authToken` (optional) sends an `Authorization: Bearer <token>` header.
    // `httpStatus` as for get().
    static bool post(const std::string& url, const std::string& jsonBody,
                     std::string& responseBody, std::string& errorMsg,
                     int timeoutMs = 15000,
                     const std::string& authToken = "",
                     int* httpStatus = nullptr);

    // True when an HTTP status means the server will never accept this
    // exact request, so retrying it is pointless: any 4xx except 408
    // (request timeout) and 429 (rate limited), which are transient. A
    // 5xx or a transport failure (status 0) is transient and worth a retry.
    static bool isPermanentFailure(int httpStatus);

private:
    // Split a full URL into host, port, path, and scheme. Returns true on
    // success.
    static bool parseUrl(const std::string& url, std::string& scheme,
                         std::string& host, int& port, std::string& path);

    // Core request routine shared by GET and POST.
    static bool request(const std::string& method, const std::string& url,
                        const std::string& body, const HttpRequestOptions& opts,
                        std::string& responseBody, std::string& errorMsg,
                        int timeoutMs, int* httpStatus);
};

} // namespace elf
