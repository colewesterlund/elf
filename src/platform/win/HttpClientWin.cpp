#include "HttpClient.h"
#include <windows.h>
#include <winhttp.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "winhttp.lib")

namespace elf {

bool HttpClient::parseUrl(const std::string& url, std::string& scheme,
                          std::string& host, int& port, std::string& path) {
    // url = scheme://host[:port]/path
    auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return false;
    scheme = url.substr(0, schemeEnd);
    std::string rest = url.substr(schemeEnd + 3);

    auto slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : rest.substr(slash);

    // Default ports.
    port = (scheme == "https") ? 443 : 80;

    auto colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        try { port = std::stoi(hostport.substr(colon + 1)); }
        catch (...) { return false; }
    } else {
        host = hostport;
    }
    return !host.empty();
}

std::string HttpClient::buildHeaderBlock(const HttpRequestOptions& opts, bool hasBody) {
    std::string h;
    if (hasBody && !opts.contentType.empty()) {
        h += "Content-Type: " + opts.contentType + "\r\n";
    }
    for (const auto& kv : opts.headers) {
        if (kv.first.empty()) continue;
        h += kv.first + ": " + kv.second + "\r\n";
    }
    return h;
}

bool HttpClient::request(const std::string& method, const std::string& url,
                         const std::string& body, const HttpRequestOptions& opts,
                         std::string& responseBody, std::string& errorMsg,
                         int timeoutMs, int* httpStatus) {
    if (httpStatus) *httpStatus = 0;
    std::string scheme, host, path;
    int port = 80;
    if (!parseUrl(url, scheme, host, port, path)) {
        errorMsg = "Invalid URL: " + url;
        return false;
    }

    std::wstring whost = utf8ToWide(host);
    std::wstring wpath = utf8ToWide(path);
    std::wstring wmethod = utf8ToWide(method);

    // Open a session. The user agent is informational.
#ifndef ELF_AGENT_VERSION
#define ELF_AGENT_VERSION "dev"
#endif
    static const std::wstring kUserAgent = L"ELF-Agent/" + utf8ToWide(ELF_AGENT_VERSION);
    HINTERNET hSession = WinHttpOpen(kUserAgent.c_str(),
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        errorMsg = "WinHttpOpen failed: " + std::to_string(GetLastError());
        return false;
    }

    // Set timeouts: resolve, connect, send, receive.
    WinHttpSetTimeouts(hSession, timeoutMs, timeoutMs, timeoutMs, timeoutMs);

    // Connect to the host.
    HINTERNET hConnect = WinHttpConnect(hSession, whost.c_str(),
                                        (INTERNET_PORT)port, 0);
    if (!hConnect) {
        errorMsg = "WinHttpConnect failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Open the request.
    DWORD flags = (scheme == "https") ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, wmethod.c_str(), wpath.c_str(),
                                            nullptr, WINHTTP_NO_REFERER,
                                            WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hRequest) {
        errorMsg = "WinHttpOpenRequest failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Ask the server to gzip large responses (e.g. /config with thousands of
    // rules) and let WinHTTP decompress them transparently. Available on
    // Windows 8.1+ (WINHTTP_DECOMPRESSION_FLAG_GZIP). If the option is
    // unsupported (older OS), WinHttpSetOption fails harmlessly and we fall
    // back to an uncompressed response.
    DWORD decompress = WINHTTP_DECOMPRESSION_FLAG_GZIP;
    WinHttpSetOption(hRequest, WINHTTP_OPTION_DECOMPRESSION,
                     &decompress, sizeof(decompress));

    // Lab-only: accept self-signed / mismatched certificates on an https
    // SIEM endpoint. The destination parser logs when this is enabled.
    if (opts.insecure && scheme == "https") {
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));
    }

    // Headers: Content-Type for a body, plus whatever the caller supplied
    // (the enrollment Bearer token for the management server, a Splunk or
    // ApiKey token for a SIEM destination, ...).
    std::wstring headers = utf8ToWide(buildHeaderBlock(opts, !body.empty()));

    // Send the request.
    BOOL ok = WinHttpSendRequest(hRequest,
                                 headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                                 (DWORD)-1,
                                 body.empty() ? WINHTTP_NO_REQUEST_DATA : (LPVOID)body.data(),
                                 (DWORD)body.size(),
                                 (DWORD)body.size(), 0);
    if (!ok) {
        errorMsg = "WinHttpSendRequest failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Receive the response.
    if (!WinHttpReceiveResponse(hRequest, nullptr)) {
        errorMsg = "WinHttpReceiveResponse failed: " + std::to_string(GetLastError());
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return false;
    }

    // Read the status code.
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    if (httpStatus) *httpStatus = static_cast<int>(statusCode);

    // Read the body in chunks. A read failure mid-body must be reported as
    // a failure, not returned as success with a partial body: a truncated
    // /config response would otherwise be handed to the JSON parser (and
    // rejected as a whole) with a misleading "parse error" instead of the
    // real transport error.
    responseBody.clear();
    DWORD bytesAvailable = 0;
    DWORD readError = 0;
    do {
        bytesAvailable = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &bytesAvailable)) {
            readError = GetLastError();
            break;
        }
        if (bytesAvailable == 0) break;
        std::vector<char> chunk(bytesAvailable);
        DWORD bytesRead = 0;
        if (!WinHttpReadData(hRequest, chunk.data(), bytesAvailable, &bytesRead)) {
            readError = GetLastError();
            break;
        }
        responseBody.append(chunk.data(), bytesRead);
    } while (bytesAvailable > 0);

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    if (readError != 0) {
        errorMsg = "WinHttpReadData failed: " + std::to_string(readError) +
                   " after " + std::to_string(responseBody.size()) + " bytes";
        return false;
    }
    if (statusCode < 200 || statusCode >= 300) {
        errorMsg = "HTTP " + std::to_string(statusCode) + " from " + url;
        return false;
    }
    return true;
}

// Agent enrollment token (machine auth). Sent on every request to the
// management server when the agent has been issued a token by the install
// script. The server hashes it and compares to the stored hash; a
// missing/wrong token gets 401.
static HttpRequestOptions bearerOptions(const std::string& authToken) {
    HttpRequestOptions o;
    if (!authToken.empty()) o.headers.emplace_back("Authorization", "Bearer " + authToken);
    return o;
}

bool HttpClient::get(const std::string& url, std::string& responseBody,
                     std::string& errorMsg, int timeoutMs,
                     const std::string& authToken, int* httpStatus) {
    return request("GET", url, "", bearerOptions(authToken), responseBody, errorMsg,
                   timeoutMs, httpStatus);
}

bool HttpClient::post(const std::string& url, const std::string& jsonBody,
                      std::string& responseBody, std::string& errorMsg,
                      int timeoutMs, const std::string& authToken,
                      int* httpStatus) {
    return request("POST", url, jsonBody, bearerOptions(authToken), responseBody,
                   errorMsg, timeoutMs, httpStatus);
}

bool HttpClient::post(const std::string& url, const std::string& body,
                      const HttpRequestOptions& opts,
                      std::string& responseBody, std::string& errorMsg,
                      int timeoutMs, int* httpStatus) {
    return request("POST", url, body, opts, responseBody, errorMsg, timeoutMs, httpStatus);
}

bool HttpClient::isPermanentFailure(int httpStatus) {
    if (httpStatus < 400 || httpStatus >= 500) return false;
    return httpStatus != 408 && httpStatus != 429;
}

} // namespace elf
