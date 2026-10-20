// libcurl implementation of HttpClient.
#include "HttpClient.h"
#include <curl/curl.h>
#include <algorithm>
#include <mutex>

namespace elf {

namespace {

struct CurlInit {
    CurlInit() { curl_global_init(CURL_GLOBAL_DEFAULT); }
    ~CurlInit() { curl_global_cleanup(); }
};

void ensureInit() {
    static CurlInit init;
}

size_t writeBody(char* ptr, size_t size, size_t nmemb, void* userdata) {
    static_cast<std::string*>(userdata)->append(ptr, size * nmemb);
    return size * nmemb;
}

} // namespace

#ifndef ELF_AGENT_VERSION
#define ELF_AGENT_VERSION "dev"
#endif

bool HttpClient::parseUrl(const std::string& url, std::string& scheme,
                          std::string& host, int& port, std::string& path) {
    auto schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return false;
    scheme = url.substr(0, schemeEnd);
    std::string rest = url.substr(schemeEnd + 3);
    auto slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    path = (slash == std::string::npos) ? "/" : rest.substr(slash);
    port = (scheme == "https") ? 443 : 80;
    auto colon = hostport.find(':');
    if (colon != std::string::npos) {
        host = hostport.substr(0, colon);
        try { port = std::stoi(hostport.substr(colon + 1)); } catch (...) { return false; }
    } else {
        host = hostport;
    }
    return !host.empty();
}

std::string HttpClient::buildHeaderBlock(const HttpRequestOptions& opts, bool hasBody) {
    std::string h;
    if (hasBody && !opts.contentType.empty()) h += "Content-Type: " + opts.contentType + "\r\n";
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
    ensureInit();
    CURL* curl = curl_easy_init();
    if (!curl) { errorMsg = "curl_easy_init failed"; return false; }

    responseBody.clear();
    curl_slist* headers = nullptr;
    if (!body.empty() && !opts.contentType.empty())
        headers = curl_slist_append(headers, ("Content-Type: " + opts.contentType).c_str());
    for (const auto& kv : opts.headers) {
        if (!kv.first.empty()) headers = curl_slist_append(headers, (kv.first + ": " + kv.second).c_str());
    }
    if (method == "POST") {
        // libcurl adds "Expect: 100-continue" to bodies over 1 MB and waits
        // up to a second for a reply the console and most SIEM endpoints
        // never send; the WinHTTP transport never sends Expect either.
        headers = curl_slist_append(headers, "Expect:");
    }
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ELF-Agent/" ELF_AGENT_VERSION);
    // Same shape as the WinHTTP timeouts: one limit for the connect, then
    // an inactivity limit on the transfer rather than a cap on the whole
    // request, so a large batch on a slow link is not cut off mid-upload.
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeoutMs));
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 1L);
    curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, static_cast<long>(std::max(1, timeoutMs / 1000)));
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeoutMs) * 4);
    // WinHTTP follows redirects by default; match it (http -> https behind
    // a proxy, trailing-slash redirects).
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writeBody);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &responseBody);
    if (headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    if (method == "POST") {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.data());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    }
    if (opts.insecure && scheme == "https") {
        // Lab-only: the destination parser logs when this is enabled.
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    if (httpStatus) *httpStatus = static_cast<int>(status);
    if (headers) curl_slist_free_all(headers);
    if (rc != CURLE_OK) {
        errorMsg = std::string("curl: ") + curl_easy_strerror(rc);
        curl_easy_cleanup(curl);
        return false;
    }
    curl_easy_cleanup(curl);
    if (status < 200 || status >= 300) {
        errorMsg = "HTTP " + std::to_string(status) + " from " + url;
        return false;
    }
    return true;
}

static HttpRequestOptions bearerOptions(const std::string& authToken) {
    HttpRequestOptions o;
    if (!authToken.empty()) o.headers.emplace_back("Authorization", "Bearer " + authToken);
    return o;
}

bool HttpClient::get(const std::string& url, std::string& responseBody,
                     std::string& errorMsg, int timeoutMs,
                     const std::string& authToken, int* httpStatus) {
    return request("GET", url, "", bearerOptions(authToken), responseBody, errorMsg, timeoutMs, httpStatus);
}

bool HttpClient::post(const std::string& url, const std::string& jsonBody,
                      std::string& responseBody, std::string& errorMsg,
                      int timeoutMs, const std::string& authToken, int* httpStatus) {
    return request("POST", url, jsonBody, bearerOptions(authToken), responseBody, errorMsg, timeoutMs, httpStatus);
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
