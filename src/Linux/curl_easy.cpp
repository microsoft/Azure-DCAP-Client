// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define NOMINMAX // tell windows NOT to define "min" and "max" macros
#define _CRT_SECURE_NO_WARNINGS // no strncpy_s on Linux, allow use of strcpy

#include "curl_easy.h"
#include <cassert>
#include <cstring>
#include <limits>
#include <locale>
#include "private.h"

#ifdef __LINUX__
#include <openssl/err.h>
#include <openssl/ssl.h>
#else
#include <PathCch.h>
#include <shlwapi.h>
#include <strsafe.h>
#endif

///////////////////////////////////////////////////////////////////////////////
// Local Helper Functions
///////////////////////////////////////////////////////////////////////////////
static std::string to_lower(const std::string& inout)
{
    const std::locale loc;
    std::string retval = inout;
    for (auto& c : retval)
    {
        c = std::tolower(c, loc);
    }

    return inout;
}

// OWS is defined in RFC 7230 as "OWS = *( SP / HTAB )"
static bool is_optional_whitespace(char c)
{
    return c == ' ' || c == '\t';
}

static bool is_http_version(const char* buffer, size_t buffer_size)
{
    static constexpr char HTTP_VERSION[] = "HTTP/1.1";
    return buffer_size >= sizeof(HTTP_VERSION) - 1 &&
           0 == memcmp(buffer, HTTP_VERSION, sizeof(HTTP_VERSION) - 1);
}

///////////////////////////////////////////////////////////////////////////////
// curl_easy::Error implementation
///////////////////////////////////////////////////////////////////////////////
curl_easy::error::error(CURLcode c, const char* f) : code(c)
{
    if (f == nullptr)
    {
        f = "<unknown function>";
    }

    strncpy(function, f, sizeof(function));
    function[sizeof(function) - 1] = 0;
}

char const* curl_easy::error::what() const noexcept
{
    return function;
}

///////////////////////////////////////////////////////////////////////////////
// curl_easy implementation
///////////////////////////////////////////////////////////////////////////////
std::unique_ptr<curl_easy> curl_easy::create(const std::string& url, const std::string* const p_body, LPCWSTR httpVerb))
{
    std::unique_ptr<curl_easy> easy(new curl_easy);

    easy->handle = curl_easy_init();
    if (easy->handle == nullptr)
    {
        // CURL does not document what null actually means other than "it's
        // bad". Assuming OOM.
        throw std::bad_alloc();
    }

    easy->set_opt_or_throw(CURLOPT_URL, url.c_str());
    easy->set_opt_or_throw(CURLOPT_WRITEFUNCTION, &write_callback);
    easy->set_opt_or_throw(CURLOPT_WRITEDATA, easy.get());
    easy->set_opt_or_throw(CURLOPT_HEADERFUNCTION, &header_callback);
    easy->set_opt_or_throw(CURLOPT_HEADERDATA, easy.get());
    easy->set_opt_or_throw(CURLOPT_FAILONERROR, 1L);
    easy->set_opt_or_throw(CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);

    if (p_body != nullptr && !p_body->empty())
    {
        if (lstrcmpW(httpVerb, L"POST"))
        {
            easy->set_opt_or_throw(CURLOPT_POST, 1L);
        }
        else {
            easy->set_opt_or_throw(CURLOPT_HTTPGET, 1L);
        }
        easy->set_opt_or_throw(CURLOPT_COPYPOSTFIELDS, p_body->c_str());
    }

#if !defined(__LINUX__)
    // The version of LibCURL we were built with was built with OpenSSL, not WinSSL. As a result, we need to
    // inform LibCURL where to find the trusted list of root CAs. We assume it is in a file named "curl-ca-bundle.crt"
    // in the directory which holds the dcap provider DLL.
    extern HINSTANCE moduleHandle;
    char fileNameBuffer[MAX_PATH];
    if (GetModuleFileNameA(moduleHandle, fileNameBuffer, _countof(fileNameBuffer)) == 0)
    {
        throw std::exception("Unable to retrieve module name.");
    }
    if (!PathRemoveFileSpecA(fileNameBuffer))
    {
        throw std::exception("Unable to remove filename from buffer.");
    }
    if (FAILED(StringCchCatA(fileNameBuffer, _countof(fileNameBuffer), "\\curl-ca-bundle.crt")))
    {
        throw std::exception("Unable to append CA bundle name");
    }

    easy->set_opt_or_throw(CURLOPT_CAINFO, fileNameBuffer);
#endif

    return easy;
}

curl_easy::~curl_easy()
{
    curl_easy_cleanup(handle);
}

void curl_easy::perform() const
{
    CURLcode result = curl_easy_perform(handle);
    if (result == CURLE_HTTP_RETURNED_ERROR)
    {
        long http_code = 0;
        curl_easy_getinfo (handle, CURLINFO_RESPONSE_CODE, &http_code);
        log(SGX_QL_LOG_ERROR, "HTTP error (%zd)", http_code);
    }
    throw_on_error(result, "curl_easy_perform");
}

const std::vector<uint8_t>& curl_easy::get_body() const
{
    return body;
}

const std::string* curl_easy::get_header(const std::string& field_name) const
{
    const std::string lower_field_name = to_lower(field_name);
    const auto field_iter = headers.find(lower_field_name);
    return field_iter == headers.end() ? nullptr : &field_iter->second;
}

void curl_easy::set_headers(const std::map<std::string, std::string>& header_name_values)
{
    struct curl_slist *headers = NULL;
    for (auto kvp : header_name_values)
    {
        std::string header = kvp.first + ":" + kvp.second;
        headers = curl_slist_append(headers, header.c_str());
    }
    set_opt_or_throw(CURLOPT_HTTPHEADER, headers);
}

std::string curl_easy::unescape(const std::string& encoded) const
{
    int decoded_size = 0;
    char* decoded = curl_easy_unescape(
        handle,
        encoded.c_str(),
        static_cast<uint32_t>(encoded.size()),
        &decoded_size);

    std::string decoded_str(decoded, decoded_size);
    curl_free(decoded);
    return decoded_str;
}

std::string curl_easy::escape(const char *unescaped, int length)
{
    char* escaped = curl_escape(unescaped, length);
    if (!escaped)
    {
        throw std::bad_alloc();
    }
    std::string escaped_str(escaped);
    curl_free(escaped);
    return escaped_str;
}

#pragma warning(suppress : 25033) // CURL defines input buffers as non-const
size_t curl_easy::write_callback(
    char* ptr,
    size_t size,
    size_t nmemb,
    void* user_data)
{
    // CURL promises that the total size will never be greater than
    // CURL_MAX_WRITE_SIZE.
    if (size > CURL_MAX_WRITE_SIZE || nmemb > CURL_MAX_WRITE_SIZE)
    {
        log(SGX_QL_LOG_ERROR, "Write callback buffer size is too large");
        return 0;
    }

    static_assert(
        CURL_MAX_WRITE_SIZE * CURL_MAX_WRITE_SIZE <
            std::numeric_limits<size_t>::max(),
        "Possible integer overflow.");

    try
    {
        const size_t full_size = size * nmemb;
        auto self = static_cast<curl_easy*>(user_data);
        self->body.insert(self->body.end(), ptr, ptr + full_size);
        return full_size;
    }
    catch (std::bad_alloc&)
    {
        return 0;
    }
}

#pragma warning(suppress : 25033) // CURL defines input buffers as non-const
size_t curl_easy::header_callback(
    char* buffer,
    size_t size,
    size_t nitems,
    void* user_data)
{
    // CURL promises that the total size will never be greater than
    // CURL_MAX_WRITE_SIZE.
    if (size > CURL_MAX_HTTP_HEADER || nitems > CURL_MAX_HTTP_HEADER)
    {
        log(SGX_QL_LOG_ERROR, "Header callback buffer size is too large");
        return 0;
    }

    const size_t buffer_size = size * nitems;

    // the string should end with CRLF
    if (buffer_size < 2 || buffer[buffer_size - 1] != '\n' ||
        buffer[buffer_size - 2] != '\r')
    {
        log(SGX_QL_LOG_ERROR, "Header data not properly terminated with CRLF.");
        return 0;
    }

    // CURL likes to pass the header/body separator line as a header (CRLF).
    // Just
    // skip it.
    if (buffer_size == 2)
    {
        return buffer_size;
    }

    // look for the delimiter
    size_t field_name_end_index = 0;
    while (field_name_end_index < buffer_size &&
           buffer[field_name_end_index] != ':')
    {
        ++field_name_end_index;
    }

    if (field_name_end_index >= buffer_size)
    {
        // CURL, for some reason, considers the status line a "header". Skip it
        // if we encounter it.
        return is_http_version(buffer, buffer_size) ? buffer_size : 0;
    }

    // next, find the start of the header data
    size_t content_start_index = field_name_end_index + 1;
    while (content_start_index < buffer_size &&
           is_optional_whitespace(buffer[content_start_index]))
    {
        ++content_start_index;
    }

    if (content_start_index >= buffer_size)
    {
        log(SGX_QL_LOG_ERROR, "Header is empty.");
        return 0;
    }

    // last, find the end of the header data (skip CRLF)
    size_t content_end_index = buffer_size - 2;
    while (content_end_index > content_start_index &&
           is_optional_whitespace(buffer[content_end_index]))
    {
        --content_end_index;
    }

    if (content_end_index <= content_start_index)
    {
        log(SGX_QL_LOG_ERROR, "Header delimiter is missing.");
        return 0;
    }

    const std::string field_name =
        to_lower(std::string(buffer, field_name_end_index));
    const std::string content(
        buffer + content_start_index, content_end_index - content_start_index);

    static_cast<curl_easy*>(user_data)->headers[field_name] = content;

    return buffer_size;
}

void curl_easy::throw_on_error(CURLcode code, const char* function)
{
    if (code != CURLE_OK)
    {
        log(SGX_QL_LOG_ERROR,
            "Encountered CURL error %d in %s",
            code,
            function);

        if (code == CURLE_OUT_OF_MEMORY)
        {
            throw std::bad_alloc();
        }

        throw curl_easy::error(code, function);
    }
}
