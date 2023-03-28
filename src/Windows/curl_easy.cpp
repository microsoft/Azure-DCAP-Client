// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "curl_easy.h"
#include <cassert>
#include <cstring>
#include <ios>
#include <sstream>
#include <limits>
#include <locale>
#include "private.h"

#include <PathCch.h>
#include <shlwapi.h>
#include <strsafe.h>

///////////////////////////////////////////////////////////////////////////////
// Constants
///////////////////////////////////////////////////////////////////////////////
static constexpr int maximum_retries = 5;
static constexpr int initial_retry_delay_ms = 20;
static constexpr WCHAR content_type_header[] =
    L"Content-Type: application/json";

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

    return retval;
}

///////////////////////////////////////////////////////////////////////////////
// curl_easy::Error implementation
///////////////////////////////////////////////////////////////////////////////
curl_easy::error::error(DWORD c, const char* f) : code(c)
{
    if (f == nullptr)
    {
        f = "<unknown function>";
    }

    strncpy_s(function, f, sizeof(function));
    function[sizeof(function) - 1] = 0;
}

char const* curl_easy::error::what() const noexcept
{
    return function;
}

std::string Utf8StringFromUnicodeString(const std::wstring& unicodeString)
{
    std::string ansiString;

    auto ansiCharSize = WideCharToMultiByte(
        CP_UTF8, 0, unicodeString.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (ansiCharSize == 0)
    {
        throw curl_easy::error(
            GetLastError(), "Unable to convert string to Utf8 (sizing)");
    }
    ansiString.reserve(ansiCharSize);
    ansiString.resize(ansiCharSize - 1);

    ansiCharSize = WideCharToMultiByte(
        CP_UTF8,
        0,
        unicodeString.c_str(),
        -1,
        &ansiString[0],
        ansiCharSize,
        nullptr,
        nullptr);
    if (ansiCharSize == 0)
    {
        throw curl_easy::error(
            GetLastError(), "Unable to convert string to Utf8 (conversion)");
    }

    return ansiString;
}

std::wstring UnicodeStringFromUtf8String(_In_ const std::string& ansiString)
{
    std::wstring unicodeString;

    if (ansiString.empty())
    {
        return L"";
    }

    auto wideCharSize = MultiByteToWideChar(
        CP_UTF8, MB_ERR_INVALID_CHARS, ansiString.c_str(), -1, nullptr, 0);
    if (wideCharSize == 0)
    {
        throw curl_easy::error(
            GetLastError(), "Unable to convert string to unicode (sizing)");
    }
    unicodeString.reserve(wideCharSize);
    unicodeString.resize(wideCharSize - 1);

    wideCharSize = MultiByteToWideChar(
        CP_UTF8,
        MB_ERR_INVALID_CHARS,
        ansiString.c_str(),
        -1,
        &unicodeString[0],
        wideCharSize);
    if (wideCharSize == 0)
    {
        throw curl_easy::error(
            GetLastError(), "Unable to convert string to unicode (conversion)");
    }

    return unicodeString;
}

///////////////////////////////////////////////////////////////////////////////
// curl_easy implementation
///////////////////////////////////////////////////////////////////////////////
std::unique_ptr<curl_easy> curl_easy::create(
    const std::string& url,
    const std::string* const p_body,
    unsigned long dwFlags)
{
    struct make_unique_enabler : public curl_easy
    {
    };
    std::unique_ptr<curl_easy> curl = std::make_unique<make_unique_enabler>();

    curl->sessionHandle.reset(WinHttpOpen(
        nullptr,
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0));
    if (!curl->sessionHandle)
    {
        throw_on_error(GetLastError(), "curl_easy::create/WinHttpOpen");
    }

    URL_COMPONENTSW urlComponents = {0};

    // Allocate some buffers to hold the various pieces of the URL.
    auto urlLen(url.size() + 1);
    auto schemeBuffer(std::make_unique<wchar_t[]>(urlLen));
    auto hostBuffer(std::make_unique<wchar_t[]>(urlLen));
    auto urlBuffer(std::make_unique<wchar_t[]>(urlLen));
    auto extraBuffer(std::make_unique<wchar_t[]>(urlLen));

    // Set required component lengths to non-zero
    // so that they are cracked.
    urlComponents.dwStructSize = sizeof(URL_COMPONENTS);
    urlComponents.dwSchemeLength = (DWORD)-1;
    urlComponents.lpszScheme = schemeBuffer.get();
    urlComponents.dwHostNameLength = (DWORD)-1;
    urlComponents.lpszHostName = hostBuffer.get();
    urlComponents.dwUrlPathLength = (DWORD)-1;
    urlComponents.lpszUrlPath = urlBuffer.get();
    urlComponents.dwExtraInfoLength = (DWORD)-1;
    urlComponents.lpszExtraInfo = extraBuffer.get();
    log(SGX_QL_LOG_INFO,
        "winhttp url is %s",
        UnicodeStringFromUtf8String(url).c_str());

    if (!WinHttpCrackUrl(
            UnicodeStringFromUtf8String(url).c_str(),
            0,
            ICU_REJECT_USERPWD,
            &urlComponents))
    {
        throw_on_error(GetLastError(), "curl_easy::create/WinHttpCrackUrl");
    }

    curl->connectionHandle.reset(WinHttpConnect(
        curl->sessionHandle.get(),
        urlComponents.lpszHostName,
        urlComponents.nPort,
        0));
    if (!curl->connectionHandle)
    {
        throw_on_error(GetLastError(), "curl_easy::create/WinHttpConnect");
    }
    log(SGX_QL_LOG_INFO,
        "lpszHostName is %ls",
        urlComponents.lpszHostName);

    std::wstring urlToRetrieve(urlComponents.lpszUrlPath);
    urlToRetrieve += urlComponents.lpszExtraInfo;

    curl->request.reset(WinHttpOpenRequest(
        curl->connectionHandle.get(),
        L"GET",
        urlToRetrieve.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        dwFlags));

    if (!curl->request)
    {
        throw_on_error(GetLastError(), "curl_easy::create/WinHttpOpenRequest");
    }

    // Enable following redirects on this request.
    DWORD redirectPolicy = WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if (!WinHttpSetOption(
            curl->request.get(),
            WINHTTP_OPTION_REDIRECT_POLICY,
            &redirectPolicy,
            sizeof(redirectPolicy)))
    {
        throw_on_error(
            GetLastError(),
            "curl_easy::create/WinHttpSetOption(RedirectPolicy)");
    }

    // Specify TLS 1.2
    DWORD protocolOptions =
        WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2 | WINHTTP_FLAG_SECURE_PROTOCOL_SSL3;
    if (!WinHttpSetOption(
            curl->sessionHandle.get(),
            WINHTTP_OPTION_SECURE_PROTOCOLS,
            &protocolOptions,
            sizeof(protocolOptions)))
    {
        throw_on_error(
            GetLastError(),
            "curl_easy::create/WinHttpSetOption(SecureProtocols)");
    }
	/*
    DWORD ignoreSecurityPolicyOptions = 
		SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE | 
		SECURITY_FLAG_IGNORE_UNKNOWN_CA | 
		SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
		SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
    if (!WinHttpSetOption(
            curl->request.get(),
            SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE,
            &ignoreSecurityPolicyOptions,
            sizeof(ignoreSecurityPolicyOptions)))
    {
        throw_on_error(
            GetLastError(),
            "curl_easy::create/WinHttpSetOption(ignoreSecurityPolicyOptions)");
    }*/

    if (p_body != nullptr)
    {
        curl->request_body_data = *p_body;
    }

    return std::move(curl);
}

curl_easy::~curl_easy()
{
}

DWORD curl_easy::get_response_code() const
{
    DWORD dwStatusCode = 0;
    DWORD dwSize = sizeof(dwStatusCode);

    // Query for the response from the current request
    if (!WinHttpQueryHeaders(
            request.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &dwStatusCode,
            &dwSize,
            WINHTTP_NO_HEADER_INDEX))
    {
        throw_on_error(GetLastError(), "curl_easy::get_response_code/WinHttpQueryHeaders");
    }
    return dwStatusCode;
}

void curl_easy::perform() const
{
    int retry_delay = initial_retry_delay_ms;
    int attempts = 0;
    do
    {
        //  Start the protocol exchange with the server.
        if (!WinHttpSendRequest(
                request.get(),
                request_header_text.c_str(),
                (DWORD)request_header_text.size(),
                (PVOID)request_body_data.c_str(),
                (DWORD)request_body_data.size(),
                (DWORD)request_body_data.size(),
                0))
        {
            throw_on_error(
                GetLastError(), "curl_easy::perform/WinHttpSendRequest");
        }

        //  Wait for the response from the server.
        if (!WinHttpReceiveResponse(request.get(), nullptr))
        {
            DWORD lastError = GetLastError();
            if (lastError == ERROR_WINHTTP_TIMEOUT ||
                lastError == ERROR_WINHTTP_RESEND_REQUEST)
            {
                if (attempts <= maximum_retries)
                {
                    attempts++;
                    log(SGX_QL_LOG_INFO,
                        "CURL timeout detected (WINHTTP Error %zd). Retrying "
                        "after %d milliseconds (attempt %d / %d) ",
                        lastError,
                        retry_delay,
                        attempts,
                        maximum_retries);
                    Sleep(retry_delay);
                    retry_delay *= 2;
                    continue;
                }
            }
            throw_on_error(
                lastError, "curl_easy::perform/WinHttpReceiveRequest");
        }

        DWORD response_code = get_response_code();
        if (response_code >= HTTP_STATUS_BAD_REQUEST)
        {
            log(SGX_QL_LOG_INFO,
                "HTTP Error (%d) on curl->perform() request",
                response_code);
            throw_on_error(WINHTTP_ERROR_BASE, "curl_easy::perform");
        }
        return;
    } while (true);
}

const std::vector<uint8_t>& curl_easy::get_body() const
{
    if (body.empty())
    {
        std::vector<uint8_t> resultData;
        while (true)
        {
            DWORD sizeAvailable = 0;

            if (!WinHttpQueryDataAvailable(request.get(), &sizeAvailable))
            {
                throw_on_error(
                    GetLastError(),
                    "curl_easy::get_body/WinHttpQueryDataAvailable");
            }
            if (sizeAvailable == 0)
            {
                break;
            }

            auto buffer = std::make_unique<uint8_t[]>(sizeAvailable + 1);
            ZeroMemory(buffer.get(), sizeAvailable + 1);

            DWORD bytesRead;
            if (!WinHttpReadData(
                    request.get(), buffer.get(), sizeAvailable, &bytesRead))
            {
                throw_on_error(
                    GetLastError(), "curl_easy::get_body/WinHttpReadData");
            }

            resultData.reserve(bytesRead + resultData.size());

            int i = 0;
            while (bytesRead != 0)
            {
                resultData.push_back(buffer.get()[i]);
                i += 1;
                bytesRead -= 1;
            }
        }
        body = resultData;
    }
    return body;
}

const std::string* curl_easy::get_header(const std::string& field_name) const
{
    DWORD bufferLength = 0;

    std::string header = to_lower(field_name);
    auto result = headers.find(header);
    if (result != headers.end())
    {
        return &result->second;
    }
    else if (
        !WinHttpQueryHeaders(
            request.get(),
            WINHTTP_QUERY_CUSTOM,
            UnicodeStringFromUtf8String(header).c_str(),
            WINHTTP_NO_OUTPUT_BUFFER,
            &bufferLength,
            WINHTTP_NO_HEADER_INDEX) &&
        (GetLastError() == ERROR_INSUFFICIENT_BUFFER))
    {
        auto buffer = std::make_unique<wchar_t[]>(bufferLength + 1);
        ZeroMemory(buffer.get(), bufferLength);

        if (!WinHttpQueryHeaders(
                request.get(),
                WINHTTP_QUERY_CUSTOM,
                UnicodeStringFromUtf8String(header).c_str(),
                buffer.get(),
                &bufferLength,
                WINHTTP_NO_HEADER_INDEX))
        {
            throw_on_error(
                GetLastError(), "curl_easy::get_header/WinHttpQueryHeaders");
        }
        std::string headerAsUtf8(Utf8StringFromUnicodeString(buffer.get()));

        auto insertedHeader = headers.emplace(header, headerAsUtf8);
        const std::string* returnValue = &insertedHeader.first->second;
        return returnValue;
    }
    return nullptr;
}

void curl_easy::set_headers(
    const std::map<std::string, std::string>& header_name_values)
{
    request_header_text = L"";
    for (auto kvp : header_name_values)
    {
        request_header_text.append(UnicodeStringFromUtf8String(kvp.first + ":" + kvp.second));
    }
}

int8_t Int8FromHexAscii(char ch)
{
    int8_t byteValue;
    if (ch >= '0' && ch <= '9')
    {
        byteValue = (ch - '0');
    }
    else if (ch >= 'a' && ch <= 'f')
    {
        byteValue = (ch - 'a') + 10;
    }
    else if (ch >= 'A' && ch <= 'F')
    {
        byteValue = (ch - 'A') + 10;
    }
    else
    {
        byteValue = -1;
    }
    return byteValue;
}

std::string curl_easy::unescape(const std::string& encoded) const
{
    std::string decodedHeader;
    for (auto it = encoded.begin(); it != encoded.end(); ++it)
    {
        if (*it == '%')
        {
            char byteValue;
            ++it;
            if (it == encoded.end())
            {
                throw_on_error(
                    EBADMSG, "Malformed URL encoding in header " + encoded);
            }
            char ch = *it;
            int8_t hexValue = Int8FromHexAscii(ch);
            if (hexValue < 0)
            {
                std::stringstream ss;
                ss << "Bogus hex value " << (uint8_t)ch << "(" << ch
                   << ") in URL encoding in header " << encoded;
                throw_on_error(EBADMSG, ss.str());
            }
            byteValue = hexValue << 4;
            ++it;
            if (it == encoded.end())
            {
                throw_on_error(
                    EBADMSG, "Malformed URL encoding in header " + encoded);
            }
            ch = *it;
            hexValue = Int8FromHexAscii(ch);
            if (hexValue < 0)
            {
                std::stringstream ss;
                ss << "Bogus hex value " << (uint8_t)ch << "(" << ch
                   << ") in URL encoding in header " << encoded;
                throw_on_error(EBADMSG, ss.str());
            }
            byteValue |= hexValue & 0xf;
            decodedHeader.push_back(byteValue);
        }
        else
        {
            decodedHeader.push_back(*it);
        }
    }
    return decodedHeader;
}

char HexAsciiFromUInt8(uint8_t i)
{
    static char intToChar[] = "0123456789ABCDEF";
    if (i < 16)
    {
        return intToChar[i];
    }
    else
    {
        return -1;
    }
}

std::string curl_easy::escape(const char* url, int length)
{
    std::string escapedHeader;
    if (length == 0)
    {
        length = static_cast<int>(strlen(url));
    }

    for (int i = 0; i < length; i += 1)
    {
        char ch = url[i];
        if ((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
            (ch >= '0' && ch <= '9') || (ch == '-') || (ch == '.') ||
            (ch == '~') || (ch == '?') || (ch == '_'))
        {
            escapedHeader.push_back(ch);
        }
        else
        {
            escapedHeader.push_back('%');
            char firstNibble = HexAsciiFromUInt8(ch >> 4);
            if (firstNibble < 0)
            {
                std::stringstream ss;
                ss << "Bogus hex value " << (uint8_t)ch << "(" << ch
                   << ") in URL encoding in header " << url;
                throw_on_error(EBADMSG, ss.str());
            }
            escapedHeader.push_back(firstNibble);
            char secondNibble = HexAsciiFromUInt8(ch & 0x0f);
            if (secondNibble < 0)
            {
                std::stringstream ss;
                ss << "Bogus hex value " << (uint8_t)ch << "(" << ch
                   << ") in URL encoding in header " << url;
                throw_on_error(EBADMSG, ss.str());
            }
            escapedHeader.push_back(secondNibble);
        }
    }
    return escapedHeader;
}

void curl_easy::throw_on_error(DWORD code, const char* function)
{
    if (code != 0)
    {
        log(SGX_QL_LOG_ERROR,
            "Encountered CURL error %d in %s",
            code,
            function);

        if (code == ERROR_NOT_ENOUGH_MEMORY)
        {
            throw std::bad_alloc();
        }

        throw curl_easy::error(code, function);
    }
}
