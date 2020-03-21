// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef CURL_EASY_H
#define CURL_EASY_H

#include <windows.h>
#include <winhttp.h>
#include <cassert>
#include <cstddef>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <wil\resource.h>

const DWORD CURLE_HTTP_RETURNED_ERROR = 0x7fff;
//
// RAII wrapper around Curl to make resource management exception-safe. This
// class also converts
// errors to exceptions, making error handling a bit easier.
//
class curl_easy
{
  public:
    class error : public std::exception
    {
      public:
        error(DWORD c, const char* f);

        char const* what() const noexcept override;

        const DWORD code;

      private:
        char function[128]{};
    };
    static std::unique_ptr<curl_easy> create(
        const std::string& url,
        const std::string* const p_body);

    ~curl_easy();

    curl_easy(curl_easy&) = delete;
    curl_easy(curl_easy&&) = delete;
    curl_easy& operator=(curl_easy&) = delete;
    curl_easy& operator=(curl_easy&&) = delete;

    void perform() const;

    const std::vector<uint8_t>& get_body() const;

    const std::string* get_header(const std::string& field_name) const;

    void set_headers(
        const std::map<std::string, std::string>& header_name_values);

    std::string unescape(const std::string& encoded) const;
    static std::string escape(const char* url, int length);

  private:
    curl_easy() = default;

    static void throw_on_error(DWORD code, const std::string& function)
    {
        throw_on_error(code, function.c_str());
    }

    static void throw_on_error(DWORD code, const char* function);

    wil::unique_winhttp_hinternet sessionHandle;
    wil::unique_winhttp_hinternet connectionHandle;
    wil::unique_winhttp_hinternet request;

    mutable std::vector<uint8_t> body;
    mutable std::map<std::string, std::string> headers; // response headers
    mutable std::wstring request_header_text;
    mutable std::string request_body_data;
};

#endif
