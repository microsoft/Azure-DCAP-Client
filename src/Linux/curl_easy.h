// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef CURL_EASY_H
#define CURL_EASY_H

#define _CRT_SECURE_NO_WARNINGS // Use strncpy for portability.
#include <cassert>
#include <cstddef>
#include <exception>
#include <map>
#include <memory>
#include <string>
#include <vector>
#include <curl/curl.h>

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
        error(CURLcode c, const char* f);

        char const* what() const noexcept override;

        const CURLcode code;

      private:
        char function[128]{};
    };

    static std::unique_ptr<curl_easy> create(
        const std::string& url,
        const std::string* const p_body,
        unsigned long dwFlags = 0,
        bool fetchingFromLocalAgent = false,
        bool fetchingFromIMDS = false);

    ~curl_easy();

    curl_easy(curl_easy&) = delete;
    curl_easy(curl_easy&&) = delete;
    curl_easy& operator=(curl_easy&) = delete;
    curl_easy& operator=(curl_easy&&) = delete;

    void perform() const;

    const std::vector<uint8_t>& get_body() const;

    const std::string* get_header(const std::string& field_name) const;

    void set_headers(const std::map<std::string, std::string>& header_name_values);

    std::string unescape(const std::string& encoded) const;
    static std::string escape(const char *buffer, int len);
  private:
    curl_easy() = default;

#pragma warning( \
    suppress : 25033 25057) // CURL defines input buffers as non-const
    static size_t write_callback(
        char* ptr,
        size_t size,
        size_t nmemb,
        void* user_data);

#pragma warning( \
    suppress : 25033 25057) // CURL defines input buffers as non-const
    static size_t header_callback(
        char* buffer,
        size_t size,
        size_t nitems,
        void* user_data);

    static CURLcode ssl_context_callback(
        CURL* curl,
        void* ssl_context,
        void* user_data);

    static void throw_on_error(CURLcode code, const std::string& function)
    {
        throw_on_error(code, function.c_str());
    }

    static void throw_on_error(CURLcode code, const char* function);

    // Wraps curl_easy_setopt operations which are not ever supposed to fail.
    template <typename T>
    void set_opt_or_throw(CURLoption option, T param)
    {
        CURLcode result = curl_easy_setopt(handle, option, param);
        assert(result == CURLE_OK);
        if (result != CURLE_OK)
        {
            auto optionStr = std::to_string(option);
            throw_on_error(result, "curl_easy_setopt(" + optionStr + ")");
        }
    }

    CURL* handle = nullptr;
    std::vector<uint8_t> body;
    std::map<std::string, std::string> headers;
};

#endif
