// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef LIBDCAP_ENVIRONMENT_H
#define LIBDCAP_ENVIRONMENT_H

// NOTE:
//  The environment variables below are mostly meant to be modified
//  by the OE Jenkins environment to support CI/CD testing. Do not
//  modify or override these values as they can cause regressions in
//  caching service behavior.
#define ENV_AZDCAP_BASE_URL "AZDCAP_BASE_CERT_URL"
#define ENV_FETCH_FROM_BASE_URL "AZDCAP_FETCH_FROM_BASE_URL"
#define ENV_AZDCAP_SECONDARY_BASE_CERT_URL "AZDCAP_SECONDARY_BASE_CERT_URL"
#define ENV_AZDCAP_CLIENT_ID "AZDCAP_CLIENT_ID"
#define ENV_AZDCAP_COLLATERAL_VER "AZDCAP_COLLATERAL_VERSION"
#define ENV_AZDCAP_DEBUG_LOG "AZDCAP_DEBUG_LOG_LEVEL"
#define ENV_AZDCAP_DISABLE_ONDEMAND "AZDCAP_DISABLE_ONDEMAND"

#define MAX_ENV_VAR_LENGTH 2000

#include <sstream>
#include <utility>

static std::pair<std::string, std::string> get_env_variable_no_log(
    std::string env_variable)
{
    const char* env_value;
    std::stringstream error_message_stream;
#ifdef __LINUX__
    env_value = getenv(env_variable.c_str());
    if (env_value == NULL)
    {
        error_message_stream << "Could not retrieve environment variable for '"
                             << env_variable << "'";
        return std::make_pair(std::string(), error_message_stream.str());
    }
#else
    std::unique_ptr<char[]> env_temp =
        std::make_unique<char[]>(MAX_ENV_VAR_LENGTH);
    if (env_temp == nullptr)
    {
        error_message_stream
            << "Failed to allocate memory for environment varible for '"
            << env_variable << "'";
        return std::make_pair(std::string(), error_message_stream.str());
    }

    env_value = env_temp.get();
    DWORD status = GetEnvironmentVariableA(
        env_variable.c_str(), env_temp.get(), MAX_ENV_VAR_LENGTH);
    if (status == 0)
    {
        error_message_stream << "Could not retrieve environment variable for '"
                             << env_variable << "'";
        return std::make_pair(std::string(), error_message_stream.str());
    }
#endif
    auto length = strnlen(env_value, MAX_ENV_VAR_LENGTH);
    if (length <= 0 || length == MAX_ENV_VAR_LENGTH)
    {
        error_message_stream << "Length of environment variable '"
                             << env_variable << "' ";
        error_message_stream << "is either empty or equal to expected max "
                                "length. ";
        error_message_stream << "Actual length is: " << length << " ";
        error_message_stream << "Max length is " << MAX_ENV_VAR_LENGTH;
        return std::make_pair(std::string(), error_message_stream.str());
    }

    return std::make_pair(env_value, std::string());
}

#endif
