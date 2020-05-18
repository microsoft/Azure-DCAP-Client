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
#define ENV_AZDCAP_CLIENT_ID "AZDCAP_CLIENT_ID"
#define ENV_AZDCAP_COLLATERAL_VER "AZDCAP_COLLATERAL_VERSION"
#define ENV_AZDCAP_DEBUG_LOG "AZDCAP_DEBUG_LOG_LEVEL"
#define ENV_AZDCAP_DISABLE_ONDEMAND "AZDCAP_DISABLE_ONDEMAND"

#define MAX_ENV_VAR_LENGTH 2000

static std::string get_env_variable(std::string env_variable)
{
    const char* env_value;
#ifdef __LINUX__
    env_value = getenv(env_variable.c_str());
    if (env_value == NULL)
    {
        return std::string();
    }
#else
    std::unique_ptr<char[]> env_temp =
        std::make_unique<char[]>(MAX_ENV_VAR_LENGTH);
    if (env_temp == nullptr)
    {
        log(SGX_QL_LOG_ERROR,
            "Failed to allocate memory for environment varible for '%s'",
            env_variable.c_str(),
            MAX_ENV_VAR_LENGTH);
    }
    env_value = env_temp.get();
    DWORD status = GetEnvironmentVariableA(
        env_variable.c_str(), env_temp.get(), MAX_ENV_VAR_LENGTH);
    if (status == 0)
    {
        log(SGX_QL_LOG_ERROR,
            "Failed to retreive environment varible for '%s'",
            env_variable.c_str(),
            MAX_ENV_VAR_LENGTH);
        return std::string();
    }
#endif
    else
    {
        if ((strnlen(env_value, MAX_ENV_VAR_LENGTH) <= 0) ||
            (strnlen(env_value, MAX_ENV_VAR_LENGTH) == MAX_ENV_VAR_LENGTH))
        {
            log(SGX_QL_LOG_ERROR,
                "Value specified in environment variable %s is either empty or "
                "expected max length '%d'.",
                env_variable.c_str(),
                MAX_ENV_VAR_LENGTH);
            return std::string();
        }

        auto retval = std::string(env_value);
        return retval;
    }
}

#endif