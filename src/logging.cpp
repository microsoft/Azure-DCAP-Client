// Licensed under the MIT License.

#ifndef __LINUX__
#include "evtx_logging.h"
#endif

#include "private.h"

#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <vector>
#include <mutex>
#include "environment.h"

using namespace std;

sgx_ql_logging_function_t logger_callback = nullptr;
static sgx_ql_log_level_t debug_log_level;
bool enable_debug_log = false;
bool debug_log_initialized = false;
mutex log_init_mutex;

static const string LEVEL_ERROR = "ERROR";
static const string LEVEL_ERROR_ALT = "SGX_QL_LOG_ERROR";

static const string LEVEL_WARNING = "WARNING";
static const string LEVEL_WARNING_ALT = "SGX_QL_LOG_WARNING";

static const string LEVEL_INFO = "INFO";
static const string LEVEL_INFO_ALT = "SGX_QL_LOG_INFO";

static inline bool convert_string_to_level(const string level, sgx_ql_log_level_t &sqx_ql_level)
{
    if (level == LEVEL_ERROR || level == LEVEL_ERROR_ALT)
    {
        sqx_ql_level = SGX_QL_LOG_ERROR;
        return true;
    }

    if (level == LEVEL_WARNING || level == LEVEL_WARNING_ALT)
    {
        sqx_ql_level = SGX_QL_LOG_WARNING;
        return true;
    }

    if (level == LEVEL_INFO || level == LEVEL_INFO_ALT)
    {
        sqx_ql_level = SGX_QL_LOG_INFO;
        return true;
    }

    return false;
}

static inline string log_level_string(const sgx_ql_log_level_t sgx_ql_level)
{
    switch (sgx_ql_level)
    {
        case SGX_QL_LOG_INFO:
            return LEVEL_INFO;
        case SGX_QL_LOG_WARNING:
            return LEVEL_WARNING;
        case SGX_QL_LOG_ERROR:
            return LEVEL_ERROR;
        default:
            return LEVEL_INFO;
    }
}

//
// Enable for debug logging via stdout
//
static inline void enable_debug_logging(string level)
{
    sgx_ql_log_level_t sgx_level;
    if (convert_string_to_level(level, sgx_level))
    {
        enable_debug_log = true;
        debug_log_level = sgx_level;

        auto logging_enabled_message = "Debug Logging Enabled";
        if (logger_callback != nullptr)
        {
            logger_callback(SGX_QL_LOG_INFO, logging_enabled_message);
        }
        printf(
            "Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n",
            log_level_string(SGX_QL_LOG_INFO).c_str(),
            logging_enabled_message);
    }
}

void init_debug_log()
{
    std::lock_guard<std::mutex> lock(log_init_mutex);
    if (debug_log_initialized)
    {
        auto log_level = get_env_variable(ENV_AZDCAP_DEBUG_LOG);
        if (!log_level.empty())
        {
            enable_debug_logging(log_level);
        }
        debug_log_initialized = true;
    }
}

//
// Global logging function.
//
void log(sgx_ql_log_level_t level, const char* fmt, ...)
{
    char message[512];
    va_list args;
    va_start(args, fmt);
#pragma warning(suppress : 25141) // all fmt buffers come from static strings
    vsnprintf(message, sizeof(message), fmt, args);
    va_end(args);

    // ensure buf is always null-terminated
    message[sizeof(message) - 1] = 0;

    init_debug_log();

    if (logger_callback != nullptr)
    {
        logger_callback(level, message);
    }else if (enable_debug_log)
    {
        if (level <= debug_log_level)
        {
            printf("Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n", log_level_string(level).c_str(), message);
        }
    }

#ifndef __LINUX__
	// Emitting Events only in Windows

    if (check_install_event_log_source() == ERROR_SUCCESS)
    {
        switch (level)
        {
            case SGX_QL_LOG_INFO:
                log_event_log_message(message, EVENTLOG_INFORMATION_TYPE);
                break;

            case SGX_QL_LOG_WARNING:
                log_event_log_message(message, EVENTLOG_WARNING_TYPE);
                break;

            case SGX_QL_LOG_ERROR:
                log_event_log_message(message, EVENTLOG_ERROR_TYPE);
                break;
        }
    }
#endif
}
