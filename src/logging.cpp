// Licensed under the MIT License.

#ifndef __LINUX__
#include "evtx_logging.h"
#endif

#include "private.h"

#include <cassert>
#include <chrono>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <fstream>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <vector>
#include <mutex>
#include <time.h>
#include "environment.h"

using namespace std;
sgx_ql_logging_callback_t logger_callback = nullptr;
sgx_ql_logging_function_t logger_function = nullptr;
static sgx_ql_log_level_t debug_log_level = SGX_QL_LOG_NONE;
static bool debug_log_initialized = false;
static mutex log_init_mutex;

static const string LEVEL_ERROR = "ERROR";
static const string LEVEL_ERROR_ALT = "SGX_QL_LOG_ERROR";

static const string LEVEL_WARNING = "WARNING";
static const string LEVEL_WARNING_ALT = "SGX_QL_LOG_WARNING";

static const string LEVEL_INFO = "INFO";
static const string LEVEL_INFO_ALT = "SGX_QL_LOG_INFO";

static const string LEVEL_UNKNOWN = "UNKNOWN";


static const string WRITE_TO_LOGS_ACTIVE_VALUE = "TRUE";

static const string logFileName = "/tmp/dcapLog.txt";

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
        case SGX_QL_LOG_NONE:
            return LEVEL_UNKNOWN;
        default:
            return LEVEL_UNKNOWN;
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
        debug_log_level = sgx_level;

        auto logging_enabled_message = "Debug Logging Enabled";
        if ((logger_callback == nullptr) && (logger_function == nullptr))
        {
            printf(
                "Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n",
                log_level_string(SGX_QL_LOG_INFO).c_str(),
                logging_enabled_message);
        }
        if (logger_callback != nullptr)
        {
            logger_callback(SGX_QL_LOG_INFO, logging_enabled_message);
        }
        if (logger_function != nullptr)
        {
            logger_function(SGX_QL_LOG_INFO, logging_enabled_message);
        }
    }
}

void init_debug_log()
{
    std::lock_guard<std::mutex> lock(log_init_mutex);
    if (!debug_log_initialized)
    {
        auto log_level = get_env_variable_no_log(ENV_AZDCAP_DEBUG_LOG);
        if (!log_level.first.empty() && log_level.second.empty())
        {
            enable_debug_logging(log_level.first);
        }

        if (!log_level.second.empty())
        {
            printf(
                "Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n",
                log_level_string(SGX_QL_LOG_ERROR).c_str(),
                log_level.second.c_str());
        }
        debug_log_initialized = true;
    }
}

//
// Logging function which doesn't allocate buffer 
//
void log_message(sgx_ql_log_level_t level, const char* message)
{
	auto now = chrono::system_clock::now();
	time_t nowTimeT = chrono::system_clock::to_time_t(now);
    char date[100];
	
#if defined __LINUX__ 
    strftime(date, sizeof(date), "%F %X", localtime(&nowTimeT));
#else 
	struct tm calendarDate;
	localtime_s(&calendarDate, &nowTimeT);
	strftime(date, sizeof(date), "%F %X", &calendarDate);
#endif

	string timestamp(date);

	auto milliseconds = chrono::duration_cast<chrono::milliseconds>(now.time_since_epoch()) % 1000;

	string millisecondsString = to_string(milliseconds.count());
	//If the number of milliseconds is below 100, append 0s in front of the milliseconds string
	//Otherwise a time like like 21:30:01.007 would print as 21:30:01.7
	while (millisecondsString.length() < 3) {
		millisecondsString.insert(0, "0");
	}
	
	timestamp += "." + millisecondsString;

	string logMessage = "Azure Quote Provider: libdcap_quoteprov.so [" + log_level_string(level) + "] [" + timestamp + "]: " + message + "\n";

#if defined __LINUX__ 
	auto envVarShouldWeWriteToLogs = get_env_variable_no_log(ENV_AZDCAP_WRITE_LOGS_TO_FILE);

	if (envVarShouldWeWriteToLogs.first == WRITE_TO_LOGS_ACTIVE_VALUE) {

		FILE *f = fopen(logFileName.c_str(), "a");
		if (f == NULL) {
			printf("Error opening log file");
			exit(1);
		}
		fprintf(f, "%s", logMessage.c_str());
		fflush(f);
		fclose(f);
	}
#endif
	

    if ((logger_function == nullptr) && (logger_callback == nullptr))
    {
        init_debug_log();
        if (debug_log_level != SGX_QL_LOG_NONE)
        {
            if (level <= debug_log_level)
            {
                printf(
                    "Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n",
                    log_level_string(level).c_str(),
                    message);
            }
        }
    }
    if (logger_callback != nullptr)
    {
        logger_callback(level, message);
    }
    if (logger_function != nullptr)
    {
        logger_function(level, message);
    }
    fflush(stdout);

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
            case SGX_QL_LOG_NONE:
                break;
            default:
                break;
        }
    }
#endif
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
    vsnprintf(message, sizeof(message),
        fmt, args);
    va_end(args);

    // ensure buf is always null-terminated
    message[sizeof(message) - 1] = 0;
    log_message(level, message);
}
