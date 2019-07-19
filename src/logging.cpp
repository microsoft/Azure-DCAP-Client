// Licensed under the MIT License.
#define _CRT_SECURE_NO_WARNINGS

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


#if 0 // Flip this to true for easy local debugging
static void DefaultLogCallback(sgx_ql_log_level_t level, const char* message)
{
    printf("Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n", level == SGX_QL_LOG_ERROR ? "ERROR" : "DEBUG", message);
}

sgx_ql_logging_function_t logger_callback = DefaultLogCallback;
#else
sgx_ql_logging_function_t logger_callback = nullptr;
#endif

//
// Global logging function.
//
void log(sgx_ql_log_level_t level, const char* fmt, ...)
{
    if (logger_callback)
    {
        char message[512];
        va_list args;
        va_start(args, fmt);
#pragma warning(suppress : 25141) // all fmt buffers come from static strings
        vsnprintf(message, sizeof(message), fmt, args);
        va_end(args);

        // ensure buf is always null-terminated
        message[sizeof(message) - 1] = 0;

        logger_callback(level, message);
    }
}

