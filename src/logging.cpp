// Licensed under the MIT License.
#define _CRT_SECURE_NO_WARNINGS

#include "private.h"

#include <wil\resource.h>
#include <windows.h>
#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <limits>
#include <memory>
#include <new>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#define MAX_RETRY 10000
#define SLEEP_RETRY_MS 15

#if 0 // Flip this to true for easy local debugging
static void DefaultLogCallback(sgx_ql_log_level_t level, const char* message)
{
    printf("Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n", level == SGX_QL_LOG_ERROR ? "ERROR" : "DEBUG", message);
}

sgx_ql_logging_function_t logger_callback = DefaultLogCallback;
#else
sgx_ql_logging_function_t logger_callback = nullptr;
#endif



void logToFile(sgx_ql_log_level_t level, const char* message)
{
    // if (level == SGX_QL_LOG_ERROR)
    //{
    wil::unique_hfile logfile;

    std::time_t now = time(nullptr);
    std::tm tm = *std::localtime(&now);
    std::wstringstream wss;

	wss << "C:\\Users\\srujon\\" << std::put_time(&tm, L"%F") << L"-dcap-error.log";

    std::wstring logfileName = wss.str();

    wprintf(L"Writing to file %s", logfileName.c_str());

    int i = 0;
    do
    {
        logfile.reset(CreateFile(
            logfileName.c_str(),
            FILE_APPEND_DATA,
            0,
            nullptr,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr));
        Sleep(SLEEP_RETRY_MS);
        i++;
    } while (!logfile && (GetLastError() == ERROR_SHARING_VIOLATION) &&
             (i < MAX_RETRY));

    logfile = std::move(logfile);

	if (!logfile)
	{
        const DWORD error = GetLastError();
        wprintf(L"Failure in file handle 0x%X", error);
	}
	else
	{
        std::string messageStr = std::string(message);

        std::wstringstream wss2;
        wss2 << std::put_time(&tm, L"%F %T")
             << L" Azure Quote Provider: libdcap_quoteprov.so [ ERROR ] "
             << std::wstring(messageStr.begin(), messageStr.end())
			 << std::endl;

        std::wstring logMessage = wss2.str();

		std::string logMessageStr(logMessage.begin(), logMessage.end());

        DWORD messagewritten;

        if (!WriteFile(
                logfile.get(),
                logMessageStr.c_str(),
                (DWORD)strlen(logMessageStr.c_str()),
                &messagewritten,
                nullptr))
        {
            printf("Failure in WriteFile");
        }
	}
    //}
}

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

        logToFile(level, message);
    }
}
