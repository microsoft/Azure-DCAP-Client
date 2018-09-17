// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <Windows.h>
#include <curl/curl.h>

extern "C" BOOL WINAPI DllMain(
    _In_ HINSTANCE /* dll */,
    _In_ const DWORD reason,
    _In_ LPVOID /* reserved */
    )
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        curl_global_init(CURL_GLOBAL_DEFAULT);
    }

    return true;
}
