// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <Windows.h>

HINSTANCE moduleHandle;
extern void uninit();

extern "C" BOOL WINAPI DllMain(
    _In_ HINSTANCE dll,
    _In_ const DWORD reason,
    _In_ LPVOID /* reserved */
    )
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(dll);
        moduleHandle = dll; 
    }
    return true;
}
