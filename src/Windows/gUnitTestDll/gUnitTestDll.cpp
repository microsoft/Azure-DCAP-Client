// gUnitTestDll.cpp : Defines the exported functions for the DLL.
//

#include "framework.h"
#include "gUnitTestDll.h"


// This is an example of an exported variable
GUNITTESTDLL_API int ngUnitTestDll=0;

// This is an example of an exported function.
GUNITTESTDLL_API int fngUnitTestDll(void)
{
    return 0;
}

// This is the constructor of a class that has been exported.
CgUnitTestDll::CgUnitTestDll()
{
    return;
}
