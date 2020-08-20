// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the GUNITTESTDLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// GUNITTESTDLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef GUNITTESTDLL_EXPORTS
#define GUNITTESTDLL_API __declspec(dllexport)
#else
#define GUNITTESTDLL_API __declspec(dllimport)
#endif

// This class is exported from the dll
class GUNITTESTDLL_API CgUnitTestDll {
public:
	CgUnitTestDll(void);
	// TODO: add your methods here.
};

extern GUNITTESTDLL_API int ngUnitTestDll;

GUNITTESTDLL_API int fngUnitTestDll(void);
