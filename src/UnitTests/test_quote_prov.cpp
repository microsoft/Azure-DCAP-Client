// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "unit_test.h"
#include "dcap_provider.h"
#include "sgx_ql_lib_common.h"
#include "local_cache.h"

#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>

#if defined(__LINUX__)
#include <tgmath.h>
#include <dlfcn.h>
#else
#include <iostream>
#include <stdlib.h>
#include <windows.h>
#endif

typedef quote3_error_t (*sgx_ql_get_quote_config_t)(
    const sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_ql_config_t** pp_quote_config);

typedef quote3_error_t (*sgx_ql_free_quote_config_t)(
    sgx_ql_config_t* p_quote_config);

//
// Invoke via function pointer because that's how both the the Intel
// and Open Enclave stacks load and use this library.
//
static sgx_ql_free_revocation_info_t sgx_ql_free_revocation_info;
static sgx_ql_get_revocation_info_t sgx_ql_get_revocation_info;
static sgx_ql_free_quote_config_t sgx_ql_free_quote_config;
static sgx_ql_get_quote_config_t sgx_ql_get_quote_config;
static sgx_ql_set_logging_function_t sgx_ql_set_logging_function;

static void Log(sgx_ql_log_level_t level, const char* message)
{
    char const* levelText = "ERROR";
    switch (level)
    {
        case SGX_QL_LOG_WARNING:
            levelText = "WARNING";
            break;
        case SGX_QL_LOG_INFO:
            levelText = "INFO";
            break;
        case SGX_QL_LOG_ERROR:
            levelText = "ERROR";
            break;
    }
    printf("[%s]: %s\n", levelText, message);
}

#if defined __LINUX__
static void* LoadFunctions()
{
    // if this assert fails, be sure libdcap_quoteprov.so is in your LD_LIBRARY_PATH

    void* library = dlopen("libdcap_quoteprov.so", RTLD_NOW);
    if (library == nullptr)
    {
        Log(SGX_QL_LOG_ERROR, dlerror());
        abort();
    }

    sgx_ql_free_revocation_info = reinterpret_cast<sgx_ql_free_revocation_info_t>(dlsym(library, "sgx_ql_free_revocation_info"));
    assert(sgx_ql_free_revocation_info);

    sgx_ql_get_revocation_info = reinterpret_cast<sgx_ql_get_revocation_info_t>(dlsym(library, "sgx_ql_get_revocation_info"));
    assert(sgx_ql_get_revocation_info);

    sgx_ql_free_quote_config = reinterpret_cast<sgx_ql_free_quote_config_t>(dlsym(library, "sgx_ql_free_quote_config"));
    assert(sgx_ql_free_quote_config);

    sgx_ql_get_quote_config = reinterpret_cast<sgx_ql_get_quote_config_t>(dlsym(library, "sgx_ql_get_quote_config"));
    assert(sgx_ql_get_quote_config);

    sgx_ql_set_logging_function = reinterpret_cast<sgx_ql_set_logging_function_t>(dlsym(library, "sgx_ql_set_logging_function"));
    assert(sgx_ql_set_logging_function);

    return library;
}
#else
static HINSTANCE LoadFunctions()
{
    std::wstring s = L"dcap_quoteprov.dll";
    HINSTANCE hLibCapdll = LoadLibrary(s.c_str());
    if (hLibCapdll == NULL)
    {
        DWORD error = GetLastError(); 
        Log(SGX_QL_LOG_ERROR , std::to_string(error).c_str());
        abort();
    }

    sgx_ql_free_revocation_info = reinterpret_cast<sgx_ql_free_revocation_info_t>(GetProcAddress(hLibCapdll, "sgx_ql_free_revocation_info"));
    assert(sgx_ql_free_revocation_info);

    sgx_ql_get_revocation_info = reinterpret_cast<sgx_ql_get_revocation_info_t>(GetProcAddress(hLibCapdll, "sgx_ql_get_revocation_info"));
    assert(sgx_ql_get_revocation_info);

    sgx_ql_free_quote_config = reinterpret_cast<sgx_ql_free_quote_config_t>(GetProcAddress(hLibCapdll, "sgx_ql_free_quote_config"));
    assert(sgx_ql_free_quote_config);

    sgx_ql_get_quote_config = reinterpret_cast<sgx_ql_get_quote_config_t>(GetProcAddress(hLibCapdll, "sgx_ql_get_quote_config"));
    assert(sgx_ql_get_quote_config);

    sgx_ql_set_logging_function = reinterpret_cast<sgx_ql_set_logging_function_t>(GetProcAddress(hLibCapdll, "sgx_ql_set_logging_function"));
    assert(sgx_ql_set_logging_function);

    return hLibCapdll;
}
#endif

//
// Fetches and validates certification data for a platform
//
static void GetCertsTest()
{
    TEST_START();

    // Setup the input (choose an arbitrary Azure server)
    uint8_t qe_id[16] = {
        0x00, 0xbd, 0x4b, 0x28, 0x79, 0xd5, 0xa2, 0x76,
        0x4a, 0x96, 0x4a, 0xb9, 0x90, 0x90, 0x8b, 0x67
    };
    sgx_cpu_svn_t cpusvn = {
        0x05, 0x05, 0x02, 0x05, 0xff, 0x80, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    sgx_isv_svn_t pcesvn = 6;

    sgx_ql_pck_cert_id_t id = {qe_id, sizeof(qe_id), &cpusvn, &pcesvn, 0};

    // Get the cert data
    sgx_ql_config_t* config;
    assert(SGX_QL_SUCCESS == sgx_ql_get_quote_config(&id, &config));
    assert(nullptr != config);

    // Just sanity check a few fields. Parsing the certs would require a big
    // dependency like OpenSSL that we don't necessarily want.
    constexpr sgx_cpu_svn_t CPU_SVN_MAPPED = {
        0x05, 0x05, 0x02, 0x04, 0x01, 0x80, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    assert(0 == memcmp(&CPU_SVN_MAPPED, &config->cert_cpu_svn, sizeof(CPU_SVN_MAPPED)));
    assert(6 == config->cert_pce_isv_svn);
    assert(SGX_QL_CONFIG_VERSION_1 == config->version);
    assert(0 < config->cert_data_size);
    assert(nullptr != config->p_cert_data);

    assert(SGX_QL_SUCCESS == sgx_ql_free_quote_config(config));

    TEST_PASSED();
}

//
// Fetches and validates revocation data for SGX
//
static void GetCrlTest()
{
    TEST_START();

    static constexpr uint8_t TEST_FMSPC[] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};

    // This is the CRL DP used by Intel for leaf certs
    static const char* TEST_CRL_URL = "https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca=processor";

    sgx_ql_get_revocation_info_params_t params = {
        SGX_QL_REVOCATION_INFO_VERSION_1,
        sizeof(TEST_FMSPC),
        TEST_FMSPC,
        1,
        &TEST_CRL_URL};

    sgx_ql_revocation_info_t* output;
    assert(SGX_PLAT_ERROR_OK == sgx_ql_get_revocation_info(&params, &output));

    assert(0 < output->tcb_info_size);
    assert(nullptr != output->tcb_info);

    assert(1 == output->crl_count);
    assert(0 < output->crls[0].crl_data_size);
    assert(nullptr != output->crls[0].crl_data);

    sgx_ql_free_revocation_info(output);

    TEST_PASSED();
}

#if defined __LINUX__
extern void QuoteProvTests()
{
    std::clock_t start;
    double duration_curl;
    double duration_local;
    void* library = LoadFunctions();

    assert(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // First pass: Get the data from the service, no cache allowed
    //

    setenv("AZDCAP_BASE_CERT_URL", "https://global.acccache.azure.net/sgx/certificates", 1);
    local_cache_clear();

    start = std::clock();
    GetCertsTest();
    duration_curl = (std::clock() - start) / (double)CLOCKS_PER_SEC;

    GetCrlTest();

    //
    // Second pass: Ensure that we ONLY get data from the cache
    //
    start = std::clock();
    GetCertsTest();
    duration_local = (std::clock() - start) / (double)CLOCKS_PER_SEC;

    GetCrlTest();

    // Ensure that there is a signficiant enough difference between the cert
    // fetch to the end point and cert fetch to local cache and that local cache
    // call is fast enough
    assert(fabs(duration_curl - duration_local) > 0.0001 && duration_local < 0.001);

    dlclose(library);
}
#else
extern void QuoteProvTests()
{
    HINSTANCE library = LoadFunctions();

    assert(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // First pass: Get the data from the service, no cache allowed
    //
    _putenv("AZDCAP_BASE_CERT_URL=https://global.acccache.azure.net/sgx/certificates");

    GetCertsTest();
    GetCrlTest();

    FreeLibrary(library);
}
#endif
