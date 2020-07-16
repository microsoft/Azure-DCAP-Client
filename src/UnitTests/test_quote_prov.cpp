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
#include <sstream>
#include <sys/stat.h>
#include <chrono>

#if defined(__LINUX__)
#include <tgmath.h>
#include <dlfcn.h>
#else
#include <iostream>
#include <stdlib.h>
#include <windows.h>
#include <AclAPI.h>
#endif

using namespace std;

#if defined __LINUX__
typedef void * libary_type_t;
typedef int permission_type_t;
#else
typedef HINSTANCE libary_type_t;
typedef struct _access_permission
{
    DWORD access_permissions;
    ACCESS_MODE access_mode;
} permission_type_t;
#endif

typedef void (*measured_function_t)(void);

typedef quote3_error_t (*sgx_ql_get_quote_config_t)(
    const sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_ql_config_t** pp_quote_config);

typedef quote3_error_t (*sgx_ql_free_quote_config_t)(
    sgx_ql_config_t* p_quote_config);

typedef quote3_error_t (*sgx_ql_free_quote_verification_collateral_t)(
    sgx_ql_qve_collateral_t* p_quote_collateral);

typedef quote3_error_t (*sgx_ql_free_qve_identity_t)(
    char* p_qve_identity,
    char* p_qve_identity_issuer_chain);

typedef quote3_error_t (*sgx_ql_free_root_ca_crl_t)(
    char* p_root_ca_crl);

typedef quote3_error_t(*sgx_ql_get_quote_verification_collateral_t)(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_quote_collateral);

typedef quote3_error_t (*sgx_ql_get_qve_identity_t)(
    char** pp_qve_identity,
    uint32_t* p_qve_identity_size,
    char** pp_qve_identity_issuer_chain,
    uint32_t* p_qve_identity_issuer_chain_size);

typedef quote3_error_t (*sgx_ql_get_root_ca_crl_t)(
    char** pp_root_ca_crl,
    uint16_t* p_root_ca_crl_size);

//
// Invoke via function pointer because that's how both the the Intel
// and Open Enclave stacks load and use this library.
//
static sgx_ql_free_revocation_info_t sgx_ql_free_revocation_info;
static sgx_ql_get_revocation_info_t sgx_ql_get_revocation_info;
static sgx_ql_free_quote_config_t sgx_ql_free_quote_config;
static sgx_ql_get_quote_config_t sgx_ql_get_quote_config;
static sgx_ql_set_logging_function_t sgx_ql_set_logging_function;
static sgx_ql_free_quote_verification_collateral_t sgx_ql_free_quote_verification_collateral;
static sgx_ql_free_qve_identity_t sgx_ql_free_qve_identity;
static sgx_ql_free_root_ca_crl_t sgx_ql_free_root_ca_crl;
static sgx_ql_get_quote_verification_collateral_t sgx_ql_get_quote_verification_collateral;
static sgx_ql_get_qve_identity_t sgx_ql_get_qve_identity;
static sgx_ql_get_root_ca_crl_t sgx_ql_get_root_ca_crl;

// Test FMSPC
static constexpr uint8_t TEST_FMSPC[] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};

// Test input (choose an arbitrary Azure server)
static uint8_t qe_id[16] = {
       0x00, 0xfb, 0xe6, 0x73, 0x33, 0x36, 0xea, 0xf7,
       0xa4, 0xe3, 0xd8, 0xb9, 0x66, 0xa8, 0x2e, 0x64
    };

static sgx_cpu_svn_t cpusvn = {
        0x04, 0x04, 0x02, 0x04, 0xff, 0x80, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

static sgx_isv_svn_t pcesvn = 6;

static sgx_ql_pck_cert_id_t id = {qe_id, sizeof(qe_id), &cpusvn, &pcesvn, 0};


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
        case SGX_QL_LOG_NONE:
            return;
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

    sgx_ql_free_quote_verification_collateral = reinterpret_cast<sgx_ql_free_quote_verification_collateral_t>(dlsym(library, "sgx_ql_free_quote_verification_collateral"));
    assert(sgx_ql_free_quote_verification_collateral);

    sgx_ql_free_qve_identity = reinterpret_cast<sgx_ql_free_qve_identity_t>(dlsym(library, "sgx_ql_free_qve_identity"));
    assert(sgx_ql_free_qve_identity);

    sgx_ql_free_root_ca_crl = reinterpret_cast<sgx_ql_free_root_ca_crl_t>(dlsym(library, "sgx_ql_free_root_ca_crl"));
    assert(sgx_ql_free_root_ca_crl);

    sgx_ql_get_quote_verification_collateral = reinterpret_cast<sgx_ql_get_quote_verification_collateral_t>(dlsym(library, "sgx_ql_get_quote_verification_collateral"));
    assert(sgx_ql_get_quote_verification_collateral);

    sgx_ql_get_qve_identity = reinterpret_cast<sgx_ql_get_qve_identity_t>(dlsym(library, "sgx_ql_get_qve_identity"));
    assert(sgx_ql_get_qve_identity);

    sgx_ql_get_root_ca_crl = reinterpret_cast<sgx_ql_get_root_ca_crl_t>(dlsym(library, "sgx_ql_get_root_ca_crl"));
    assert(sgx_ql_get_root_ca_crl);
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

    sgx_ql_free_quote_verification_collateral = reinterpret_cast<sgx_ql_free_quote_verification_collateral_t>(GetProcAddress(hLibCapdll, "sgx_ql_free_quote_verification_collateral"));
    assert(sgx_ql_free_quote_verification_collateral);

    sgx_ql_free_qve_identity = reinterpret_cast<sgx_ql_free_qve_identity_t>(GetProcAddress(hLibCapdll, "sgx_ql_free_qve_identity"));
    assert(sgx_ql_free_qve_identity);

    sgx_ql_free_root_ca_crl = reinterpret_cast<sgx_ql_free_root_ca_crl_t>(GetProcAddress(hLibCapdll, "sgx_ql_free_root_ca_crl"));
    assert(sgx_ql_free_root_ca_crl);

    sgx_ql_get_quote_verification_collateral = reinterpret_cast<sgx_ql_get_quote_verification_collateral_t>(GetProcAddress(hLibCapdll, "sgx_ql_get_quote_verification_collateral"));
    assert(sgx_ql_get_quote_verification_collateral);

    sgx_ql_get_qve_identity = reinterpret_cast<sgx_ql_get_qve_identity_t>(GetProcAddress(hLibCapdll, "sgx_ql_get_qve_identity"));
    assert(sgx_ql_get_qve_identity);

    sgx_ql_get_root_ca_crl = reinterpret_cast<sgx_ql_get_root_ca_crl_t>(GetProcAddress(hLibCapdll, "sgx_ql_get_root_ca_crl"));
    assert(sgx_ql_get_root_ca_crl);

    return hLibCapdll;
}
#endif

//
// Fetches and validates certification data for a platform
//
static void GetCertsTest()
{
    TEST_START();

    sgx_ql_config_t* config = nullptr;
    // Get the cert data
    Log(SGX_QL_LOG_INFO , "Calling sgx_ql_get_quote_config");
    assert(SGX_QL_SUCCESS == sgx_ql_get_quote_config(&id, &config));
    Log(SGX_QL_LOG_INFO , "sgx_ql_get_quote_config returned");
    assert(nullptr != config);
    
    // Just sanity check a few fields. Parsing the certs would require a big
    // dependency like OpenSSL that we don't necessarily want.
    constexpr sgx_cpu_svn_t CPU_SVN_MAPPED = {
        0x04, 0x04, 0x02, 0x04, 0x01, 0x80, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    constexpr sgx_isv_svn_t pcesvn_mapped = 5;
    assert(0 == memcmp(&CPU_SVN_MAPPED, &config->cert_cpu_svn, sizeof(CPU_SVN_MAPPED)));
    assert(pcesvn_mapped == config->cert_pce_isv_svn);
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

//
// Fetches and validates verification APIs of QPL
//
static void GetVerificationCollateralTest()
{
    TEST_START();

    sgx_ql_qve_collateral_t *collateral = nullptr;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral(TEST_FMSPC, sizeof(TEST_FMSPC), "processor", &collateral);
    assert(SGX_QL_SUCCESS == result);
    assert(collateral != nullptr);

    assert(collateral->version == 1);
    assert(collateral->pck_crl != nullptr);
    assert(collateral->pck_crl_size > 0);
    assert(collateral->pck_crl_issuer_chain != nullptr);
    assert(collateral->pck_crl_issuer_chain_size > 0);

    assert(collateral->qe_identity != nullptr);
    assert(collateral->qe_identity_size > 0);
    assert(collateral->qe_identity_issuer_chain != nullptr);
    assert(collateral->qe_identity_issuer_chain_size > 0);

    assert(collateral->root_ca_crl != nullptr);
    assert(collateral->root_ca_crl_size > 0);

    assert(collateral->tcb_info != nullptr);
    assert(collateral->tcb_info_size > 0);
    assert(collateral->tcb_info_issuer_chain != nullptr);
    assert(collateral->tcb_info_size > 0);

    // Make sure all collateral is terminated with a null character
    assert(collateral->pck_crl[collateral->pck_crl_size - 1] == '\0');
    assert(collateral->pck_crl_issuer_chain[collateral->pck_crl_issuer_chain_size - 1] == '\0');
    assert(collateral->qe_identity[collateral->qe_identity_size - 1] == '\0');
    assert(collateral->qe_identity_issuer_chain[collateral->qe_identity_issuer_chain_size - 1] == '\0');
    assert(collateral->root_ca_crl[collateral->root_ca_crl_size - 1] == '\0');
    assert(collateral->tcb_info[collateral->tcb_info_size - 1] == '\0');
    assert(collateral->tcb_info_issuer_chain[collateral->tcb_info_issuer_chain_size - 1] == '\0');

    sgx_ql_free_quote_verification_collateral(collateral);

    TEST_PASSED();
}

static void GetQveIdentityTest()
{
    TEST_START();

    char *qve_identity = nullptr;
    uint32_t qve_identity_size;
    char *qve_identity_issuer_chain = nullptr;
    uint32_t qve_identity_issuer_chain_size;
    quote3_error_t result = sgx_ql_get_qve_identity(&qve_identity, &qve_identity_size, &qve_identity_issuer_chain, &qve_identity_issuer_chain_size);
    assert(SGX_QL_SUCCESS == result);
    assert(qve_identity != nullptr);
    assert(qve_identity_issuer_chain != nullptr);
    assert(qve_identity_size > 0);
    assert(qve_identity_issuer_chain_size > 0);

    assert(qve_identity[qve_identity_size - 1] == '\0');
    assert(qve_identity_issuer_chain[qve_identity_issuer_chain_size - 1] == '\0');

    sgx_ql_free_qve_identity(qve_identity, qve_identity_issuer_chain);

    TEST_PASSED()
}

static void GetRootCACrlTest()
{
    TEST_START();

    char *root_ca_crl = nullptr;
    uint16_t root_ca_crl_size;
    quote3_error_t result = sgx_ql_get_root_ca_crl(&root_ca_crl, &root_ca_crl_size);
    assert(SGX_QL_SUCCESS == result);
    assert(root_ca_crl != nullptr);
    assert(root_ca_crl_size > 0);
    assert(root_ca_crl[root_ca_crl_size - 1] == '\0');

    sgx_ql_free_root_ca_crl(root_ca_crl);

    TEST_PASSED();
}

// The Windows tolerance is 40ms while the Linux is about 2ms. That's for two reasons:
// 1) The windows system timer runs at a 10ms cadence, meaning that you're not going to see 1ms or 2ms intervals.
// 2) The windows console is synchronous and quite slow relative to the linux console.
#if defined __LINUX__
constexpr auto CURL_TOLERANCE = 0.002;
constexpr auto CURL_FILESYSTEM_TOLERANCE = 0;
#else
constexpr auto CURL_TOLERANCE = 0.04;
constexpr auto CURL_FILESYSTEM_TOLERANCE = 0.025;
#endif

static inline float MeasureFunction(measured_function_t func)
{
    auto start = chrono::steady_clock::now();
    func();
    return (float)chrono::duration_cast<chrono::microseconds>(
               chrono::steady_clock::now() - start).count() / 1000000;
}

void RunQuoteProviderTests(bool caching_enabled = false)
{
    local_cache_clear();

    auto duration_curl_cert = MeasureFunction(GetCertsTest);
    GetCrlTest();

    auto duration_curl_verification =
        MeasureFunction(GetVerificationCollateralTest);

    GetRootCACrlTest();

    //
    // Second pass: Ensure that we ONLY get data from the cache
    //
    auto duration_local_cert = MeasureFunction(GetCertsTest);

    GetCrlTest();
    GetRootCACrlTest();

    auto duration_local_verification =
        MeasureFunction(GetVerificationCollateralTest);

    if (caching_enabled)
    {
        // Ensure that there is a signficiant enough difference between the cert
        // fetch to the end point and cert fetch to local cache and that local
        // cache call is fast enough
        assert(fabs(duration_curl_cert - duration_local_cert) > CURL_TOLERANCE);
        assert(duration_local_cert < CURL_TOLERANCE);
        assert(
            fabs(duration_curl_verification - duration_local_verification) >
            CURL_TOLERANCE);

        constexpr int NUMBER_VERIFICATION_CURL_CALLS = 4;
        assert(
            duration_local_verification <
            (NUMBER_VERIFICATION_CURL_CALLS * (CURL_TOLERANCE + CURL_FILESYSTEM_TOLERANCE)));
    }
}

void ReloadLibrary(libary_type_t *library, bool set_logging_callback = true)
{
#if defined __LINUX__
    dlclose(*library);
    *library = LoadFunctions();
#else 
    FreeLibrary(*library);
    *library = LoadFunctions();
#endif
    if (set_logging_callback)
    {
        assert(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));
    }
}

#ifndef __LINUX__
void set_access(std::string foldername, permission_type_t permission)
{
    PSID p_groupId;
    PSID p_ownerId;
    PACL p_dacl;
    PACL p_sacl;
    PACL new_acl = NULL;
    PSECURITY_DESCRIPTOR p_security_desc = NULL;
    EXPLICIT_ACCESS_A new_ace;
    DWORD lastError = ERROR_SUCCESS;
    DWORD retval;

    retval = GetNamedSecurityInfoA(
        foldername.c_str(),
        SE_FILE_OBJECT,
        GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION |
            LABEL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION |
            ATTRIBUTE_SECURITY_INFORMATION,
        &p_ownerId,
        &p_groupId,
        &p_dacl,
        &p_sacl,
        &p_security_desc);
    if (!SUCCEEDED(retval))
    {
        lastError = GetLastError();
        goto Cleanup;
    }

    // Initialize the new ACE
    RtlZeroMemory(&new_ace, sizeof(new_ace));
    new_ace.grfInheritance = SUB_CONTAINERS_AND_OBJECTS_INHERIT;
    new_ace.Trustee.pMultipleTrustee = NULL;
    new_ace.Trustee.MultipleTrusteeOperation = NO_MULTIPLE_TRUSTEE;
    new_ace.Trustee.TrusteeForm = _TRUSTEE_FORM::TRUSTEE_IS_SID;
    new_ace.Trustee.TrusteeType = _TRUSTEE_TYPE::TRUSTEE_IS_UNKNOWN;
    new_ace.Trustee.ptstrName = (LPCH)p_ownerId;

    // Set the new access permission
    new_ace.grfAccessMode = permission.access_mode;
    new_ace.grfAccessPermissions = permission.access_permissions;
    
    retval = SetEntriesInAclA(1, &new_ace, p_dacl, &new_acl);
    if (!SUCCEEDED(retval))
    {
        lastError = GetLastError();
        goto Cleanup;
    }

    retval = SetNamedSecurityInfoA(
        (LPSTR)foldername.c_str(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION,
        p_ownerId,
        p_groupId,
        new_acl,
        p_sacl);
    if (!SUCCEEDED(retval))
    {
        lastError = GetLastError();
        goto Cleanup;
    }

Cleanup:
    if (p_security_desc != NULL)
    {
        LocalFree(p_security_desc);
    }

    if (new_acl != NULL)
    {
        LocalFree(new_acl);
    }

    if (lastError != ERROR_SUCCESS)
    {
        std::stringstream error_message;
        error_message << "Setting folder permissions failed. Last error: ";
        error_message << lastError;
        Log(SGX_QL_LOG_ERROR, error_message.str().c_str());
        assert(false);
    }
}
#endif

void allow_access(std::string foldername)
{
#if defined __LINUX__
    assert(0 == chmod(foldername.c_str(), 0700));
#else
    set_access(
        foldername,
        {
            STANDARD_RIGHTS_ALL,
            SET_ACCESS,
        });
#endif
}

void make_folder(std::string foldername, permission_type_t permission)
{
#if defined __LINUX__
    assert(0 == mkdir(foldername.c_str(), permission));
#else
    assert(CreateDirectoryA(foldername.c_str(), NULL));
    set_access(foldername, permission);
#endif
}

void change_permission(std::string foldername, permission_type_t permission)
{
#if defined __LINUX__
    assert(0 == chmod(foldername.c_str(), permission));
#else
    set_access(foldername, permission);
#endif
}

bool is_caching_allowed(permission_type_t permission)
{
#if defined __LINUX__
    return permission == 0700;
#else 
    return permission.access_mode == ACCESS_MODE::GRANT_ACCESS &&
           ((permission.access_permissions & (GENERIC_WRITE | GENERIC_READ)) !=
            0);
#endif
}

void remove_folder(std::string foldername)
{
#if defined __LINUX__
    auto delete_command = "rm -rf " + foldername;
#else
    auto delete_command = "del /s /q " + foldername + "\\*";
    assert(0 == system(delete_command.c_str()));
    delete_command = "rmdir /s /q " + foldername;
#endif
    assert(0 == system(delete_command.c_str()));
}

void RunCachePermissionTests(libary_type_t *library)
{
    TEST_START();
    #if defined __LINUX__
        auto permission_folder = "./test_permission";
        int permissions[] = {0700, 0400, 0200, 0000};
        setenv("AZDCAP_CACHE", permission_folder, 1);
    #else 
        auto permission_folder = ".\\test_permission";
    permission_type_t permissions[] = {
            {STANDARD_RIGHTS_ALL, SET_ACCESS}, 
            {GENERIC_READ | GENERIC_WRITE, DENY_ACCESS},
            {GENERIC_READ, DENY_ACCESS},
            {GENERIC_WRITE, DENY_ACCESS}};
        assert(SetEnvironmentVariableA("AZDCAP_CACHE", permission_folder));
    #endif

    // Create the parent folder before the library runs
    for (auto permission : permissions)
    {   
        ReloadLibrary(library);
        make_folder(permission_folder, permission);
        
        RunQuoteProviderTests(is_caching_allowed(permission));
        allow_access(permission_folder);
        remove_folder(permission_folder);
    }

    // Change the permissions on the parent folder after the
    // library has used it
    for (auto permission : permissions)
    {
        ReloadLibrary(library);
        make_folder(permission_folder, permissions[0]);
        RunQuoteProviderTests(true);

        change_permission(permission_folder, permission);

        RunQuoteProviderTests(false);

        allow_access(permission_folder);
        remove_folder(permission_folder);
    }
    
    TEST_PASSED();
}

void SetupEnvironment(std::string version)
{
#if defined __LINUX__
    setenv("AZDCAP_BASE_CERT_URL", "https://global.acccache.azure.net/sgx/certificates", 1);
    setenv("AZDCAP_CLIENT_ID", "AzureDCAPTestsLinux", 1);
    if (!version.empty())
    {
        setenv("AZDCAP_COLLATERAL_VERSION", version.c_str(), 1);
    }
#else
    std::stringstream version_var;
    if (!version.empty())
    {
        assert(SetEnvironmentVariableA(
            "AZDCAP_COLLATERAL_VERSION", version.c_str()));
    }
    assert(SetEnvironmentVariableA(
        "AZDCAP_BASE_CERT_URL",
        "https://global.acccache.azure.net/sgx/certificates"));
    assert(
        SetEnvironmentVariableA("AZDCAP_CLIENT_ID", "AzureDCAPTestsWindows"));
#endif
}

extern void QuoteProvTests()
{
    libary_type_t library = LoadFunctions();

    assert(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("");
    RunQuoteProviderTests();

    //
    // Get the V1 collateral specifically
    //
    SetupEnvironment("v1");
    RunQuoteProviderTests();

    //
    // Get the V2 data from the service
    //
    SetupEnvironment("v2");
    RunQuoteProviderTests();
    GetQveIdentityTest();

    //
    // Run tests without logging to make sure library can operate
    // even if logging callback isn't set
    //
    ReloadLibrary(&library, false);
    RunQuoteProviderTests();
    GetQveIdentityTest();
    // 
    // Run tests to make sure libray can operate
    // even if access to filesystem is restricted
    //
    RunCachePermissionTests(&library);
  
#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}
