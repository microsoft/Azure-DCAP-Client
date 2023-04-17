// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include "../local_cache.h"
#include "dcap_provider.h"
#include "sgx_ql_lib_common.h"

#include <sys/stat.h>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <sstream>

#if defined(__LINUX__)
#include <dlfcn.h>
#include <tgmath.h>
#else
#include <AclAPI.h>
#include <stdlib.h>
#include <windows.h>
#include <iostream>
#endif

using namespace std;

#if defined(__LINUX__)
typedef bool boolean;
#else
#endif

#if defined __LINUX__
typedef void* libary_type_t;
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

typedef quote3_error_t (*tdx_ql_free_quote_verification_collateral_t)(
    tdx_ql_qve_collateral_t* p_quote_collateral);

typedef quote3_error_t (*sgx_ql_free_qve_identity_t)(
    char* p_qve_identity,
    char* p_qve_identity_issuer_chain);

typedef quote3_error_t (*sgx_ql_free_root_ca_crl_t)(char* p_root_ca_crl);

typedef quote3_error_t (*sgx_ql_get_quote_verification_collateral_t)(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_quote_collateral);

typedef quote3_error_t (*sgx_ql_get_quote_verification_collateral_with_params_t)(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    const void* custom_param,
    const uint16_t custom_param_length,
    sgx_ql_qve_collateral_t** pp_quote_collateral);

typedef quote3_error_t (*tdx_ql_get_quote_verification_collateral_t)(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    tdx_ql_qve_collateral_t** pp_quote_collateral);

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
static sgx_ql_free_quote_verification_collateral_t
    sgx_ql_free_quote_verification_collateral;
static tdx_ql_free_quote_verification_collateral_t
    tdx_ql_free_quote_verification_collateral;
static sgx_ql_free_qve_identity_t sgx_ql_free_qve_identity;
static sgx_ql_free_root_ca_crl_t sgx_ql_free_root_ca_crl;
static sgx_ql_get_quote_verification_collateral_t
    sgx_ql_get_quote_verification_collateral;
static sgx_ql_get_quote_verification_collateral_with_params_t
    sgx_ql_get_quote_verification_collateral_with_params;
static tdx_ql_get_quote_verification_collateral_t
    tdx_ql_get_quote_verification_collateral;
static sgx_ql_get_qve_identity_t sgx_ql_get_qve_identity;
static sgx_ql_get_root_ca_crl_t sgx_ql_get_root_ca_crl;

// Test FMSPC
static constexpr uint8_t TEST_FMSPC[] = {0x00, 0x90, 0x6E, 0xA1, 0x00, 0x00};
static constexpr uint8_t ICX_TEST_FMSPC[] = {0x00, 0x60, 0x6a, 0x00, 0x00, 0x00};
static constexpr uint8_t TDX_TEST_FMSPC[] =
    {0x00, 0x80, 0x6F, 0x05, 0x00, 0x00};

const uint16_t custom_param_length = 45;
const char* custom_param = "tcbEvaluationDataNumber=11;region=us central";
std::string tcbEvaluationDataNumber = "11";

const uint16_t incorrect_custom_param_length = 24;
const char* incorrect_custom_param = "tcbEvaluationDataNum=11";

// Test input (choose an arbitrary Azure server)
static uint8_t qe_id[16] = {
    0x00,
    0xfb,
    0xe6,
    0x73,
    0x33,
    0x36,
    0xea,
    0xf7,
    0xa4,
    0xe3,
    0xd8,
    0xb9,
    0x66,
    0xa8,
    0x2e,
    0x64};

static sgx_cpu_svn_t cpusvn = {
    0x04,
    0x04,
    0x02,
    0x04,
    0xff,
    0x80,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00};

static sgx_isv_svn_t pcesvn = 6;

static sgx_ql_pck_cert_id_t id = {qe_id, sizeof(qe_id), &cpusvn, &pcesvn, 0};

static uint8_t icx_qe_id[16] = {
    0x0f,
    0xe3,
    0x21,
    0xfa,
    0xa3,
    0x1e,
    0x76,
    0xda,
    0x3e,
    0xaa,
    0xd8,
    0x27,
    0xab,
    0x69,
    0x07,
    0x19};

static sgx_cpu_svn_t icx_cpusvn = {
    0x04,
    0x04,
    0x03,
    0x08,
    0xff,
    0xff,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00,
    0x00};

static sgx_isv_svn_t icx_pcesvn = 10;

static sgx_ql_pck_cert_id_t icx_id = {icx_qe_id,
                                      sizeof(icx_qe_id),
                                      &icx_cpusvn,
                                      &icx_pcesvn,
                                      0};

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
    // if this assert fails, be sure libdcap_quoteprov.so is in your
    // LD_LIBRARY_PATH

    void* library = dlopen("libdcap_quoteprov.so", RTLD_NOW);
    if (library == nullptr)
    {
        Log(SGX_QL_LOG_ERROR, dlerror());
        abort();
    }

    sgx_ql_free_revocation_info =
        reinterpret_cast<sgx_ql_free_revocation_info_t>(
            dlsym(library, "sgx_ql_free_revocation_info"));
    EXPECT_NE(sgx_ql_free_revocation_info, nullptr);

    sgx_ql_get_revocation_info = reinterpret_cast<sgx_ql_get_revocation_info_t>(
        dlsym(library, "sgx_ql_get_revocation_info"));
    EXPECT_NE(sgx_ql_get_revocation_info, nullptr);

    sgx_ql_free_quote_config = reinterpret_cast<sgx_ql_free_quote_config_t>(
        dlsym(library, "sgx_ql_free_quote_config"));
    EXPECT_NE(sgx_ql_free_quote_config, nullptr);

    sgx_ql_get_quote_config = reinterpret_cast<sgx_ql_get_quote_config_t>(
        dlsym(library, "sgx_ql_get_quote_config"));
    EXPECT_NE(sgx_ql_get_quote_config, nullptr);

    sgx_ql_set_logging_function =
        reinterpret_cast<sgx_ql_set_logging_function_t>(
            dlsym(library, "sgx_ql_set_logging_function"));
    EXPECT_NE(sgx_ql_set_logging_function, nullptr);

    sgx_ql_free_quote_verification_collateral =
        reinterpret_cast<sgx_ql_free_quote_verification_collateral_t>(
            dlsym(library, "sgx_ql_free_quote_verification_collateral"));
    EXPECT_NE(sgx_ql_free_quote_verification_collateral, nullptr);

    tdx_ql_free_quote_verification_collateral =
        reinterpret_cast<tdx_ql_free_quote_verification_collateral_t>(
            dlsym(library, "tdx_ql_free_quote_verification_collateral"));
    EXPECT_NE(tdx_ql_free_quote_verification_collateral, nullptr);

    sgx_ql_free_qve_identity = reinterpret_cast<sgx_ql_free_qve_identity_t>(
        dlsym(library, "sgx_ql_free_qve_identity"));
    EXPECT_NE(sgx_ql_free_qve_identity, nullptr);

    sgx_ql_free_root_ca_crl = reinterpret_cast<sgx_ql_free_root_ca_crl_t>(
        dlsym(library, "sgx_ql_free_root_ca_crl"));
    EXPECT_NE(sgx_ql_free_root_ca_crl, nullptr);

    sgx_ql_get_quote_verification_collateral_with_params = reinterpret_cast<
        sgx_ql_get_quote_verification_collateral_with_params_t>(
        dlsym(library, "sgx_ql_get_quote_verification_collateral_with_params"));
    EXPECT_NE(sgx_ql_get_quote_verification_collateral_with_params, nullptr);

    sgx_ql_get_quote_verification_collateral =
        reinterpret_cast<sgx_ql_get_quote_verification_collateral_t>(
            dlsym(library, "sgx_ql_get_quote_verification_collateral"));
    EXPECT_NE(sgx_ql_get_quote_verification_collateral, nullptr);

    tdx_ql_get_quote_verification_collateral =
        reinterpret_cast<tdx_ql_get_quote_verification_collateral_t>(
            dlsym(library, "tdx_ql_get_quote_verification_collateral"));
    EXPECT_NE(tdx_ql_get_quote_verification_collateral, nullptr);

    sgx_ql_get_qve_identity = reinterpret_cast<sgx_ql_get_qve_identity_t>(
        dlsym(library, "sgx_ql_get_qve_identity"));
    EXPECT_NE(sgx_ql_get_qve_identity, nullptr);

    sgx_ql_get_root_ca_crl = reinterpret_cast<sgx_ql_get_root_ca_crl_t>(
        dlsym(library, "sgx_ql_get_root_ca_crl"));
    EXPECT_NE(sgx_ql_get_root_ca_crl, nullptr);
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
        Log(SGX_QL_LOG_ERROR, std::to_string(error).c_str());
        abort();
    }

    sgx_ql_free_revocation_info =
        reinterpret_cast<sgx_ql_free_revocation_info_t>(
            GetProcAddress(hLibCapdll, "sgx_ql_free_revocation_info"));
    EXPECT_NE(sgx_ql_free_revocation_info, nullptr);

    sgx_ql_get_revocation_info = reinterpret_cast<sgx_ql_get_revocation_info_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_get_revocation_info"));
    EXPECT_NE(sgx_ql_get_revocation_info, nullptr);

    sgx_ql_free_quote_config = reinterpret_cast<sgx_ql_free_quote_config_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_free_quote_config"));
    EXPECT_NE(sgx_ql_free_quote_config, nullptr);

    sgx_ql_get_quote_config = reinterpret_cast<sgx_ql_get_quote_config_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_get_quote_config"));
    EXPECT_NE(sgx_ql_get_quote_config, nullptr);

    sgx_ql_set_logging_function =
        reinterpret_cast<sgx_ql_set_logging_function_t>(
            GetProcAddress(hLibCapdll, "sgx_ql_set_logging_function"));
    EXPECT_NE(sgx_ql_set_logging_function, nullptr);

    sgx_ql_free_quote_verification_collateral =
        reinterpret_cast<sgx_ql_free_quote_verification_collateral_t>(
            GetProcAddress(
                hLibCapdll, "sgx_ql_free_quote_verification_collateral"));
    EXPECT_NE(sgx_ql_free_quote_verification_collateral, nullptr);

    tdx_ql_free_quote_verification_collateral =
        reinterpret_cast<tdx_ql_free_quote_verification_collateral_t>(
            GetProcAddress(
                hLibCapdll, "tdx_ql_free_quote_verification_collateral"));
    EXPECT_NE(tdx_ql_free_quote_verification_collateral, nullptr);

    sgx_ql_free_qve_identity = reinterpret_cast<sgx_ql_free_qve_identity_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_free_qve_identity"));
    EXPECT_NE(sgx_ql_free_qve_identity, nullptr);

    sgx_ql_free_root_ca_crl = reinterpret_cast<sgx_ql_free_root_ca_crl_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_free_root_ca_crl"));
    EXPECT_NE(sgx_ql_free_root_ca_crl, nullptr);

    sgx_ql_get_quote_verification_collateral =
        reinterpret_cast<sgx_ql_get_quote_verification_collateral_t>(
            GetProcAddress(
                hLibCapdll, "sgx_ql_get_quote_verification_collateral"));
    EXPECT_NE(sgx_ql_get_quote_verification_collateral, nullptr);

    sgx_ql_get_quote_verification_collateral_with_params = reinterpret_cast<
        sgx_ql_get_quote_verification_collateral_with_params_t>(GetProcAddress(
        hLibCapdll, "sgx_ql_get_quote_verification_collateral_with_params"));
    EXPECT_NE(sgx_ql_get_quote_verification_collateral_with_params, nullptr);

    tdx_ql_get_quote_verification_collateral =
        reinterpret_cast<tdx_ql_get_quote_verification_collateral_t>(
            GetProcAddress(
                hLibCapdll, "tdx_ql_get_quote_verification_collateral"));
    EXPECT_NE(tdx_ql_get_quote_verification_collateral, nullptr);

    sgx_ql_get_qve_identity = reinterpret_cast<sgx_ql_get_qve_identity_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_get_qve_identity"));
    EXPECT_NE(sgx_ql_get_qve_identity, nullptr);

    sgx_ql_get_root_ca_crl = reinterpret_cast<sgx_ql_get_root_ca_crl_t>(
        GetProcAddress(hLibCapdll, "sgx_ql_get_root_ca_crl"));
    EXPECT_NE(sgx_ql_get_root_ca_crl, nullptr);

    return hLibCapdll;
}
#endif

//
// extract raw value from response body, if exists
//
sgx_plat_error_t extract_from_json(
    const nlohmann::json& json,
    const std::string& item,
    std::string* out_header)
{
    try
    {
        nlohmann::json raw_value = json[item];
        if (!raw_value.is_string())
        {
            raw_value = raw_value.dump();
        }
        if (out_header != nullptr)
        {
            *out_header = raw_value;
        }
    }
    catch (const exception& ex)
    {
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    return SGX_PLAT_ERROR_OK;
}

//
// Fetches and validates certification data for a platform
//
static void GetCertsTest()
{
    boolean TEST_SUCCESS = false;
    sgx_ql_config_t* config = nullptr;
    // Get the cert data
    Log(SGX_QL_LOG_INFO, "Calling sgx_ql_get_quote_config");
    ASSERT_TRUE(SGX_QL_SUCCESS == sgx_ql_get_quote_config(&id, &config));
    Log(SGX_QL_LOG_INFO, "sgx_ql_get_quote_config returned");
    ASSERT_TRUE(nullptr != config);

    // Just sanity check a few fields. Parsing the certs would require a big
    // dependency like OpenSSL that we don't necessarily want.
    constexpr sgx_cpu_svn_t CPU_SVN_MAPPED = {
        0x04,
        0x04,
        0x02,
        0x04,
        0x01,
        0x80,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00};
    constexpr sgx_isv_svn_t pcesvn_mapped = 5;
    ASSERT_TRUE(0 == memcmp(&CPU_SVN_MAPPED, &config->cert_cpu_svn, sizeof(CPU_SVN_MAPPED)));
    ASSERT_TRUE(pcesvn_mapped == config->cert_pce_isv_svn);
    ASSERT_TRUE(SGX_QL_CONFIG_VERSION_1 == config->version);
    ASSERT_TRUE(0 < config->cert_data_size);
    ASSERT_TRUE(nullptr != config->p_cert_data);
    ASSERT_TRUE(SGX_QL_SUCCESS == sgx_ql_free_quote_config(config));
    TEST_SUCCESS = true;
    ASSERT_TRUE(TEST_SUCCESS);
}

static void GetCertsTestICXV3()
{
    boolean TEST_SUCCESS = false;
    sgx_ql_config_t* config = nullptr;

    // Get the cert data
    Log(SGX_QL_LOG_INFO, "Calling sgx_ql_get_quote_config");
    ASSERT_TRUE(SGX_QL_SUCCESS == sgx_ql_get_quote_config(&icx_id, &config));
    Log(SGX_QL_LOG_INFO, "sgx_ql_get_quote_config returned");
    ASSERT_TRUE(nullptr != config);

    // Just sanity check a few fields. Parsing the certs would require a big
    // dependency like OpenSSL that we don't necessarily want.
    constexpr sgx_cpu_svn_t CPU_SVN_MAPPED = {
        0x04,
        0x04,
        0x03,
        0x03,
        0xff,
        0xff,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00};
    constexpr sgx_isv_svn_t pcesvn_mapped = 10;
    ASSERT_TRUE(0 == memcmp(&CPU_SVN_MAPPED, &config->cert_cpu_svn, sizeof(CPU_SVN_MAPPED)));
    ASSERT_TRUE(pcesvn_mapped == config->cert_pce_isv_svn);
    ASSERT_TRUE(SGX_QL_CONFIG_VERSION_1 == config->version);
    ASSERT_TRUE(0 < config->cert_data_size);
    ASSERT_TRUE(nullptr != config->p_cert_data);
    ASSERT_TRUE(SGX_QL_SUCCESS == sgx_ql_free_quote_config(config));
    TEST_SUCCESS = true;
    ASSERT_TRUE(TEST_SUCCESS);
}

static inline void VerifyCrlOutput(sgx_ql_get_revocation_info_params_t params)
{
    boolean TEST_SUCCESS = false;
    sgx_ql_revocation_info_t* output;
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_get_revocation_info(&params, &output));
    ASSERT_TRUE(0 < output->tcb_info_size);
    ASSERT_TRUE(nullptr != output->tcb_info);
    ASSERT_TRUE(1 == output->crl_count);
    ASSERT_TRUE(0 < output->crls[0].crl_data_size);
    ASSERT_TRUE(nullptr != output->crls[0].crl_data);
    sgx_ql_free_revocation_info(output);
    TEST_SUCCESS = true;
    ASSERT_TRUE(TEST_SUCCESS);
}

//
// Fetches and validates revocation data for SGX
//
static void GetCrlTest()
{
    // This is the CRL DP used by Intel for leaf certs
    static const char* TEST_CRL_URL = "https://api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca=processor";
    sgx_ql_get_revocation_info_params_t params = {
        SGX_QL_REVOCATION_INFO_VERSION_1,
        sizeof(TEST_FMSPC),
        TEST_FMSPC,
        1,
        &TEST_CRL_URL};
    VerifyCrlOutput(params);
}

//
// Fetches and validates revocation data for SGX
//
static void GetCrlTestICXV3()
{
    static const char* TEST_CRL_URL = "https://api.trustedservices.intel.com/sgx/certification/v3/pckcrl?ca=platform&encoding=pem";
    sgx_ql_get_revocation_info_params_t params = {
        SGX_QL_REVOCATION_INFO_VERSION_1,
        sizeof(ICX_TEST_FMSPC),
        ICX_TEST_FMSPC,
        1,
        &TEST_CRL_URL};
    VerifyCrlOutput(params);
}

static inline void VerifyCollateralCommon(sgx_ql_qve_collateral_t* collateral)
{
    ASSERT_TRUE(collateral != nullptr);
    ASSERT_TRUE(collateral->version == 1 || (collateral->major_version == 4 && collateral->minor_version == 0));
    ASSERT_TRUE(collateral->tee_type == 0x0 || collateral->tee_type == 0x81);
    ASSERT_TRUE(collateral->pck_crl != nullptr);
    ASSERT_TRUE(collateral->pck_crl_size > 0);
    ASSERT_TRUE(collateral->pck_crl_issuer_chain != nullptr);
    ASSERT_TRUE(collateral->pck_crl_issuer_chain_size > 0);
    ASSERT_TRUE(collateral->qe_identity != nullptr);
    ASSERT_TRUE(collateral->qe_identity_size > 0);
    ASSERT_TRUE(collateral->qe_identity_issuer_chain != nullptr);
    ASSERT_TRUE(collateral->qe_identity_issuer_chain_size > 0);
    ASSERT_TRUE(collateral->root_ca_crl != nullptr);
    ASSERT_TRUE(collateral->root_ca_crl_size > 0);
    ASSERT_TRUE(collateral->tcb_info != nullptr);
    ASSERT_TRUE(collateral->tcb_info_size > 0);
    ASSERT_TRUE(collateral->tcb_info_issuer_chain != nullptr);
    ASSERT_TRUE(collateral->tcb_info_size > 0);

    // Make sure all collateral is terminated with a null character
    ASSERT_TRUE(collateral->pck_crl[collateral->pck_crl_size - 1] == '\0');
    ASSERT_TRUE(collateral->pck_crl_issuer_chain[collateral->pck_crl_issuer_chain_size - 1] == '\0');
    ASSERT_TRUE(collateral->qe_identity[collateral->qe_identity_size - 1] == '\0');
    ASSERT_TRUE(collateral->qe_identity_issuer_chain[collateral->qe_identity_issuer_chain_size - 1] == '\0');
    ASSERT_TRUE(collateral->root_ca_crl[collateral->root_ca_crl_size - 1] == '\0');
    ASSERT_TRUE(collateral->tcb_info[collateral->tcb_info_size - 1] == '\0');
    ASSERT_TRUE(collateral->tcb_info_issuer_chain[collateral->tcb_info_issuer_chain_size - 1] == '\0');
}

static inline void VerifyCollateral(sgx_ql_qve_collateral_t* collateral)
{
    boolean TEST_SUCCESS = false;
    VerifyCollateralCommon(collateral);
    sgx_ql_free_quote_verification_collateral(collateral);
    TEST_SUCCESS = true;
    ASSERT_TRUE(TEST_SUCCESS);
}

static inline void VerifyCollateralTDX(tdx_ql_qve_collateral_t* collateral)
{
    boolean TEST_SUCCESS = false;
    VerifyCollateralCommon(collateral);
    tdx_ql_free_quote_verification_collateral(collateral);
    TEST_SUCCESS = true;
    ASSERT_TRUE(TEST_SUCCESS);
}

//
// Fetches and validates verification APIs of QPL
//
static void GetVerificationCollateralTest()
{
    sgx_ql_qve_collateral_t* collateral = nullptr;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral(
        TEST_FMSPC,
        sizeof(TEST_FMSPC),
        "processor",
        &collateral);
    ASSERT_TRUE(SGX_QL_SUCCESS == result);
    VerifyCollateral(collateral);
}

//
// Fetches and validates verification APIs of QPL with custom params provided
//
static void GetVerificationCollateralTestWithParams()
{
    // Test input (choose an arbitrary Azure server)
    sgx_ql_qve_collateral_t* collateral = nullptr;
    std::string tcbInfoTcbEvaluationDataNumber;
    std::string enclaveIdentityTcbEvaluationDataNumber;
    nlohmann::json json_body;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral_with_params(
            TEST_FMSPC,
            sizeof(TEST_FMSPC),
            "processor",
            custom_param,
            custom_param_length,
            &collateral);
    ASSERT_TRUE(SGX_QL_SUCCESS == result);
    json_body = nlohmann::json::parse(collateral->tcb_info);
    extract_from_json(
        json_body.flatten(),
        "/tcbInfo/tcbEvaluationDataNumber",
        &tcbInfoTcbEvaluationDataNumber);
    ASSERT_TRUE(tcbInfoTcbEvaluationDataNumber.compare(tcbEvaluationDataNumber) == 0);
    json_body = nlohmann::json::parse(collateral->qe_identity);
    extract_from_json(
        json_body.flatten(),
        "/enclaveIdentity/tcbEvaluationDataNumber",
        &enclaveIdentityTcbEvaluationDataNumber);
    ASSERT_TRUE(enclaveIdentityTcbEvaluationDataNumber.compare(tcbEvaluationDataNumber) == 0);
    VerifyCollateral(collateral);
}

//
// Validates the return code if curl request to the THIM service failed.
//
static void GetVerificationCollateralTestWithIncorrectParams()
{
    // Test input (choose an arbitrary Azure server)

    sgx_ql_qve_collateral_t* collateral = nullptr;
    nlohmann::json json_body;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral_with_params(
            TEST_FMSPC,
            sizeof(TEST_FMSPC),
            "processor",
            incorrect_custom_param,
            incorrect_custom_param_length,
            &collateral);
    ASSERT_TRUE(SGX_QL_NO_QUOTE_COLLATERAL_DATA == result);
}

//
// Fetches and validates verification APIs of QPL
//
static void GetVerificationCollateralTestICXV3()
{
    sgx_ql_qve_collateral_t* collateral = nullptr;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral(
        ICX_TEST_FMSPC,
        sizeof(ICX_TEST_FMSPC),
        "platform",
        &collateral);
    ASSERT_TRUE(SGX_QL_SUCCESS == result);
    VerifyCollateral(collateral);
}

//
// Fetches and validates verification APIs of QPL with custom params provided
//
static void GetVerificationCollateralTestICXV3WithParams()
{
    sgx_ql_qve_collateral_t* collateral = nullptr;
    std::string tcbEvaluationDataNumber;
    std::string enclaveIdentityTcbEvaluationDataNumber;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral_with_params(
            ICX_TEST_FMSPC,
            sizeof(ICX_TEST_FMSPC),
            "platform",
            custom_param,
            custom_param_length,
            &collateral);
    ASSERT_TRUE(SGX_QL_SUCCESS == result);
    nlohmann::json json_body = nlohmann::json::parse(collateral->tcb_info);
    extract_from_json(
        json_body.flatten(),
        "/tcbInfo/tcbEvaluationDataNumber",
        &tcbEvaluationDataNumber);
    ASSERT_TRUE(tcbEvaluationDataNumber.compare(tcbEvaluationDataNumber) == 0);
    json_body = nlohmann::json::parse(collateral->qe_identity);
    extract_from_json(
        json_body.flatten(),
        "/enclaveIdentity/tcbEvaluationDataNumber",
        &enclaveIdentityTcbEvaluationDataNumber);
    ASSERT_TRUE(
        enclaveIdentityTcbEvaluationDataNumber.compare(tcbEvaluationDataNumber) == 0);
    VerifyCollateral(collateral);
}

//
// Validates the return code if curl request to the THIM service failed.
//
static void GetVerificationCollateralTestICXV3WithIncorrectParams()
{
    sgx_ql_qve_collateral_t* collateral = nullptr;
    quote3_error_t result = sgx_ql_get_quote_verification_collateral_with_params(
            ICX_TEST_FMSPC,
            sizeof(ICX_TEST_FMSPC),
            "platform",
            incorrect_custom_param,
            incorrect_custom_param_length,
            &collateral);
    ASSERT_TRUE(SGX_QL_NO_QUOTE_COLLATERAL_DATA == result);
}

static void GetVerificationCollateralTestTDX()
{
	local_cache_clear();
    tdx_ql_qve_collateral_t* collateral = nullptr;
    quote3_error_t result = tdx_ql_get_quote_verification_collateral(
        TDX_TEST_FMSPC, sizeof(TDX_TEST_FMSPC), "processor", &collateral);
    ASSERT_TRUE(SGX_QL_SUCCESS == result);
    VerifyCollateralTDX(collateral);
}

static boolean GetQveIdentityTest()
{
    boolean TEST_SUCCESS = false;
    char* qve_identity = nullptr;
    uint32_t qve_identity_size;
    char* qve_identity_issuer_chain = nullptr;
    uint32_t qve_identity_issuer_chain_size;
    quote3_error_t result = sgx_ql_get_qve_identity(
        &qve_identity,
        &qve_identity_size,
        &qve_identity_issuer_chain,
        &qve_identity_issuer_chain_size);
    EXPECT_TRUE(SGX_QL_SUCCESS == result);
    EXPECT_TRUE(qve_identity != nullptr);
    EXPECT_TRUE(qve_identity_issuer_chain != nullptr);
    EXPECT_TRUE(qve_identity_size > 0);
    EXPECT_TRUE(qve_identity_issuer_chain_size > 0);
    EXPECT_TRUE(qve_identity[qve_identity_size - 1] == '\0');
    EXPECT_TRUE(qve_identity_issuer_chain[qve_identity_issuer_chain_size - 1] == '\0');
    sgx_ql_free_qve_identity(qve_identity, qve_identity_issuer_chain);
    TEST_SUCCESS = true;
    return TEST_SUCCESS;
}

static void GetRootCACrlTest()
{
    boolean TEST_SUCCESS = false;
    char* root_ca_crl = nullptr;
    uint16_t root_ca_crl_size;
    quote3_error_t result =
        sgx_ql_get_root_ca_crl(&root_ca_crl, &root_ca_crl_size);
    ASSERT_TRUE(SGX_QL_SUCCESS == result);
    ASSERT_TRUE(root_ca_crl != nullptr);
    ASSERT_TRUE(root_ca_crl_size > 0);
    ASSERT_TRUE(root_ca_crl[root_ca_crl_size - 1] == '\0');
    sgx_ql_free_root_ca_crl(root_ca_crl);
    TEST_SUCCESS = true;
    ASSERT_TRUE(TEST_SUCCESS);
}

#ifdef __LINUX__
constexpr auto CURL_TOLERANCE = 0.002;
#else
constexpr auto CURL_TOLERANCE = 0.008;
#endif

static inline float MeasureFunction(measured_function_t func)
{
    auto start = chrono::steady_clock::now();
    func();
    return (float)chrono::duration_cast<chrono::microseconds>(
               chrono::steady_clock::now() - start)
               .count() /
           1000000;
}

static inline void VerifyDurationChecks(
    float duration_local_cert,
    float duration_local_verification,
    float duration_curl_cert,
    float duration_curl_verification,
    bool caching_enabled = false)
{
    if (caching_enabled)
    {
        // Ensure that there is a signficiant enough difference between the cert
        // fetch to the end point and cert fetch to local cache and that local
        // cache call is fast enough
        constexpr auto PERMISSION_CHECK_TEST_TOLERANCE = CURL_TOLERANCE;
        EXPECT_TRUE(
            fabs(duration_curl_cert - duration_local_cert) > CURL_TOLERANCE);
        EXPECT_TRUE(
            duration_local_cert <
            (CURL_TOLERANCE + PERMISSION_CHECK_TEST_TOLERANCE));
        EXPECT_TRUE(
            fabs(duration_curl_verification - duration_local_verification) >
            CURL_TOLERANCE);
        constexpr int NUMBER_VERIFICATION_CURL_CALLS = 4;
        EXPECT_TRUE(
            duration_local_verification <
            (NUMBER_VERIFICATION_CURL_CALLS * PERMISSION_CHECK_TEST_TOLERANCE));
    }
}

static inline void VerifyDurationChecks(
    float duration_local_cert,
    float duration_curl_cert,
    bool caching_enabled = false)
{
    if (caching_enabled)
    {
        // Ensure that there is a signficiant enough difference between the cert
        // fetch to the end point and cert fetch to local cache and that local
        // cache call is fast enough
        constexpr auto PERMISSION_CHECK_TEST_TOLERANCE = CURL_TOLERANCE;
        EXPECT_TRUE(
            fabs(duration_curl_cert - duration_local_cert) > CURL_TOLERANCE);
        EXPECT_TRUE(
            duration_local_cert <
            (CURL_TOLERANCE + PERMISSION_CHECK_TEST_TOLERANCE));
    }
}

boolean RunQuoteProviderTests(bool caching_enabled = false)
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
    auto duration_local_verification = MeasureFunction(GetVerificationCollateralTest);
    VerifyDurationChecks(
        duration_local_cert,
        duration_local_verification,
        duration_curl_cert,
        duration_curl_verification,
        caching_enabled);
    return true;
}

boolean RunQuoteProviderTestsWithCustomParams(bool caching_enabled = false)
{
    local_cache_clear();
    auto duration_curl_cert = MeasureFunction(GetCertsTest);
    GetCrlTest();
    auto duration_curl_verification_with_params =
        MeasureFunction(GetVerificationCollateralTestWithParams);
    GetRootCACrlTest();

    //
    // Second pass: Ensure that we ONLY get data from the cache
    //
    auto duration_local_cert = MeasureFunction(GetCertsTest);
    GetCrlTest();
    GetRootCACrlTest();
    auto duration_local_verification_with_params =
        MeasureFunction(GetVerificationCollateralTestWithParams);
    VerifyDurationChecks(
        duration_local_cert,
        duration_local_verification_with_params,
        duration_curl_cert,
        duration_curl_verification_with_params,
        caching_enabled);

    return true;
}

boolean RunQuoteProviderTestsICXV3(bool caching_enabled = false)
{
    local_cache_clear();
    auto duration_curl_cert = MeasureFunction(GetCertsTestICXV3);
    GetCrlTestICXV3();
    auto duration_curl_verification = MeasureFunction(GetVerificationCollateralTestICXV3);
    GetRootCACrlTest();

    //
    // Second pass: Ensure that we ONLY get data from the cache
    //
    auto duration_local_cert = MeasureFunction(GetCertsTestICXV3);
    GetCrlTestICXV3();
    GetRootCACrlTest();
    auto duration_local_verification = MeasureFunction(GetVerificationCollateralTestICXV3);
    VerifyDurationChecks(
        duration_local_cert,
        duration_local_verification,
        duration_curl_cert,
        duration_curl_verification,
        caching_enabled);
    return true;
}

boolean RunQuoteProviderTestsICXV3WithParam(bool caching_enabled = false)
{
    local_cache_clear();
    auto duration_curl_cert = MeasureFunction(GetCertsTestICXV3);
    GetCrlTestICXV3();
    auto duration_curl_verification_with_params =
        MeasureFunction(GetVerificationCollateralTestICXV3WithParams);
    GetRootCACrlTest();

    //
    // Second pass: Ensure that we ONLY get data from the cache
    //
    auto duration_local_cert = MeasureFunction(GetCertsTestICXV3);
    GetCrlTestICXV3();
    GetRootCACrlTest();
    auto duration_local_verification_with_params =
        MeasureFunction(GetVerificationCollateralTestICXV3WithParams);
    VerifyDurationChecks(
        duration_local_cert,
        duration_local_verification_with_params,
        duration_curl_cert,
        duration_curl_verification_with_params,
        caching_enabled);
    return true;
}

void ReloadLibrary(libary_type_t* library, bool set_logging_callback = true)
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
        ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));
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
        FAIL() << "We shouldn't get here.";
    }
}
#endif

void allow_access(std::string foldername)
{
#if defined __LINUX__
    ASSERT_TRUE(0 == chmod(foldername.c_str(), 0700));
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
    ASSERT_TRUE(0 == mkdir(foldername.c_str(), permission));
#else
    ASSERT_TRUE(CreateDirectoryA(foldername.c_str(), NULL));
    set_access(foldername, permission);
#endif
}

void change_permission(std::string foldername, permission_type_t permission)
{
#if defined __LINUX__
    ASSERT_TRUE(0 == chmod(foldername.c_str(), permission));
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
    ASSERT_TRUE(0 == system(delete_command.c_str()));
    delete_command = "rmdir /s /q " + foldername;
#endif
    ASSERT_TRUE(0 == system(delete_command.c_str()));
}

boolean RunCachePermissionTests(libary_type_t* library)
{
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
        {GENERIC_WRITE, DENY_ACCESS}
    };
    EXPECT_TRUE(SetEnvironmentVariableA("AZDCAP_CACHE", permission_folder));
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

    return true;
}

boolean RunCachePermissionTestsWithCustomParamToFetchCollateral(libary_type_t* library)
{
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
        {GENERIC_WRITE, DENY_ACCESS}
    };
    EXPECT_TRUE(SetEnvironmentVariableA("AZDCAP_CACHE", permission_folder));
#endif

    // Create the parent folder before the library runs
    for (auto permission : permissions)
    {
        ReloadLibrary(library);
        make_folder(permission_folder, permission);
        RunQuoteProviderTestsWithCustomParams(is_caching_allowed(permission));
        allow_access(permission_folder);
        remove_folder(permission_folder);
    }

    // Change the permissions on the parent folder after the
    // library has used it
    for (auto permission : permissions)
    {
        ReloadLibrary(library);
        make_folder(permission_folder, permissions[0]);
        RunQuoteProviderTestsWithCustomParams(true);
        change_permission(permission_folder, permission);
        RunQuoteProviderTestsWithCustomParams(false);
        allow_access(permission_folder);
        remove_folder(permission_folder);
    }

    return true;
}

void SetupEnvironment(std::string version)
{
#if defined __LINUX__
    setenv(
        "AZDCAP_PRIMARY_BASE_CERT_URL",
        "http://169.254.169.254/metadata/THIM/sgx/certification",
        1);
    setenv(
        "ENV_AZDCAP_SECONDARY_BASE_CERT_URL",
        "https://global.acccache.azure.net/sgx/certification",
        1);
    setenv(
        "ENV_AZDCAP_BASE_URL",
        "https://global.acccache.azure.net/sgx/certification",
        1);
    setenv("AZDCAP_CLIENT_ID", "AzureDCAPTestsLinux", 1);
    if (!version.empty())
    {
        setenv("AZDCAP_COLLATERAL_VERSION", version.c_str(), 1);
    }
#else
    std::stringstream version_var;
    if (!version.empty())
    {
        EXPECT_TRUE(SetEnvironmentVariableA(
            "AZDCAP_COLLATERAL_VERSION", version.c_str()));
    }
    EXPECT_TRUE(SetEnvironmentVariableA(
        "AZDCAP_PRIMARY_BASE_CERT_URL",
        "http://169.254.169.254/metadata/THIM/sgx/certification"));
    EXPECT_TRUE(SetEnvironmentVariableA(
        "AZDCAP_SECONDARY_BASE_CERT_URL",
        "https://global.acccache.azure.net/sgx/certification"));
    EXPECT_TRUE(SetEnvironmentVariableA(
        "AZDCAP_BASE_CERT_URL",
        "https://global.acccache.azure.net/sgx/certification"));
    EXPECT_TRUE(
        SetEnvironmentVariableA("AZDCAP_CLIENT_ID", "AzureDCAPTestsWindows"));
#endif
}

void SetupEnvironmentTDX(std::string version)
{
#if defined __LINUX__
    setenv(
		"AZDCAP_PRIMARY_BASE_CERT_URL", 
		"", 
		1);
    setenv(
        "ENV_AZDCAP_SECONDARY_BASE_CERT_URL",
        "",
        1);
    setenv(
        "AZDCAP_BASE_CERT_URL_TDX",
        "",
        1);
    setenv(
        "AZDCAP_REGION_URL",
        "eastus2euap",
        1);
    setenv("AZDCAP_CLIENT_ID", "AzureDCAPTestsLinux", 1);
    if (!version.empty())
    {
        setenv("AZDCAP_COLLATERAL_VERSION_TDX", version.c_str(), 1);
    }
#else
    std::stringstream version_var;
    EXPECT_TRUE(SetEnvironmentVariableA(
        "AZDCAP_PRIMARY_BASE_CERT_URL",
        ""));
    EXPECT_TRUE(SetEnvironmentVariableA(
        "AZDCAP_SECONDARY_BASE_CERT_URL", ""));
    EXPECT_TRUE(SetEnvironmentVariableA(
		"AZDCAP_BASE_CERT_URL_TDX", ""));
    EXPECT_TRUE(SetEnvironmentVariableA(
        "AZDCAP_REGION_URL",
        "eastus2euap"));
    EXPECT_TRUE(
        SetEnvironmentVariableA("AZDCAP_CLIENT_ID", "AzureDCAPTestsWindows"));
    if (!version.empty())
    {
        EXPECT_TRUE(SetEnvironmentVariableA(
            "AZDCAP_COLLATERAL_VERSION_TDX", version.c_str()));
    }
#endif
}

void SetupEnvironmentToReachSecondary()
{
#if defined __LINUX__
    setenv("AZDCAP_BYPASS_BASE_URL", "true", 1);
#else
    EXPECT_TRUE(SetEnvironmentVariableA("AZDCAP_BYPASS_BASE_URL", "true"));
#endif
}

TEST(testQuoteProv, quoteProviderTestsData)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("");
    ASSERT_TRUE(RunQuoteProviderTests());

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, quoteProviderTestsV2DataFromService)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v2");
    SetupEnvironmentToReachSecondary();
    ASSERT_TRUE(RunQuoteProviderTests());
    ASSERT_TRUE(RunQuoteProviderTestsWithCustomParams());
    ASSERT_TRUE(GetQveIdentityTest());

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, quoteProviderTestsV2Data)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v2");
    ASSERT_TRUE(RunQuoteProviderTests());
    ASSERT_TRUE(RunQuoteProviderTestsWithCustomParams());
    ASSERT_TRUE(GetQveIdentityTest());

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, quoteProviderTestsV3DataFromService)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v3");
    SetupEnvironmentToReachSecondary();
    ASSERT_TRUE(RunQuoteProviderTests());
    ASSERT_TRUE(RunQuoteProviderTestsICXV3());
    ASSERT_TRUE(RunQuoteProviderTestsICXV3WithParam());
    ASSERT_TRUE(GetQveIdentityTest());

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, quoteProviderTestsV3Data)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v3");
    ASSERT_TRUE(RunQuoteProviderTests());
    ASSERT_TRUE(RunQuoteProviderTestsICXV3());
    ASSERT_TRUE(RunQuoteProviderTestsICXV3WithParam());
    ASSERT_TRUE(GetQveIdentityTest());

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, quoteProviderTestsGetVerificationCollateralTDX)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironmentTDX("v4");
    GetVerificationCollateralTestTDX();

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, quoteProviderTestsWithIncorrectCustomParam)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v2");
    GetVerificationCollateralTestWithIncorrectParams();
    SetupEnvironment("v3");
    GetVerificationCollateralTestICXV3WithIncorrectParams();

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}
TEST(testQuoteProv, testWithoutLogging)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v2");
    ReloadLibrary(&library, false);
    ASSERT_TRUE(RunQuoteProviderTestsWithCustomParams());
    ASSERT_TRUE(GetQveIdentityTest());

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, testRestrictAccessToFilesystem)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v2");
    SetupEnvironmentToReachSecondary();
    ReloadLibrary(&library, false);
    ASSERT_TRUE(RunCachePermissionTests(&library));

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProv, testRestrictAccessToFilesystemForCustomParamCollateral)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

    //
    // Get the data from the service
    //
    SetupEnvironment("v2");
    SetupEnvironmentToReachSecondary();
    ReloadLibrary(&library, false);
    ASSERT_TRUE(
        RunCachePermissionTestsWithCustomParamToFetchCollateral(&library));

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}

TEST(testQuoteProvServiceVM, quoteProviderServiceVMTestsData)
{
    libary_type_t library = LoadFunctions();
    ASSERT_TRUE(SGX_PLAT_ERROR_OK == sgx_ql_set_logging_function(Log));

#if defined __SERVICE_VM__
    //
    // Get the data from THIMAgent
    //
    Log(SGX_QL_LOG_INFO, "Clearing Cache.");
    local_cache_clear();

    Log(SGX_QL_LOG_INFO, "Fetching certificate from THIMAgent.");
    auto duration_curl_cert = MeasureFunction(GetCertsTest);

    //
    // Second pass: Ensure that we ONLY get data from the cache
    //
    Log(SGX_QL_LOG_INFO, "Fetching certificate from cache.");
    auto duration_local_cert = MeasureFunction(GetCertsTest);
    VerifyDurationChecks(
        duration_local_cert,
        duration_curl_cert,
        false);
#else
    Log(SGX_QL_LOG_INFO,
        "Service VM flag was not set during compilation. No Service VM tests were executed.");
#endif

#if defined __LINUX__
    dlclose(library);
#else
    FreeLibrary(library);
#endif
}