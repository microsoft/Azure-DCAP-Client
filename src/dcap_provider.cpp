// Licensed under the MIT License.

#include "dcap_provider.h"
#include "curl_easy.h"

#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include "intel/sgx_ql_lib_common.h"

#ifdef __LINUX__
#include <arpa/inet.h>
#else
#include <intsafe.h>
#include <winsock.h>
#endif

// We need std::numeric_limits::max; ensure no macros are clobbering it.
#ifdef max
#undef max
#endif

// External function names are dictated by Intel
// ReSharper disable CppInconsistentNaming

namespace headers
{
constexpr char PCK_CERT_ISSUER_CHAIN[] = "SGX-PCK-Certificate-Issuer-Chain";
constexpr char CRL_ISSUER_CHAIN[] = "SGX-PCK-CRL-Issuer-Chain";
constexpr char TCB_INFO_ISSUER_CHAIN[] = "SGX-TCB-Info-Issuer-Chain";
constexpr char TCB_INFO[] = "SGX-TCBm";
constexpr char CONTENT_TYPE[] = "Content-Type";
constexpr char QE_ISSUER_CHAIN[] = "SGX-QE-Identity-Issuer-Chain";
constexpr char REQUEST_ID[] = "Request-ID";
};

static constexpr char CYBERTRUST_ROOT_CERT[] =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ\n"
    "RTESMBAGA1UEChMJQmFsdGltb3JlMRMwEQYDVQQLEwpDeWJlclRydXN0MSIwIAYD\n"
    "VQQDExlCYWx0aW1vcmUgQ3liZXJUcnVzdCBSb290MB4XDTAwMDUxMjE4NDYwMFoX\n"
    "DTI1MDUxMjIzNTkwMFowWjELMAkGA1UEBhMCSUUxEjAQBgNVBAoTCUJhbHRpbW9y\n"
    "ZTETMBEGA1UECxMKQ3liZXJUcnVzdDEiMCAGA1UEAxMZQmFsdGltb3JlIEN5YmVy\n"
    "VHJ1c3QgUm9vdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKMEuyKr\n"
    "mD1X6CZymrV51Cni4eiVgLGw41uOKymaZN+hXe2wCQVt2yguzmKiYv60iNoS6zjr\n"
    "IZ3AQSsBUnuId9Mcj8e6uYi1agnnc+gRQKfRzMpijS3ljwumUNKoUMMo6vWrJYeK\n"
    "mpYcqWe4PwzV9/lSEy/CG9VwcPCPwBLKBsua4dnKM3p31vjsufFoREJIE9LAwqSu\n"
    "XmD+tqYF/LTdB1kC1FkYmGP1pWPgkAx9XbIGevOF6uvUA65ehD5f/xXtabz5OTZy\n"
    "dc93Uk3zyZAsuT3lySNTPx8kmCFcB5kpvcY67Oduhjprl3RjM71oGDHweI12v/ye\n"
    "jl0qhqdNkNwnGjkCAwEAAaNFMEMwHQYDVR0OBBYEFOWdWTCCR1jMrPoIVDaGezq1\n"
    "BE3wMBIGA1UdEwEB/wQIMAYBAf8CAQMwDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3\n"
    "DQEBBQUAA4IBAQCFDF2O5G9RaEIFoN27TyclhAO992T9Ldcw46QQF+vaKSm2eT92\n"
    "9hkTI7gQCvlYpNRhcL0EYWoSihfVCr3FvDB81ukMJY2GQE/szKN+OMY3EU/t3Wgx\n"
    "jkzSswF07r51XgdIGn9w/xZchMB5hbgF/X++ZRGjD8ACtPhSNzkE1akxehi/oCr0\n"
    "Epn3o0WC4zxe9Z2etciefC7IpJ5OCBRLbf1wbWsaY71k5h+3zvDyny67G7fyUIhz\n"
    "ksLi4xaNmjICq44Y3ekQEe5+NauQrz4wlHrQMz2nZQ/1/I6eYs9HRCwBXbsdtTLS\n"
    "R9I4LtD+gdwyah617jzV/OeBHRnDJELqYzmp\n"
    "-----END CERTIFICATE-----";

constexpr char API_VERSION[] = "api-version=2018-10-01-preview";

static char DEFAULT_CERT_URL[] =
    "https://pck-cache-prod-webapp-eastus.azurewebsites.net/sgx/certificates";
static std::string cert_base_url = DEFAULT_CERT_URL;

// Before Azure PCK service supports caching qe identity, fetch directly from
// Intel server for now
static char QE_IDENTITY_URL[] =
    "https://api.trustedservices.intel.com/sgx/certification/v1/qe/identity";

#if 0 // Flip this to true for easy local debugging
static void DefaultLogCallback(sgx_ql_log_level_t level, const char* message)
{
    printf("Azure Quote Provider: libdcap_quoteprov.so [%s]: %s\n", level == SGX_QL_LOG_ERROR ? "ERROR" : "DEBUG", message);
}

static sgx_ql_logging_function_t logger_callback = DefaultLogCallback;
#else
static sgx_ql_logging_function_t logger_callback = nullptr;
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

//
// get raw value for header_item item if exists
//
sgx_plat_error_t get_raw_header(
    const curl_easy& curl,
    const std::string header_item,
    std::string* out_header)
{
    const std::string* raw_header = curl.get_header(header_item);
    if (raw_header == nullptr)
    {
        log(SGX_QL_LOG_ERROR, "Header '%s' is missing.", header_item);
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    if (out_header != nullptr)
    {
        *out_header = *raw_header;
        log(SGX_QL_LOG_INFO,
            "raw_header %s:[%s]\n",
            header_item,
            raw_header->c_str());
    }
    return SGX_PLAT_ERROR_OK;
}

//
// get unescape value for header_item item if exists
//
sgx_plat_error_t get_unescape_header(
    const curl_easy& curl,
    const std::string header_item,
    std::string* unescape_header)
{
    sgx_plat_error_t result = SGX_PLAT_ERROR_OK;
    std::string raw_header;

    result = get_raw_header(curl, header_item, &raw_header);
    if (result != SGX_PLAT_ERROR_OK)
        return result;
    *unescape_header = curl.unescape(raw_header);
    log(SGX_QL_LOG_INFO,
        "unescape_header %s:[%s]\n",
        header_item,
        unescape_header->c_str());
    return result;
}

//
// Format the given byte buffer as a hexadecimal string.
//
static std::string format_as_hex_string(
    const void* buffer,
    const size_t buffer_size)
{
    const auto byte_buffer = static_cast<const uint8_t*>(buffer);
    const size_t formatted_buffer_size = (buffer_size)*2 + 1;
    auto formatted_buffer = std::make_unique<char[]>(formatted_buffer_size);
    for (size_t i = 0; i < buffer_size; ++i)
    {
        assert((i * 2) + 1 < formatted_buffer_size);
        snprintf(&formatted_buffer[i * 2], 3, "%02x", byte_buffer[i]);
    }

    formatted_buffer[formatted_buffer_size - 1] = '\0';

    return formatted_buffer.get();
}

//
// Return true if the current CPU architecture is little-endian.
//
static bool is_little_endian()
{
    // On LE system, 0x00000001 = [ 0, 0, 0, 1]
    // On BE system, 0x00000001 = [ 1, 0, 0, 0]
    const int one = 1;
    const auto one_bytes = reinterpret_cast<const uint8_t*>(&one);
    return one_bytes[0] == 0;
}

//
// Byte swap the given integer value.
//
static uint16_t byte_swap(const uint16_t input)
{
    return ((input & 0xff00) >> 8) | ((input & 0x00ff) << 8);
}

//
// Format a given integer value as a big-endian hexadecimal string.
//
static std::string format_as_big_endian_hex_string(uint16_t input)
{
    if (is_little_endian())
    {
        input = byte_swap(input);
    }

    return format_as_hex_string(&input, sizeof(input));
}

//
// Add two unsigned integers. Throw std::overflow_error on overflow.
//
static size_t safe_add(size_t first, size_t second)
{
    size_t result;

#ifdef __LINUX__
    if (!__builtin_add_overflow(first, second, &result))
#else
    if (SUCCEEDED(ULongLongAdd(first, second, &result)))
#endif
    {
        return result;
    }

    throw std::overflow_error("Integer addition overflow");
}

//
// Multiply two unsigned integers. Throw std::overflow_error on overflow.
//
static size_t safe_multiply(size_t first, size_t second)
{
    size_t result;
#ifdef __LINUX__
    if (!__builtin_mul_overflow(first, second, &result))
#else
    if (SUCCEEDED(ULongLongMult(first, second, &result)))
#endif
    {
        return first * second;
    }

    throw std::overflow_error("Integer multiplication overflow");
}

//
// Safely cast an integer to a different size.
//
template <typename input_t, typename output_t>
void safe_cast(input_t in, output_t* out)
{
    if (in > std::numeric_limits<output_t>::max())
    {
        throw std::overflow_error("Integer cast overflow");
    }

    *out = static_cast<output_t>(in);
}

//
// Build up the URL needed to fetch specific certificate information.
//
static std::string build_pck_cert_url(const sgx_ql_pck_cert_id_t& pck_cert_id)
{
    const std::string qe_id =
        format_as_hex_string(pck_cert_id.p_qe3_id, pck_cert_id.qe3_id_size);

    const std::string cpu_svn = format_as_hex_string(
        pck_cert_id.p_platform_cpu_svn,
        sizeof(*pck_cert_id.p_platform_cpu_svn));

    const std::string pce_svn =
        format_as_big_endian_hex_string(*pck_cert_id.p_platform_pce_isv_svn);

    const std::string pce_id =
        format_as_big_endian_hex_string(pck_cert_id.pce_id);

    return cert_base_url + '/' + qe_id + '/' + cpu_svn + '/' + pce_svn + '/' +
           pce_id + '?' + API_VERSION;
}

//
// Build a complete cert chain from a completed curl object.
//
static std::string build_cert_chain(const curl_easy& curl)
{
    std::string leaf_cert(curl.get_body().begin(), curl.get_body().end());

    // The cache service does not return a newline in the response body.
    // Add one here so that we have a properly formatted chain.
    if (leaf_cert.back() != '\n')
    {
        leaf_cert += "\n";
    }

    const std::string chain =
        curl.unescape(*curl.get_header(headers::PCK_CERT_ISSUER_CHAIN));

    log(SGX_QL_LOG_INFO, "libquote_provider.so: [%s]\n", chain.c_str());
    return leaf_cert + chain;
}

//
// Decode the given hexadecimal string as a native integer value.
//
#pragma warning(suppress : 25057) // a count is not needed for "decoded",
                                  // because we know the type size
template <typename T>
static sgx_plat_error_t hex_decode(const std::string& hex_string, T* decoded)
{
    static constexpr size_t EXPECTED_STRING_SIZE = 2 * sizeof(T);
    if (hex_string.size() != EXPECTED_STRING_SIZE)
    {
        log(SGX_QL_LOG_ERROR,
            "Malformed hex-encoded data. Size is not %u.",
            EXPECTED_STRING_SIZE);
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    auto* output = reinterpret_cast<uint8_t*>(decoded);
    for (size_t i = 0; i < sizeof(T); ++i)
    {
        std::string byte_string = hex_string.substr(i * 2, 2);

        char* end = nullptr;
        output[i] = strtoul(byte_string.c_str(), &end, 16) & 0xff;

        if (*end != 0)
        {
            log(SGX_QL_LOG_ERROR,
                "Malformed hex-encoded data. '%s' is not a hex integer value.",
                byte_string.c_str());
            return SGX_PLAT_ERROR_INVALID_PARAMETER;
        }
    }

    return SGX_PLAT_ERROR_OK;
}

//
// Parse the CPU & PCE svn values, per the Intel spec:
//  "Hex-encoded string representation of concatenation of CPUSVN(16 bytes) and
//  PCESVN(2 bytes)."
//
static sgx_plat_error_t parse_svn_values(
    const curl_easy& curl,
    sgx_ql_config_t* quote_config)
{
    sgx_plat_error_t result = SGX_PLAT_ERROR_OK;

    std::string tcb;
    result = get_raw_header(curl, headers::TCB_INFO, &tcb);
    if (result != SGX_PLAT_ERROR_OK)
        return result;

    // string size == byte size * 2 (for hex-encoding)
    static constexpr size_t CPUSVN_SIZE =
        2 * sizeof(quote_config->cert_cpu_svn);
    static constexpr size_t PCESVN_SIZE =
        2 * sizeof(quote_config->cert_pce_isv_svn);

    if (tcb.size() != CPUSVN_SIZE + PCESVN_SIZE)
    {
        log(SGX_QL_LOG_ERROR, "TCB info header is malformed.");
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }

    const std::string cpu_svn_string = tcb.substr(0, CPUSVN_SIZE);
    log(SGX_QL_LOG_INFO, "CPU SVN: '%s'.", cpu_svn_string.c_str());
    if (const sgx_plat_error_t err =
            hex_decode(cpu_svn_string, &quote_config->cert_cpu_svn))
    {
        log(SGX_QL_LOG_ERROR, "CPU SVN is malformed.");
        return err;
    }

    const std::string pce_svn_string = tcb.substr(CPUSVN_SIZE, PCESVN_SIZE);
    log(SGX_QL_LOG_INFO, "PCE ISV SVN: '%s'.", pce_svn_string.c_str());
    if (const sgx_plat_error_t err =
            hex_decode(pce_svn_string, &quote_config->cert_pce_isv_svn))
    {
        log(SGX_QL_LOG_ERROR, "PCE ISV SVN is malformed.");
        return err;
    }

    if (is_little_endian()) // PCESVN is hosted in big-endian format for
                            // consistency with Intel
    {
        quote_config->cert_pce_isv_svn =
            byte_swap(quote_config->cert_pce_isv_svn);
    }

    log(SGX_QL_LOG_INFO,
        "PCE SVN parsed as '0x%04x'",
        quote_config->cert_pce_isv_svn);

    return SGX_PLAT_ERROR_OK;
}

//
// Convert an internal error enum value to an Intel DCAP enum value.
//
static quote3_error_t convert_to_intel_error(sgx_plat_error_t platformError)
{
    switch (platformError)
    {
        case SGX_PLAT_ERROR_OK:
            return SGX_QL_SUCCESS;
        case SGX_PLAT_ERROR_OUT_OF_MEMORY:
            return SGX_QL_ERROR_OUT_OF_MEMORY;
        case SGX_PLAT_ERROR_INVALID_PARAMETER:
            return SGX_QL_ERROR_INVALID_PARAMETER;
        case SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE:
            return SGX_QL_ERROR_UNEXPECTED;
        case SGX_PLAT_NO_DATA_FOUND:
            return SGX_QL_NO_PLATFORM_CERT_DATA;
        default:
            return SGX_QL_ERROR_UNEXPECTED;
    }
}

//
// Get the expected URL for a given CRL.
//
static sgx_plat_error_t build_pck_crl_url(
    const sgx_ql_get_revocation_info_params_t& params,
    uint32_t crl_index,
    std::string* out)
{
    std::string crl_url = params.crl_urls[crl_index];
    if (crl_url.empty())
    {
        log(SGX_QL_LOG_ERROR, "Empty input CRL string.");
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    int crl_size;
    safe_cast(crl_url.size(), &crl_size);
    char* escaped = curl_escape(crl_url.data(), crl_size);
    if (!escaped)
    {
        throw std::bad_alloc();
    }

    try
    {
        *out = cert_base_url + "/pckcrl?uri=" + escaped + '&' + API_VERSION;
        curl_free(escaped);
        return SGX_PLAT_ERROR_OK;
    }
    catch (...)
    {
        curl_free(escaped);
        throw;
    }
}

//
// The the expected URL for a given TCB.
//
static std::string build_tcb_info_url(
    const sgx_ql_get_revocation_info_params_t& params)
{
    return cert_base_url + "/tcb/" +
           format_as_hex_string(params.fmspc, params.fmspc_size) + '?' +
           API_VERSION;
}

extern "C" quote3_error_t sgx_ql_get_quote_config(
    const sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_ql_config_t** pp_quote_config)
{
    *pp_quote_config = nullptr;

    try
    {
        auto p_quote_config = std::make_unique<sgx_ql_config_t>();
        memset(p_quote_config.get(), 0, sizeof(*p_quote_config));
        p_quote_config->version = SGX_QL_CONFIG_VERSION_1;

        const std::string cert_url = build_pck_cert_url(*p_pck_cert_id);
        const auto curl = curl_easy::create(cert_url, CYBERTRUST_ROOT_CERT);
        log(SGX_QL_LOG_INFO,
            "Fetching quote config from remote server: '%s'.",
            cert_url.c_str());
        curl->perform();

        // we better get TCB info and the cert chain, else we cannot provide the
        // required data to the caller.
        if ((get_raw_header(*curl, headers::TCB_INFO, nullptr) !=
             SGX_PLAT_ERROR_OK) ||
            (get_raw_header(*curl, headers::PCK_CERT_ISSUER_CHAIN, nullptr) !=
             SGX_PLAT_ERROR_OK))
        {
            log(SGX_QL_LOG_ERROR, "Required HTTP headers are missing.");
            return SGX_QL_ERROR_UNEXPECTED;
        }

        if (const sgx_plat_error_t err =
                parse_svn_values(*curl, p_quote_config.get()))
        {
            return convert_to_intel_error(err);
        }

        std::string cert_data = build_cert_chain(*curl);

        // copy the null-terminator for convenience (less error-prone)
        const uint32_t cert_data_size =
            static_cast<uint32_t>(cert_data.size()) + 1;
        p_quote_config->p_cert_data = new uint8_t[cert_data_size];
        p_quote_config->cert_data_size = cert_data_size;
        memcpy(p_quote_config->p_cert_data, cert_data.data(), cert_data_size);

        *pp_quote_config = p_quote_config.release();
    }
    catch (std::bad_alloc&)
    {
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (curl_easy::error& error)
    {
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_QL_NO_PLATFORM_CERT_DATA
                   : SGX_QL_ERROR_UNEXPECTED;
    }

    return SGX_QL_SUCCESS;
}

extern "C" quote3_error_t sgx_ql_free_quote_config(
    sgx_ql_config_t* p_quote_config)
{
    if (p_quote_config != nullptr)
    {
        delete[] p_quote_config->p_cert_data;
        delete p_quote_config;
    }

    return SGX_QL_SUCCESS;
}

extern "C" sgx_plat_error_t sgx_ql_get_revocation_info(
    const sgx_ql_get_revocation_info_params_t* params,
    sgx_ql_revocation_info_t** pp_revocation_info)
{
    sgx_plat_error_t result = SGX_PLAT_ERROR_OK;

    // Requests for higher versions work, but this function will ONLY return the
    // highest version of output that it supports.
    if (params->version < SGX_QL_REVOCATION_INFO_VERSION_1)
    {
        log(SGX_QL_LOG_ERROR,
            "Unexpected parameter version: %u.",
            params->version);
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    if ((params->crl_url_count == 0) != (params->crl_urls == nullptr))
    {
        log(SGX_QL_LOG_ERROR, "Invalid CRL input parameters.");
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    if ((params->fmspc == nullptr) != (params->fmspc_size == 0))
    {
        log(SGX_QL_LOG_ERROR, "Invalid FMSPC input parameters.");
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    char* buffer = nullptr;

    try
    {
        // first fetch the CRL info
        std::vector<std::vector<uint8_t>> crls;
        crls.reserve(params->crl_url_count);
        size_t total_crl_size = 0;

        std::vector<std::string> crl_issuer_chains;
        crl_issuer_chains.reserve(params->crl_url_count);
        size_t total_crl_issuer_chain_size = 0;

        for (uint32_t i = 0; i < params->crl_url_count; ++i)
        {
            std::string crl_url;
            if (const sgx_plat_error_t err =
                    build_pck_crl_url(*params, i, &crl_url))
            {
                return err;
            }

            const auto crl_operation =
                curl_easy::create(crl_url, CYBERTRUST_ROOT_CERT);
            log(SGX_QL_LOG_INFO,
                "Fetching revocation info from remote server: '%s'",
                crl_url.c_str());
            crl_operation->perform();
            crls.push_back(crl_operation->get_body());
            total_crl_size = safe_add(total_crl_size, crls.back().size());
            total_crl_size =
                safe_add(total_crl_size, 1); // include null terminator

            std::string crl_issuer_chain_header;
            result = get_unescape_header(
                *crl_operation,
                headers::CRL_ISSUER_CHAIN,
                &crl_issuer_chain_header);
            if (result != SGX_PLAT_ERROR_OK)
                return result;

            crl_issuer_chains.push_back(crl_issuer_chain_header);
            total_crl_issuer_chain_size = safe_add(
                total_crl_issuer_chain_size, crl_issuer_chains.back().size());
            total_crl_issuer_chain_size = safe_add(
                total_crl_issuer_chain_size, 1); // include null terminator
        }

        // next get the TCB info
        std::vector<uint8_t> tcb_info;
        std::string tcb_issuer_chain;
        if (params->fmspc_size > 0)
        {
            const auto tcb_info_operation = curl_easy::create(
                build_tcb_info_url(*params), CYBERTRUST_ROOT_CERT);
            tcb_info_operation->perform();

            tcb_info = tcb_info_operation->get_body();

            result = get_unescape_header(
                *tcb_info_operation,
                headers::TCB_INFO_ISSUER_CHAIN,
                &tcb_issuer_chain);
            if (result != SGX_PLAT_ERROR_OK)
                return result;
        }

        // last, pack it all up into a single buffer
        size_t buffer_size = 0;
        buffer_size = safe_add(buffer_size, sizeof(**pp_revocation_info));
        buffer_size = safe_add(buffer_size, tcb_info.size());
        buffer_size = safe_add(buffer_size, tcb_issuer_chain.size());
        buffer_size = safe_add(
            buffer_size,
            tcb_issuer_chain.empty() ? 0 : 1); // issuer chain null terminator
        buffer_size = safe_add(
            buffer_size, safe_multiply(crls.size(), sizeof(sgx_ql_crl_data_t)));
        buffer_size = safe_add(buffer_size, total_crl_size);
        buffer_size = safe_add(buffer_size, total_crl_issuer_chain_size);

        buffer = new char[buffer_size];
        memset(buffer, 0, buffer_size);
#ifndef NDEBUG
        const char* buffer_end = buffer + buffer_size;
#endif
        *pp_revocation_info =
            reinterpret_cast<sgx_ql_revocation_info_t*>(buffer);
        buffer += sizeof(**pp_revocation_info);
        assert(buffer < buffer_end);
        (*pp_revocation_info)->version = SGX_QL_REVOCATION_INFO_VERSION_1;

        assert(tcb_info.empty() == tcb_issuer_chain.empty());

        if (!tcb_info.empty())
        {
            (*pp_revocation_info)->tcb_info = buffer;
            (*pp_revocation_info)->tcb_info_size =
                static_cast<uint32_t>(tcb_info.size());
            buffer += tcb_info.size();
            assert(buffer < buffer_end);
            memcpy(
                (*pp_revocation_info)->tcb_info,
                tcb_info.data(),
                tcb_info.size());

            (*pp_revocation_info)->tcb_issuer_chain = buffer;
            (*pp_revocation_info)->tcb_issuer_chain_size =
                static_cast<uint32_t>(tcb_issuer_chain.size());
            buffer += tcb_issuer_chain.size() + 1; // skip null terminator
            assert(buffer <= buffer_end);
            memcpy(
                (*pp_revocation_info)->tcb_issuer_chain,
                tcb_issuer_chain.data(),
                tcb_issuer_chain.size());
        }

        assert(crls.size() == params->crl_url_count);
        assert(crls.size() == crl_issuer_chains.size());

        if (!crls.empty())
        {
            safe_cast(crls.size(), &(*pp_revocation_info)->crl_count);
            (*pp_revocation_info)->crls =
                reinterpret_cast<sgx_ql_crl_data_t*>(buffer);
            buffer += safe_multiply(crls.size(), sizeof(sgx_ql_crl_data_t));

            for (size_t i = 0; i < crls.size(); ++i)
            {
                (*pp_revocation_info)->crls[i].crl_data = buffer;
                safe_cast(
                    crls[i].size(),
                    &(*pp_revocation_info)->crls[i].crl_data_size);
                buffer += crls[i].size() + 1; // skip null terminator
                assert(buffer < buffer_end);
                memcpy(
                    (*pp_revocation_info)->crls[i].crl_data,
                    crls[i].data(),
                    crls[i].size());

                (*pp_revocation_info)->crls[i].crl_issuer_chain = buffer;
                (*pp_revocation_info)->crls[i].crl_issuer_chain_size =
                    static_cast<uint32_t>(crl_issuer_chains[i].size());
                buffer +=
                    crl_issuer_chains[i].size() + 1; // skip null terminator
                assert(buffer <= buffer_end);
                memcpy(
                    (*pp_revocation_info)->crls[i].crl_issuer_chain,
                    crl_issuer_chains[i].data(),
                    crl_issuer_chains[i].size());
            }
        }

        assert(buffer == buffer_end);
    }
    catch (std::bad_alloc&)
    {
        return SGX_PLAT_ERROR_OUT_OF_MEMORY;
    }
    catch (std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        delete[] buffer;
        *pp_revocation_info = nullptr;
        return SGX_PLAT_ERROR_OVERFLOW;
    }
    catch (curl_easy::error& error)
    {
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_PLAT_NO_DATA_FOUND
                   : SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }

    return SGX_PLAT_ERROR_OK;
}

extern "C" void sgx_ql_free_revocation_info(
    sgx_ql_revocation_info_t* p_revocation_info)
{
    delete[] reinterpret_cast<uint8_t*>(p_revocation_info);
}

extern "C" sgx_plat_error_t sgx_ql_set_base_url(const char* url)
{
    cert_base_url = (url == nullptr) ? DEFAULT_CERT_URL : url;
    log(SGX_QL_LOG_INFO, "Base URL set to '%s'.", cert_base_url.c_str());
    return SGX_PLAT_ERROR_OK;
}

extern "C" sgx_plat_error_t sgx_ql_set_logging_function(
    sgx_ql_logging_function_t logger)
{
    logger_callback = logger;
    return SGX_PLAT_ERROR_OK;
}

extern "C" sgx_plat_error_t sgx_get_qe_identity_info(
    sgx_qe_identity_info_t** pp_qe_identity_info)
{
    sgx_qe_identity_info_t* p_qe_identity_info = NULL;
    sgx_plat_error_t result;
    char* buffer = nullptr;

    if (!pp_qe_identity_info)
    {
        log(SGX_QL_LOG_ERROR, "Invalid parameter pp_qe_identity_info");
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    try
    {
        std::vector<uint8_t> identity_info;
        std::string issuer_chain;
        std::string request_id;
        size_t total_buffer_size = 0;
        const auto curl =
            curl_easy::create(QE_IDENTITY_URL, CYBERTRUST_ROOT_CERT);
        log(SGX_QL_LOG_INFO,
            "Fetching QE Identity from remote server: '%s'.",
            QE_IDENTITY_URL);
        curl->perform();

        // issuer chain
        result =
            get_unescape_header(*curl, headers::QE_ISSUER_CHAIN, &issuer_chain);
        if (result != SGX_PLAT_ERROR_OK)
            return result;

        result = get_unescape_header(*curl, headers::REQUEST_ID, &request_id);
        if (result != SGX_PLAT_ERROR_OK)
            return result;

        // read body
        identity_info = curl->get_body();
        std::string qe_identity(
            curl->get_body().begin(), curl->get_body().end());

        // Calculate total buffer size
        total_buffer_size =
            safe_add(sizeof(sgx_qe_identity_info_t), identity_info.size());
        total_buffer_size = safe_add(total_buffer_size, 1); // null terminator
        total_buffer_size = safe_add(total_buffer_size, issuer_chain.size());
        total_buffer_size = safe_add(total_buffer_size, 1); // null terminator

        buffer = new char[total_buffer_size];
        memset(buffer, 0, total_buffer_size);

#ifndef NDEBUG
        const char* buffer_end = buffer + total_buffer_size;
#endif
        // fill in the qe info
        p_qe_identity_info = reinterpret_cast<sgx_qe_identity_info_t*>(buffer);

        // advance to the end of the sgx_qe_identity_info_t structure
        buffer += sizeof(*p_qe_identity_info);

        // qe_id_info
        p_qe_identity_info->qe_id_info_size =
            static_cast<uint32_t>(identity_info.size());
        p_qe_identity_info->qe_id_info = buffer;
        memcpy(
            p_qe_identity_info->qe_id_info,
            identity_info.data(),
            identity_info.size());
        buffer += identity_info.size() + 1; // skip null terminator
        assert(buffer < buffer_end);

        // set issuer_chain info
        p_qe_identity_info->issuer_chain_size =
            static_cast<uint32_t>(issuer_chain.size());
        p_qe_identity_info->issuer_chain = buffer;
        buffer += issuer_chain.size() + 1; // skip null terminator
        assert(buffer == buffer_end);
        memcpy(
            p_qe_identity_info->issuer_chain,
            issuer_chain.data(),
            issuer_chain.size());
        *pp_qe_identity_info = p_qe_identity_info;
    }
    catch (std::bad_alloc&)
    {
        return SGX_PLAT_ERROR_OUT_OF_MEMORY;
    }
    catch (std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        *pp_qe_identity_info = nullptr;
        return SGX_PLAT_ERROR_OVERFLOW;
    }
    catch (curl_easy::error& error)
    {
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_PLAT_NO_DATA_FOUND
                   : SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }

    return SGX_PLAT_ERROR_OK;
}

extern "C" void sgx_free_qe_identity_info(
    sgx_qe_identity_info_t* p_qe_identity_info)
{
    delete[] reinterpret_cast<uint8_t*>(p_qe_identity_info);
}
