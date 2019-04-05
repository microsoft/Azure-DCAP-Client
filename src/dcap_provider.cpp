// Licensed under the MIT License.

#include "dcap_provider.h"
#include "curl_easy.h"
#include "local_cache.h"

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

// NOTE:
//  The environment variables below are mostly meant to be modified
//  by the OE Jenkins environment to support CI/CD testing. Do not
//  modify or override these values as they can cause regressions in
//  caching service behavior.
#define ENV_AZDCAP_BASE_URL "AZDCAP_BASE_CERT_URL"
#define ENV_AZDCAP_CLIENT_ID "AZDCAP_CLIENT_ID"
#define MAX_ENV_VAR_LENGTH 2000

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
constexpr char CACHE_CONTROL[] = "Cache-Control";
};

constexpr char API_VERSION[] = "api-version=2018-10-01-preview";

static char DEFAULT_CERT_URL[] =
    "https://global.acccache.azure.net/sgx/certificates";
static std::string cert_base_url = DEFAULT_CERT_URL;

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

static std::string get_env_variable(std::string env_variable)
{
    const char * env_value = getenv(env_variable.c_str());

    if (env_value == NULL)
    {
        return std::string();
    }
    else
    {
        if ((strnlen(env_value, MAX_ENV_VAR_LENGTH) <= 0) ||
            (strnlen(env_value, MAX_ENV_VAR_LENGTH) == MAX_ENV_VAR_LENGTH))
        {
            log(SGX_QL_LOG_ERROR,
                "Value specified in environment variable %s is either empty or expected max length '%d'.",
                env_variable.c_str(),
                MAX_ENV_VAR_LENGTH);
            
            return std::string();
        }

        return std::string(env_value);
    }
}

static std::string get_base_url()
{
    std::string env_base_url = get_env_variable(ENV_AZDCAP_BASE_URL);

    if (env_base_url.empty())
    {
        log(SGX_QL_LOG_WARNING, "Using default base cert URL '%s'.", cert_base_url.c_str());
        return cert_base_url;
    }
    
    log(SGX_QL_LOG_INFO, "Using %s envvar for base cert URL, set to '%s'.", ENV_AZDCAP_BASE_URL, env_base_url.c_str());
    return env_base_url;
}

static std::string get_client_id()
{
    std::string env_client_id = get_env_variable(ENV_AZDCAP_CLIENT_ID);

    if (env_client_id.empty())
    {
        log(SGX_QL_LOG_WARNING, "Client id not set.");
        return std::string();
    }
    
    log(SGX_QL_LOG_INFO, "Using %s envvar for client id, set to '%s'.", ENV_AZDCAP_CLIENT_ID, env_client_id.c_str());
    return env_client_id;
}

//
// determines the maximum age in local cache
//
sgx_plat_error_t get_cache_max_age(
    const curl_easy& curl,
    time_t* max_age)
{
    if (max_age == nullptr)
    {
        return SGX_PLAT_ERROR_INVALID_PARAMETER;
    }

    //
    // currently set to persist all cached
    // certs for exactly 1 day.
    //
    tm * max_age_s = localtime(max_age);
    max_age_s->tm_mday += 1;
    *max_age = mktime(max_age_s);

    return SGX_PLAT_ERROR_OK;
}

//
// get raw value for header_item item if exists
//
sgx_plat_error_t get_raw_header(
    const curl_easy& curl,
    const std::string& header_item,
    std::string* out_header)
{
    const std::string* raw_header = curl.get_header(header_item);
    if (raw_header == nullptr)
    {
        log(SGX_QL_LOG_ERROR, "Header '%s' is missing.", header_item.c_str());
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    if (out_header != nullptr)
    {
        *out_header = *raw_header;
        log(SGX_QL_LOG_INFO,
            "raw_header %s:[%s]\n",
            header_item.c_str(),
            raw_header->c_str());
    }
    return SGX_PLAT_ERROR_OK;
}

//
// get unescape value for header_item item if exists
//
sgx_plat_error_t get_unescape_header(
    const curl_easy& curl,
    const std::string& header_item,
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
        header_item.c_str(),
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


    std::string pck_cert_url = get_base_url() + '/' + qe_id + 
                                '/' + cpu_svn + '/' + pce_svn +
                                '/' + pce_id + '?';
    
    std::string client_id = get_client_id();

    if (!client_id.empty())
    {
        pck_cert_url += "clientid=" + client_id + '&';
    }

    return pck_cert_url + API_VERSION;
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
    std::string client_id;

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
        *out = get_base_url() + "/pckcrl?uri=" + escaped + '&';

        client_id = get_client_id();
        if (!client_id.empty())
        {
            *out += "clientid=" + client_id + '&';
        }

        *out += API_VERSION;

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
// The expected URL for a given TCB.
//
static std::string build_tcb_info_url(
    const sgx_ql_get_revocation_info_params_t& params)
{
    std::string tcb_info_url = get_base_url() + "/tcb/" +
           format_as_hex_string(params.fmspc, params.fmspc_size) + '?';

    std::string client_id = get_client_id();

    if (!client_id.empty())
    {
        tcb_info_url += "clientid=" + client_id + '&';
    }

    return tcb_info_url + API_VERSION;
}

//
// The expected URL for QeID
//
static std::string build_qe_id_url()
{
    std::string qe_id_url = get_base_url() + "/qeid?";

    std::string client_id = get_client_id();

    if (!client_id.empty())
    {
        qe_id_url += "clientid=" + client_id + '&';
    }

    return qe_id_url + API_VERSION;
}

extern "C" quote3_error_t sgx_ql_get_quote_config(
    const sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_ql_config_t** pp_quote_config)
{
    *pp_quote_config = nullptr;

    try
    {
        const std::string cert_url = build_pck_cert_url(*p_pck_cert_id);

        if (auto cache_hit = local_cache_get(cert_url))
        {
            *pp_quote_config = (sgx_ql_config_t*)(new uint8_t[cache_hit->size()]);
            memcpy(*pp_quote_config, cache_hit->data(), cache_hit->size());

            // re-aligning the p_cert_data pointer
            (*pp_quote_config)->p_cert_data = (uint8_t *)(*pp_quote_config) +
                sizeof(sgx_ql_config_t);
            
            return SGX_QL_SUCCESS;
        }

        const auto curl = curl_easy::create(cert_url);
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

        // figure out how long we should cache the data (if at all)
        time_t max_age = 0;
        if (get_cache_max_age(*curl, &max_age) != SGX_PLAT_ERROR_OK)
        {
            log(SGX_QL_LOG_ERROR, "Failed to process cache header(s).");
            return SGX_QL_ERROR_UNEXPECTED;
        }

        // parse the SVNs into a local data structure so we can handle any parse
        // errors before allocating the output buffer
        sgx_ql_config_t temp_config{};
        if (const sgx_plat_error_t err = parse_svn_values(*curl, &temp_config))
        {
            return convert_to_intel_error(err);
        }

        const std::string cert_data = build_cert_chain(*curl);

        // copy the null-terminator for convenience (less error-prone)
        const uint32_t cert_data_size =
            static_cast<uint32_t>(cert_data.size()) + 1;

        // allocate return value contiguously (makes caching easier)
        const size_t buf_size = sizeof(sgx_ql_config_t) + cert_data_size;
        uint8_t* buf = new uint8_t[buf_size];
        memset(buf, 0, buf_size);

#ifndef NDEBUG
        const uint8_t* buf_end = buf + buf_size;
#endif

        *pp_quote_config = reinterpret_cast<sgx_ql_config_t*>(buf);
        buf += sizeof(sgx_ql_config_t);
        assert(buf <= buf_end);

        (*pp_quote_config)->cert_cpu_svn = temp_config.cert_cpu_svn;
        (*pp_quote_config)->cert_pce_isv_svn = temp_config.cert_pce_isv_svn;
        (*pp_quote_config)->version = SGX_QL_CONFIG_VERSION_1;
        (*pp_quote_config)->p_cert_data = buf;
        (*pp_quote_config)->cert_data_size = cert_data_size;
        memcpy((*pp_quote_config)->p_cert_data, cert_data.data(), cert_data_size);
        buf += cert_data_size;
        assert(buf == buf_end);

        if (max_age > 0)
        {
            time_t expiry = time(nullptr) + max_age;
            local_cache_add(cert_url, expiry, buf_size, *pp_quote_config);
        }
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
    delete[] p_quote_config;

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

            const auto crl_operation = curl_easy::create(crl_url);
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
            const auto tcb_info_operation = curl_easy::create(build_tcb_info_url(*params));
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
        std::string qe_id_url = build_qe_id_url();

        const auto curl = curl_easy::create(qe_id_url);
        log(SGX_QL_LOG_INFO,
            "Fetching QE Identity from remote server: '%s'.",
            qe_id_url);
        curl->perform();

        // issuer chain
        result =
            get_unescape_header(*curl, headers::QE_ISSUER_CHAIN, &issuer_chain);
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
