// Licensed under the MIT License.
#define _CRT_SECURE_NO_WARNINGS

#include "dcap_provider.h"
#include <curl_easy.h>
#include "local_cache.h"
#include "private.h"

#include <cassert>
#include <cstdarg>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>

#include "sgx_ql_lib_common.h"
#include "environment.h"

#ifdef __LINUX__
#include <arpa/inet.h>
#else
#include <intsafe.h>
#include <winsock.h>
#endif

using namespace std;

// External function names are dictated by Intel
// ReSharper disable CppInconsistentNaming

namespace headers
{
constexpr char PCK_CERT_ISSUER_CHAIN[] = "sgx-Pck-Certificate-Issuer-Chain";
constexpr char CRL_ISSUER_CHAIN[] = "SGX-PCK-CRL-Issuer-Chain";
constexpr char TCB_INFO_ISSUER_CHAIN[] = "SGX-TCB-Info-Issuer-Chain";
constexpr char TCB_INFO[] = "sgx-Tcbm";
constexpr char CONTENT_TYPE[] = "Content-Type";
constexpr char QE_ISSUER_CHAIN[] = "SGX-QE-Identity-Issuer-Chain";
constexpr char ENCLAVE_ID_ISSUER_CHAIN[] = "SGX-Enclave-Identity-Issuer-Chain";
constexpr char REQUEST_ID[] = "Request-ID";
constexpr char CERT_CACHE_CONTROL[] = "cacheMaxAge";
constexpr char CACHE_CONTROL[] = "Cache-Control";
constexpr char JSON_VERSION[] = "version";

static std::map<std::string, std::string> default_values = {
    {"Content-Type", "application/json"}};

static const std::map<std::string, std::string> localhost_metadata = {
    {"metadata", "true"}};

}; // namespace headers

// New API version used to request PEM encoded CRLs
constexpr char API_VERSION_10_2018[] = "api-version=2018-10-01-preview";
constexpr char API_VERSION_02_2020[] = "api-version=2020-02-12-preview";
constexpr char API_VERSION_07_2021[] = "api-version=2021-07-22-preview";

static char DEFAULT_CERT_URL[] =
    "https://global.acccache.azure.net/sgx/certification";
static std::string default_cert_url = DEFAULT_CERT_URL;

static char DEFAULT_BYPASS_BASE_URL[] = "false";
static std::string default_bypass_base_url = DEFAULT_BYPASS_BASE_URL;

static char PRIMARY_CERT_URL[] =
    "http://169.254.169.254/metadata/THIM/sgx/certification";
static std::string primary_cert_url = PRIMARY_CERT_URL;

static char SECONDARY_CERT_URL[] =
    "https://global.acccache.azure.net/sgx/certification";
static std::string secondary_cert_url = SECONDARY_CERT_URL;

static char DEFAULT_CLIENT_ID[] = "production_client";
static std::string prod_client_id = DEFAULT_CLIENT_ID;

static char DEFAULT_COLLATERAL_VERSION[] = "v3";
static std::string default_collateral_version = DEFAULT_COLLATERAL_VERSION;

static char CRL_CA_PROCESSOR[] = "processor";
static char CRL_CA_PLATFORM[] = "platform";
static char ROOT_CRL_NAME[] =
    "https%3a%2f%2fcertificates.trustedservices.intel.com%2fintelsgxrootca.crl";
static char PROCESSOR_CRL_NAME[] = "https%3a%2f%2fcertificates.trustedservices."
                                   "intel.com%2fintelsgxpckprocessor.crl";
static char PLATFORM_CRL_NAME[] =
    "https%3a%2f%2fapi.trustedservices.intel.com%2fsgx%2fcertification%2fv3%2fpckcrl%3fca%3dplatform%26encoding%3dpem";

static const string CACHE_CONTROL_MAX_AGE = "max-age=";

enum class CollateralTypes
{
    TcbInfo,
    QeIdentity,
    QveIdentity,
    PckCert,
    PckCrl,
    PckRootCrl
};

static std::string get_env_variable(std::string env_variable)
{
    auto retval = get_env_variable_no_log(env_variable);
    if (!retval.second.empty())
    {
        log(SGX_QL_LOG_WARNING, retval.second.c_str());
    }
    return retval.first;
}

static std::string get_collateral_version()
{
    std::string collateral_version =
        get_env_variable(ENV_AZDCAP_COLLATERAL_VER);

    if (collateral_version.empty())
    {
        log(SGX_QL_LOG_INFO,
            "Using default collateral version '%s'.",
            default_collateral_version.c_str());
        return default_collateral_version;
    }
    else
    {
        if (collateral_version.compare("v1") &&
            collateral_version.compare("v2") &&
            collateral_version.compare("v3"))
        {
            log(SGX_QL_LOG_ERROR,
                "Value specified in environment variable '%s' is invalid. "
                "Acceptable values are empty, v1, or v2 or v3",
                collateral_version.c_str(),
                MAX_ENV_VAR_LENGTH);

            log(SGX_QL_LOG_INFO,
                "Using default collateral version '%s'.",
                default_collateral_version.c_str());
            return default_collateral_version;
        }

        log(SGX_QL_LOG_WARNING,
            "Using %s envvar for collateral version URL, set to '%s'.",
            ENV_AZDCAP_COLLATERAL_VER,
            collateral_version.c_str());
        return collateral_version;
    }
}

static std::string get_base_url()
{
    std::string env_base_url = get_env_variable(ENV_AZDCAP_BASE_URL);

    if (env_base_url.empty())
    {
        log(SGX_QL_LOG_INFO,
            "Using default primary base cert URL '%s'.",
            default_cert_url.c_str());
        return default_cert_url;
    }

    log(SGX_QL_LOG_WARNING,
        "Using %s envvar for base cert URL, set to '%s'.",
        ENV_AZDCAP_BASE_URL,
        env_base_url.c_str());
    return env_base_url;
}

static std::string bypass_base_url()
{
    std::string env_bypass_base_url = get_env_variable(ENV_BYPASS_BASE_URL);

    if (env_bypass_base_url.empty())
    {
        log(SGX_QL_LOG_INFO,
            "Bypass default base URL:'%s'",
            default_bypass_base_url.c_str());
        return default_bypass_base_url;
    }

    log(SGX_QL_LOG_WARNING,
        "Bypass default base URL:'%s'",
        ENV_BYPASS_BASE_URL,
        env_bypass_base_url.c_str());
    return env_bypass_base_url;
}

static std::string get_primary_url()
{
    std::string env_primary_url =
        get_env_variable(ENV_AZDCAP_PRIMARY_BASE_CERT_URL);

    if (env_primary_url.empty())
    {
        log(SGX_QL_LOG_INFO,
            "Using default primary base cert URL '%s'.",
            primary_cert_url.c_str());
        return primary_cert_url;
    }

    log(SGX_QL_LOG_WARNING,
        "Using %s envvar for base cert URL, set to '%s'.",
        ENV_AZDCAP_PRIMARY_BASE_CERT_URL,
        env_primary_url.c_str());
    return env_primary_url;
}

static std::string get_secondary_url()
{
    std::string env_secondary_url =
        get_env_variable(ENV_AZDCAP_SECONDARY_BASE_CERT_URL);

    if (env_secondary_url.empty())
    {
        log(SGX_QL_LOG_INFO,
            "Using default secondary base cert URL '%s'.",
            secondary_cert_url.c_str());
        return secondary_cert_url;
    }

    log(SGX_QL_LOG_WARNING,
        "Using %s envvar for base cert URL, set to '%s'.",
        ENV_AZDCAP_SECONDARY_BASE_CERT_URL,
        env_secondary_url.c_str());
    return env_secondary_url;
}

static std::string get_client_id()
{
    std::string env_client_id = get_env_variable(ENV_AZDCAP_CLIENT_ID);

    if (env_client_id.empty())
    {
        log(SGX_QL_LOG_INFO,
            "Using default client id '%s'.",
            prod_client_id.c_str());
        return prod_client_id;
    }

    log(SGX_QL_LOG_WARNING,
        "Using %s envvar for client id, set to '%s'.",
        ENV_AZDCAP_CLIENT_ID,
        env_client_id.c_str());
    return env_client_id;
}

static inline quote3_error_t fill_qpl_string_buffer(
    std::string content,
    char*& buffer,
    uint32_t& bufferLength)
{
    // Allocate memory for the structure fields +1 to include null character
    bufferLength = (uint32_t)content.size() + 1;
    buffer = new char[bufferLength];
    if (buffer == nullptr)
    {
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }

    memcpy(buffer, content.data(), bufferLength);
    return SGX_QL_SUCCESS;
}

static inline quote3_error_t fill_qpl_string_buffer(
    std::vector<uint8_t> content,
    char*& buffer,
    uint32_t& bufferLength)
{
    content.push_back(0);
    bufferLength = (uint32_t)content.size();
    buffer = new char[bufferLength];
    if (!buffer)
    {
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    memcpy(buffer, content.data(), content.size());
    return SGX_QL_SUCCESS;
}

//
// Determine the time cache should invalidate for given certificate.
// The return object from the service is a string value that
// defines certificate expiration time in seconds. In this function
// we convert the returned value to ingeter and uses that to define 
// the expiration time of the certificate cached locally.
//
bool get_cert_cache_expiration_time(const string& cache_max_age, const string& url, time_t& expiration_time)
{
    time_t max_age = 0;
    tm* max_age_s = localtime(&max_age);
    int cache_time_seconds = 0;
    constexpr int MAX_CACHE_TIME_SECONDS = 86400;
    try
    {
        cache_time_seconds = stoi(cache_max_age);
        if (cache_time_seconds > MAX_CACHE_TIME_SECONDS)
        {
            log(SGX_QL_LOG_ERROR,
                "Caching control '%d' larger than maximum '%d' seconds. Collateral will not be cached",
                cache_time_seconds,
                MAX_CACHE_TIME_SECONDS);
            return false;
        }
    }
    catch (const std::invalid_argument& e)
    {
        log(SGX_QL_LOG_ERROR,
            "Invalid argument thrown when parsing cache-control. Header text: '%s' Error: '%s'. Collateral will not be cached",
            cache_max_age.c_str(),
            e.what());
        return false;
    }
    catch (const std::out_of_range& e)
    {
        log(SGX_QL_LOG_ERROR,
            "Invalid argument thrown when parsing cache-control. Header "
            "text: '%s' Error: '%s'. Collateral will not be cached",
            cache_max_age.c_str(),
            e.what());
        return false;
    }

    max_age_s->tm_sec += cache_time_seconds;
    expiration_time = time(nullptr) + mktime(max_age_s);
    log(SGX_QL_LOG_INFO,
        "Caching collateral '%s' for '%d' seconds",
        url.c_str(),
        cache_time_seconds);
    return true;
}

//
// Determine time cache should invalidate for given collateral
//
bool get_cache_expiration_time(const string& cache_control, const string& url, time_t& expiration_time)
{
    time_t max_age = 0;
    tm* max_age_s = localtime(&max_age);
    size_t index = cache_control.find(CACHE_CONTROL_MAX_AGE);
    int cache_time_seconds = 0;
    constexpr int MAX_CACHE_TIME_SECONDS = 86400;
    if (index != string::npos)
    {
        try
        {
            cache_time_seconds = stoi(cache_control.substr(index + CACHE_CONTROL_MAX_AGE.length()));
            if (cache_time_seconds > MAX_CACHE_TIME_SECONDS)
            {
                log(SGX_QL_LOG_ERROR,
                    "Caching control '%d' larger than maximum '%d' seconds. Collateral will not be cached",
                    cache_time_seconds,
                    MAX_CACHE_TIME_SECONDS);
                return false;
            }
        }
        catch (const std::invalid_argument& e)
        {
            log(SGX_QL_LOG_ERROR,
                "Invalid argument thrown when parsing cache-control. Header text: '%s' Error: '%s'. Collateral will not be cached",
                cache_control.c_str(),
                e.what());
            return false;
        }
        catch (const std::out_of_range& e)
        {
            log(SGX_QL_LOG_ERROR,
                "Invalid argument thrown when parsing cache-control. Header text: '%s' Error: '%s'. Collateral will not be cached",
                cache_control.c_str(),
                e.what());
            return false;
        }
    }

    max_age_s->tm_sec += cache_time_seconds;
    expiration_time = time(nullptr) + mktime(max_age_s);
    log(SGX_QL_LOG_INFO,
        "Caching collateral '%s' for '%d' seconds",
        url.c_str(),
        cache_time_seconds);
    return true;
}

//
// Get string value for printing for each collateral type
//
std::string get_collateral_friendly_name(CollateralTypes collateral_type)
{
    switch (collateral_type)
    {
        case CollateralTypes::TcbInfo:
        {
            return "Tcb Info";
        }
        case CollateralTypes::QeIdentity:
        {
            return "Qe Identity";
        }
        case CollateralTypes::QveIdentity:
        {
            return "Qve Identity";
        }
        case CollateralTypes::PckCert:
        {
            return "PCK Cert";
        }
        case CollateralTypes::PckCrl:
        {
            return "PCK Crl";
        }
        case CollateralTypes::PckRootCrl:
        {
            return "Root CA Crl";
        }
        default:
        {
            return std::string();
        }
    }
}

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
        log(SGX_QL_LOG_INFO,
            "Fetched %s value from JSON. \n", item.c_str());
        if (out_header != nullptr)
        {
            *out_header = raw_value;
        }
    }
    catch (const exception& ex)
    {
        log(SGX_QL_LOG_ERROR,
            "Required information '%s' is missing. \n", item.c_str());
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
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
            "raw_header %s:[%s]",
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
    {
        log(SGX_QL_LOG_INFO,
            "Failed to get unescape header %s",
            header_item.c_str());
        return result;
    }

    *unescape_header = curl.unescape(raw_header);
    log(SGX_QL_LOG_INFO,
        "unescape_header %s:[%s]",
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
    if (in > static_cast<input_t>((std::numeric_limits<output_t>::max)()))
    {
        throw std::overflow_error("Integer cast overflow");
    }

    *out = static_cast<output_t>(in);
}

static std::string build_eppid(const sgx_ql_pck_cert_id_t& pck_cert_id)
{
    const std::string disable_ondemand =
        get_env_variable(ENV_AZDCAP_DISABLE_ONDEMAND);
    if (!disable_ondemand.empty())
    {
        if (disable_ondemand == "1")
        {
            log(SGX_QL_LOG_WARNING,
                "On demand registration disabled by environment variable. No "
                "eppid being sent to caching service");
            return "";
        }
    }

    const std::string eppid = format_as_hex_string(
        pck_cert_id.p_encrypted_ppid, pck_cert_id.encrypted_ppid_size);

    if (eppid.empty())
    {
        log(SGX_QL_LOG_WARNING,
            "No eppid provided.");
        return "";
    }
    else
    {
        log(SGX_QL_LOG_INFO, "Sending the provided eppid.");
        return eppid;
    }
}

static void pck_cert_url(
    std::stringstream& url,
    std::string version,
    std::string qe_id,
    std::string cpu_svn,
    std::string pce_svn,
    std::string pce_id,
    std::string eppid_json,
    bool append_eppid = true)
{
    url << '/' << version;
    url << "/pckcert?";
    url << "qeid=" << qe_id << '&';
    url << "cpusvn=" << cpu_svn << '&';
    url << "pcesvn=" << pce_svn << '&';
    url << "pceid=" << pce_id << '&';

    // EPPID is not fixed for a particular node. Cached file hash will
    // differ if we use EPPID in the name so ignoring EPPID when evaluating
    // local cache file name for the certificate.
    if (append_eppid && !eppid_json.empty())
    {
        url << "encrypted_ppid=" << eppid_json << '&';
    }
    std::string client_id = get_client_id();
    if (!client_id.empty())
    {
        url << "clientid=" << client_id << '&';
    }
    url << API_VERSION_07_2021;
}

static void build_pck_cert_url(const sgx_ql_pck_cert_id_t& pck_cert_id, certificate_fetch_url& certificate_url, std::stringstream& cached_file_name)
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
    std::string version = get_collateral_version();

    const std::string eppid_json = build_eppid(pck_cert_id);

    certificate_url.primary_base_url << get_primary_url();
    pck_cert_url(certificate_url.primary_base_url, version, qe_id, cpu_svn, pce_svn, pce_id, eppid_json);

    certificate_url.secondary_base_url << get_secondary_url();
    pck_cert_url(certificate_url.secondary_base_url, version, qe_id, cpu_svn, pce_svn, pce_id, eppid_json);

    cached_file_name << get_secondary_url();
    pck_cert_url(cached_file_name, version, qe_id, cpu_svn, pce_svn, pce_id, eppid_json, false);
}

//
// Build a complete cert chain from a completed curl object.
//
static sgx_plat_error_t build_cert_chain(const curl_easy& curl, const nlohmann::json& json, std::string* out_header)
{
    std::string leaf_cert;
    std::string chain;
    std::string temp_chain;
    sgx_plat_error_t result = SGX_PLAT_ERROR_OK;

    result = extract_from_json(json, "pckCert", &leaf_cert);
    if (result != SGX_PLAT_ERROR_OK)
        return result;
    log(SGX_QL_LOG_INFO, "pckCert : %s from JSON", leaf_cert.c_str()); 
    result = extract_from_json(json, headers::PCK_CERT_ISSUER_CHAIN, &temp_chain);
    if (result != SGX_PLAT_ERROR_OK)
        return result;
    log(SGX_QL_LOG_INFO,
        "%s : %s",
        headers::PCK_CERT_ISSUER_CHAIN,
        temp_chain.c_str()); 
    chain = curl.unescape(temp_chain);

    // The cache service does not return a newline in the response
    // response_body. Add one here so that we have a properly formatted chain.
    if (leaf_cert.back() != '\n')
    {
        leaf_cert += "\n";
    }

    log(SGX_QL_LOG_INFO, "Cert chain formed: [%s]", chain.c_str());
    if (out_header != nullptr)
    {
        *out_header = leaf_cert + chain;
    }
    return result;
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
    const nlohmann::json& json,
    sgx_ql_config_t* quote_config)
{
    sgx_plat_error_t result = SGX_PLAT_ERROR_OK;
    std::string tcb;
    result = extract_from_json(json, headers::TCB_INFO, &tcb);
    if (result != SGX_PLAT_ERROR_OK)
        return result;
    log(SGX_QL_LOG_INFO, "%s : %s", headers::TCB_INFO, tcb.c_str()); 
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
    log(SGX_QL_LOG_INFO, "CPU SVN: '%s", cpu_svn_string.c_str());
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

static std::string build_pck_crl_url(
    std::string crl_name,
    std::string api_version)
{
    std::string version = get_collateral_version();
    std::stringstream url;
    std::string escaped =
        curl_easy::escape(crl_name.data(), (int)crl_name.size());
    std::string client_id = get_client_id();
    url << get_base_url();
    if (!version.empty())
    {
        url << "/" << version;
    }
    url << "/pckcrl?uri=" << escaped << "&";
    if (!client_id.empty())
    {
        url << "clientid=" << client_id << '&';
    }
    url << api_version;
    return url.str();
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
    *out = build_pck_crl_url(crl_url, API_VERSION_10_2018);
    return SGX_PLAT_ERROR_OK;
}

// Base64 alphabet defined in RFC 4648
/* Value    Encoding    Value   Encoding    Value   Encoding    Value   Encoding
   0        A           17      R           34      i           51      z
   1        B           18      S           35      j           52      0
   2        C           19      T           36      k           53      1
   3        D           20      U           37      l           54      2
   4        E           21      V           38      m           55      3
   5        F           22      W           39      n           56      4
   6        G           23      X           40      o           57      5
   7        H           24      Y           41      p           58      6
   8        I           25      Z           42      q           59      7
   9        J           26      a           43      r           60      8
   10       K           27      b           44      s           61      9
   11       L           28      c           45      t           62      +
   12       M           29      d           46      u           63      /
   13       N           30      e           47      v
   14       O           31      f           48      w           (pad) =
   15       P           32      g           49      x 
   16       Q           33      h           50      y
*/
char get_base64_char(uint8_t val)
{
    if (val < 26)
    {
        return 'A' + val;
    }

    if (val < 52)
    {
        return 'a' + val - 26;
    }

    if (val < 62)
    {
        return '0' + val - 52;
    }

    if (val == 62)
    {
        return '+';
    }

    if (val == 63)
    {
        return '/';
    }

    // error case
    throw SGX_QL_ERROR_INVALID_PARAMETER;
}

 std::string base64_encode(
    const void* source,
    const uint16_t custom_param_length)
{
    // Character set of base64 encoding scheme
    const uint8_t* input = static_cast<const uint8_t*>(source);

    // Group input string into 3 characters. Since we are converting 8 bit(3 bytes) to
    // 6 bit(4 bytes) and lcm of these is 24, the base case is having 24 bits to work with. 
    size_t groups = custom_param_length / 3;

    // Last group will either have 1 or 2 characters. This case will be handled
    // separately at the end.
    size_t last_group_size = custom_param_length % 3;
    std::string encoded_string;
    try
    {
        for(size_t i = 0; i < groups; ++i)
        {
            // To get base 64 encoded first byte, take the first 6 bits from the first byte of input string
            uint8_t byte1 = (input[i * 3] >> 2);
            // To get base 64 encoded second byte, take the first 4 bits from the second byte of the input
            // string and the remaining 2 bits of the first byte of the input string
            uint8_t byte2 = (input[i * 3 + 1] >> 4) | ((input[i * 3] & 3) << 4);
            // To get base 64 encoded third byte, take the first 2 bits from the third byte of the input string
            // and the remaining 4 bits of the second byte of the input string
            uint8_t byte3 = (input[i * 3 + 2] >> 6) | ((input[i * 3 + 1] & 15) << 2);
            // To get base 64 encoded last byte, take the remaining 6 bits from the third byte of the input string
            uint8_t byte4 = input[i * 3 + 2] & 63;
            encoded_string.push_back(get_base64_char(byte1));
            encoded_string.push_back(get_base64_char(byte2));
            encoded_string.push_back(get_base64_char(byte3));
            encoded_string.push_back(get_base64_char(byte4));
        }

        // Last group has 1 character to encode 
        if (last_group_size == 1)
        {
            // To get base 64 encoded first byte, take the first 6 bits from the
            // first byte of input string
            uint8_t byte1 = input[groups * 3] >> 2;
            // To get base 64 encoded second byte, take the remaining 2 bits of the first byte of the input string
            uint8_t byte2 = (input[groups * 3] & 3) << 4;
            encoded_string.push_back(get_base64_char(byte1));
            encoded_string.push_back(get_base64_char(byte2));

            // Add padding for the remianing bits
            encoded_string.push_back('=');
            encoded_string.push_back('=');
        }
        // Last group has 2 characters to encode 
        else if (last_group_size == 2)
        {
            // To get base 64 encoded first byte, take the first 6 bits from the
            // first byte of input string
            uint8_t byte1 = input[groups * 3] >> 2;
            // To get base 64 encoded second byte, take the first 4 bits from the
            // second byte of the input string and the remaining 2 bits of the first
            // byte of the input string
            uint8_t byte2 = (input[groups * 3 + 1] >> 4) | ((input[groups * 3] & 3) << 4);
            // To get base 64 encoded third byte, take the remaining 4 bits of the second
            // byte of the input string
            uint8_t byte3 = (input[groups * 3 + 1] & 15) << 2;
            encoded_string.push_back(get_base64_char(byte1));
            encoded_string.push_back(get_base64_char(byte2));
            encoded_string.push_back(get_base64_char(byte3));

            // Add padding for the remianing bits
            encoded_string.push_back('=');
        }
    return encoded_string;
    }
    catch(exception SGX_QL_ERROR_INVALID_PARAMETER)
    {
        log(SGX_QL_LOG_ERROR, "Incorrect parameter passed for encoding.");
        throw SGX_QL_ERROR_INVALID_PARAMETER;
    }
}

static std::string build_tcb_info_url(
    const std::string& fmspc,
    const void* custom_param = nullptr,
    const uint16_t custom_param_length = 0)
{
    std::string version = get_collateral_version();
    std::string client_id = get_client_id();
    std::stringstream tcb_info_url;
    tcb_info_url << get_base_url();

    if (!version.empty())
    {
        tcb_info_url << "/" << version;
    }

    tcb_info_url << "/tcb?";
    tcb_info_url << "fmspc=" << format_as_hex_string(fmspc.c_str(), fmspc.size()) << "&";

    if (custom_param != nullptr)
    {
        std::string encoded_str;
        try
        {
            encoded_str = base64_encode(custom_param, custom_param_length);
        }
        catch (exception e)
        {
            log(SGX_QL_LOG_ERROR, "TCB_Info_URL: Invalid parameters provided.");
            throw e;
        }
        tcb_info_url << customParam << "=" << encoded_str << "&";
    }


    if (!client_id.empty())
    {
        tcb_info_url << "clientid=" << client_id << "&";
    }
    tcb_info_url << API_VERSION_10_2018;
    return tcb_info_url.str();
}

//
// The expected URL for a given TCB.
//
static std::string build_tcb_info_url(
    const sgx_ql_get_revocation_info_params_t& params,
    const void* custom_param = nullptr,
    const uint16_t custom_param_length = 0)
{
    std::string fmspc((char*)params.fmspc, params.fmspc_size);
    std ::string tcb_info_url;
    try
    {
        tcb_info_url =
            build_tcb_info_url(fmspc, custom_param, custom_param_length);
        return tcb_info_url;
    }
    catch (exception e)
    {
        throw e;
    }

}

//
// The expected URL for QeID or QveID
//
static std::string build_enclave_id_url(
    bool qve,
    std::string& expected_issuer_chain_header,
    const void* custom_param = nullptr,
    const uint16_t custom_param_length = 0)
{
    std::string version = get_collateral_version();
    std::string client_id = get_client_id();
    std::stringstream qe_id_url;
    expected_issuer_chain_header = headers::QE_ISSUER_CHAIN;

    qe_id_url << get_base_url();

    // Select the correct issuer header name
    if (!version.empty())
    {
        qe_id_url << "/" << version;
        if (version != "v1")
        {
            expected_issuer_chain_header = headers::ENCLAVE_ID_ISSUER_CHAIN;
        }
    }

    // If QVE and V1 is specified, don't create a URL
    if (qve && version == "v1")
    {
        return "";
    }

    qe_id_url << "/" << (qve ? "qveid" : "qeid") << "?";

    if (custom_param != nullptr)
    {
        std::string encoded_str;
        try
        {
            encoded_str = base64_encode(custom_param, custom_param_length);
        }
        catch (exception e)
        {
            log(SGX_QL_LOG_ERROR, "Enclave_Id_URL: Invalid parameters provided.");
            throw e;
        }
        qe_id_url << customParam << "=" << encoded_str << "&";
    }

    if (!client_id.empty())
    {
        qe_id_url << "clientid=" << client_id << '&';
    }
    qe_id_url << API_VERSION_10_2018;
    return qe_id_url.str();
}

static std::unique_ptr<std::vector<uint8_t>> try_cache_get(
    const std::string& cert_url)
{
    try
    {
        return local_cache_get(cert_url);
    }
    catch (const std::runtime_error& error)
    {
        log(SGX_QL_LOG_WARNING, "Unable to access cache: %s", error.what());
        return nullptr;
    }
}

static std::string get_issuer_chain_cache_name(std::string url)
{
    return url + "IssuerChain";
}

static quote3_error_t get_collateral(
    CollateralTypes collateral_type,
    std::string url,
    const char *issuer_chain_header,
    std::vector<uint8_t>& response_body,
    std::string& issuer_chain,
    const std::string* const request_body = nullptr)
{
    quote3_error_t retval = SGX_QL_ERROR_UNEXPECTED;
    std::string friendly_name = get_collateral_friendly_name(collateral_type);
    try
    {
        std::string issuer_chain_cache_name = get_issuer_chain_cache_name(url);
        if (auto cache_hit_collateral = try_cache_get(url))
        {
            if (auto cache_hit_issuer_chain = try_cache_get(issuer_chain_cache_name))
            {
                log(SGX_QL_LOG_INFO,
                    "Fetching %s from cache: '%s'.",
                    friendly_name.c_str(),
                    url.c_str());
                response_body = *cache_hit_collateral;
                issuer_chain = std::string(cache_hit_issuer_chain->begin(), cache_hit_issuer_chain->end());
                log(SGX_QL_LOG_INFO,
                    "Successfully fetched %s from cache: '%s'.",
                    friendly_name.c_str(),
                    url.c_str());
                return SGX_QL_SUCCESS;
            }
        }
        log(SGX_QL_LOG_INFO,
            "Fetching %s from remote server: '%s'.",
            friendly_name.c_str(),
            url.c_str());

        const auto curl_operation = curl_easy::create(url, request_body);
        curl_operation->perform();
        response_body = curl_operation->get_body();
        auto get_issuer_chain_operation =
            get_unescape_header(*curl_operation, issuer_chain_header, &issuer_chain);
        retval = convert_to_intel_error(get_issuer_chain_operation);
        if (retval == SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_INFO,
                "Successfully fetched %s from URL: '%s'.",
                friendly_name.c_str(),
                url.c_str());
            std::string cache_control;
            auto get_cache_header_operation = get_unescape_header(*curl_operation, headers::CACHE_CONTROL, &cache_control);
            retval = convert_to_intel_error(get_cache_header_operation);
            if (retval == SGX_QL_SUCCESS)
            {
                // Update the cache
                time_t expiry = 0;
                if (get_cache_expiration_time(cache_control, url, expiry))
                {
                    local_cache_add(url, expiry, response_body.size(), response_body.data());
                    local_cache_add(issuer_chain_cache_name, expiry, issuer_chain.size(), issuer_chain.c_str());
                }
            }
        }

        return retval;
    }
    catch (const std::runtime_error& error)
    {
        log(SGX_QL_LOG_WARNING,
            "Runtime exception thrown, error: %s",
            error.what());
        // Swallow adding file to cache. Library can
        // operate without caching
        return retval;
    }
    catch (const curl_easy::error& error)
    {
        log(SGX_QL_LOG_ERROR,
            "curl error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_QL_NO_QUOTE_COLLATERAL_DATA
                   : SGX_QL_NETWORK_ERROR;
    }
}

bool check_cache(std::string cached_file_name, sgx_ql_config_t** pp_quote_config)
{
    bool fetch_from_cache = false;
    if (auto cache_hit = try_cache_get(cached_file_name))
    {
        fetch_from_cache = true;
        log(SGX_QL_LOG_INFO,
            "Fetching quote config from cache: '%s'.",
            cached_file_name.c_str());

        *pp_quote_config = (sgx_ql_config_t*)(new uint8_t[cache_hit->size()]);
        memcpy(*pp_quote_config, cache_hit->data(), cache_hit->size());

        // re-aligning the p_cert_data pointer
        (*pp_quote_config)->p_cert_data =
            (uint8_t*)(*pp_quote_config) + sizeof(sgx_ql_config_t);
    }
    return fetch_from_cache;
}

bool fetch_response(
    std::string base_url,
    std::unique_ptr<curl_easy>& curl,
    std::map<std::string, std::string> header_value,
    quote3_error_t &retval,
    unsigned long dwFlags = 0x00800000)
{
    bool fetch_response = false;
    try
    {
        curl = curl_easy::create(base_url, nullptr, dwFlags);
        log(SGX_QL_LOG_INFO,
            "Fetching certificate from: '%s'.",
            base_url.c_str());
        curl->set_headers(header_value);
        curl->perform();
        fetch_response = true;
    }
    catch (const std::bad_alloc&)
    {
        log_message(SGX_QL_LOG_ERROR, "Out of memory thrown");
        retval = SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (const std::runtime_error& error)
    {
        log(SGX_QL_LOG_WARNING,
            "Runtime exception thrown, error: %s",
            error.what());
    }
    catch (const curl_easy::error& error)
    {
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
    }
    return fetch_response;
}

extern "C" quote3_error_t sgx_ql_get_quote_config(
    const sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_ql_config_t** pp_quote_config)
{
    *pp_quote_config = nullptr;

    try
    {
        bool recieved_certificate = false;
        quote3_error_t retval;
        sgx_ql_config_t temp_config{};
        nlohmann::json json_body;
        certificate_fetch_url certificate_url;
        std::vector<uint8_t> response_body;
        std::unique_ptr<curl_easy> curl;
        std::string cert_data;
        std::stringstream cached_file_name;

        build_pck_cert_url(*p_pck_cert_id, certificate_url, cached_file_name);
        std::string primary_base_url = certificate_url.primary_base_url.str();
        std::string secondary_base_url = certificate_url.secondary_base_url.str();

        std::string bypass_base = bypass_base_url();
        transform(
            bypass_base.begin(),
            bypass_base.end(),
            bypass_base.begin(),
            ::tolower);
        try
        {
            if (bypass_base.compare("false") == 0)
            {
                log(SGX_QL_LOG_INFO,
                    "Trying to fetch response from primary URL: '%s'.",
                    primary_base_url.c_str());
                recieved_certificate = fetch_response(
                    primary_base_url,
                    curl,
                    headers::localhost_metadata,
                    retval,
                    0);
            }
            if (recieved_certificate)
            {
                log(SGX_QL_LOG_INFO,
                    "Successfully fetched certificate from primary URL: '%s'.",
                    primary_base_url.c_str());
            }
            else
            {
                log(SGX_QL_LOG_INFO,
                    "Trying to fetch response from local cache.");
                recieved_certificate =
                    check_cache(cached_file_name.str(), pp_quote_config);
                if (recieved_certificate)
                {
                    log(SGX_QL_LOG_INFO,
                        "Successfully fetched certificate from cache.");
                    return SGX_QL_SUCCESS;
                }
                else
                {
                    log(SGX_QL_LOG_INFO,
                        "Certificate not found in local cache. Trying to fetch response from secondary URL: '%s'.",
                        secondary_base_url.c_str());
                    recieved_certificate = fetch_response(
                        secondary_base_url,
                        curl,
                        headers::default_values,
                        retval);
                    if (!recieved_certificate)
                        return retval;
                    log(SGX_QL_LOG_INFO,
                        "Successfully fetched certificate from secondary URL: '%s'.",
                        secondary_base_url.c_str());
                }
            }

            // Parse the body returned by host agent to extract
            // 1. Certificate
            // 2. TCB Info
            // 3. Cert Chain
            // This will be returned to the caller.
            response_body = curl->get_body();
            json_body = nlohmann::json::parse(response_body);
        }
        catch (const std::exception& error)
        {
            log(SGX_QL_LOG_ERROR,
                "Unknown exception thrown, error: %s",
                error.what());
        }

        // parse the SVNs into a local data structure so we can handle any
        // parse errors before allocating the output buffer
        if (const sgx_plat_error_t err = parse_svn_values(*curl, json_body, &temp_config))
        {
            return convert_to_intel_error(err);
        }

        const sgx_plat_error_t err = build_cert_chain(*curl, json_body, &cert_data);
        retval = convert_to_intel_error(err);
        if (retval == SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_INFO, "Successfully parsed certificate chain: %s.", cert_data.c_str());
        }
        else
        {
            log(SGX_QL_LOG_ERROR, "Unable to parse certificate chain from the response.");
            return retval;
        }

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
        memcpy(
            (*pp_quote_config)->p_cert_data, cert_data.data(), cert_data_size);
        buf += cert_data_size;
        assert(buf == buf_end);

        // Get the cache control header
        std::string cache_control;
        auto get_cache_header_operation = extract_from_json(
            json_body, headers::CERT_CACHE_CONTROL, &cache_control);
        retval = convert_to_intel_error(get_cache_header_operation);
        if (retval == SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_INFO,
                "%s : %s",
                headers::CERT_CACHE_CONTROL,
                cache_control.c_str());
            time_t expiry = 0;
            if (get_cert_cache_expiration_time(cache_control, cached_file_name.str(), expiry))
            {
                local_cache_add(cached_file_name.str(), expiry, buf_size, *pp_quote_config);
            }
        }
        else
        {
            log(SGX_QL_LOG_ERROR, "Unable to add certificate to local cache.");
        }
    }
    catch (const std::bad_alloc&)
    {
        log_message(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (const curl_easy::error& error)
    {
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_QL_NO_PLATFORM_CERT_DATA
                   : SGX_QL_ERROR_UNEXPECTED;
    }
    catch (const std::runtime_error& error)
    {
        log(SGX_QL_LOG_WARNING,
            "Runtime exception thrown, error: %s",
            error.what());
        // Swallow adding file to cache. Library can
        // operate without caching
        // return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_QL_ERROR_UNEXPECTED;
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

            const auto crl_operation = curl_easy::create(crl_url, nullptr);
            log(SGX_QL_LOG_INFO,
                "Fetching revocation info from remote server: '%s'",
                crl_url.c_str());
            crl_operation->set_headers(headers::default_values);
            crl_operation->perform();
            log(SGX_QL_LOG_INFO,
                "Successfully fetched %s from URL: '%s'",
                get_collateral_friendly_name(CollateralTypes::PckCrl).c_str(),
                crl_url.c_str());
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
            std::string tcb_info_url = build_tcb_info_url(*params);

            const auto tcb_info_operation =
                curl_easy::create(tcb_info_url, nullptr);
            log(SGX_QL_LOG_INFO,
                "Fetching TCB Info from remote server: '%s'.",
                tcb_info_url.c_str());
            tcb_info_operation->perform();
            log(SGX_QL_LOG_INFO,
                "Successfully fetched '%s' from URL: '%s'",
                get_collateral_friendly_name(CollateralTypes::TcbInfo).c_str(),
                tcb_info_url.c_str());

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
    catch (const std::bad_alloc&)
    {
        return SGX_PLAT_ERROR_OUT_OF_MEMORY;
    }
    catch (const std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        delete[] buffer;
        *pp_revocation_info = nullptr;
        return SGX_PLAT_ERROR_OVERFLOW;
    }
    catch (const curl_easy::error& error)
    {
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_PLAT_NO_DATA_FOUND
                   : SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
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
        std::string issuer_chain_header;
        std::string issuer_chain;
        std::string request_id;
        size_t total_buffer_size = 0;
        std::string qe_id_url;
        try
        {
            qe_id_url = build_enclave_id_url(false, issuer_chain_header);
        }
        catch (exception e)
        {
            log(SGX_QL_LOG_ERROR, "QE_ID_URL can't be formed. Validate the parameters passed.");
            return SGX_PLAT_ERROR_INVALID_PARAMETER;
        }

        const auto curl = curl_easy::create(qe_id_url, nullptr);
        log(SGX_QL_LOG_INFO,
            "Fetching QE Identity from remote server: '%s'.",
            qe_id_url.c_str());
        curl->perform();
        log(SGX_QL_LOG_INFO,
            "Successfully fetched '%s' from URL: '%s'",
            get_collateral_friendly_name(CollateralTypes::QeIdentity).c_str(),
            qe_id_url.c_str());

        // issuer chain
        result = get_unescape_header(*curl, issuer_chain_header, &issuer_chain);
        if (result != SGX_PLAT_ERROR_OK)
            return result;

        // read response_body
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
    catch (const std::bad_alloc&)
    {
        return SGX_PLAT_ERROR_OUT_OF_MEMORY;
    }
    catch (const std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        *pp_qe_identity_info = nullptr;
        return SGX_PLAT_ERROR_OVERFLOW;
    }
    catch (const curl_easy::error& error)
    {
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_PLAT_NO_DATA_FOUND
                   : SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }

    return SGX_PLAT_ERROR_OK;
}

extern "C" void sgx_free_qe_identity_info(
    sgx_qe_identity_info_t* p_qe_identity_info)
{
    delete[] reinterpret_cast<uint8_t*>(p_qe_identity_info);
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

extern "C" quote3_error_t sgx_ql_free_quote_verification_collateral(
    sgx_ql_qve_collateral_t* p_quote_collateral)
{
    delete[] p_quote_collateral->pck_crl;
    delete[] p_quote_collateral->root_ca_crl;
    delete[] p_quote_collateral->tcb_info;
    delete[] p_quote_collateral->tcb_info_issuer_chain;
    delete[] p_quote_collateral->qe_identity;
    delete[] p_quote_collateral->qe_identity_issuer_chain;
    delete[] p_quote_collateral->pck_crl_issuer_chain;
    delete[] p_quote_collateral;
    p_quote_collateral = nullptr;
    return SGX_QL_SUCCESS;
}

extern "C" quote3_error_t sgx_ql_free_qve_identity(
    char* p_qve_identity,
    char* p_qve_identity_issuer_chain)
{
    delete[] p_qve_identity;
    delete[] p_qve_identity_issuer_chain;
    p_qve_identity = nullptr;
    p_qve_identity_issuer_chain = nullptr;
    return SGX_QL_SUCCESS;
}

extern "C" quote3_error_t sgx_ql_free_root_ca_crl(char* p_root_ca_crl)
{
    delete[] p_root_ca_crl;
    return SGX_QL_SUCCESS;
}

quote3_error_t sgx_ql_fetch_quote_verification_collateral(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_quote_collateral,
    const void* custom_param = nullptr,
    const  uint16_t custom_param_length = 0)
{
    log(SGX_QL_LOG_INFO, "Getting quote verification collateral");
    sgx_ql_qve_collateral_t* p_quote_collateral = nullptr;

    try
    {
        if (fmspc == nullptr)
        {
            log(SGX_QL_LOG_ERROR, "FMSPC is null");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (fmspc_size == 0)
        {
            log(SGX_QL_LOG_ERROR, "FMSPC buffer size is 0");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (pck_ca == nullptr)
        {
            log(SGX_QL_LOG_ERROR, "PCK CA is null");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (pp_quote_collateral == nullptr)
        {
            log(SGX_QL_LOG_ERROR, "Pointer to collateral pointer is null");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (*pp_quote_collateral != nullptr)
        {
            log(SGX_QL_LOG_ERROR,
                "Collateral pointer is not null. This memory will be allocated by this library");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        std::string requested_ca;
        std::string root_crl_name = ROOT_CRL_NAME;
        if (strcmp(CRL_CA_PROCESSOR, pck_ca) == 0)
        {
            requested_ca = PROCESSOR_CRL_NAME;
        }

        if (strcmp(CRL_CA_PLATFORM, pck_ca) == 0)
        {
            requested_ca = PLATFORM_CRL_NAME;
            root_crl_name = ROOT_CRL_NAME;
        }

        if (requested_ca.empty())
        {
            log(SGX_QL_LOG_ERROR,
                "PCK CA must be either %s or %s",
                CRL_CA_PROCESSOR,
                CRL_CA_PLATFORM);
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        std::string str_fmspc((char*)fmspc, fmspc_size);
        quote3_error_t operation_result;
        std::vector<uint8_t> pck_crl;
        std::string pck_issuer_chain;
        std::vector<uint8_t> root_ca_crl;
        std::string root_ca_chain;
        std::vector<uint8_t> tcb_info;
        std::string tcb_issuer_chain;
        std::vector<uint8_t> qe_identity;
        std::string qe_identity_issuer_chain;

        // Get PCK CRL
        std::string pck_crl_url = build_pck_crl_url(requested_ca, API_VERSION_02_2020);
        operation_result = get_collateral(
            CollateralTypes::PckCrl,
            pck_crl_url,
            headers::CRL_ISSUER_CHAIN,
            pck_crl,
            pck_issuer_chain);
        if (operation_result != SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_ERROR,
                "Error fetching PCK CRL: %d",
                operation_result);
            return operation_result;
        }

        // Get Root CA CRL
        std::string root_ca_crl_url =
            build_pck_crl_url(root_crl_name, API_VERSION_02_2020);
        operation_result = get_collateral(
            CollateralTypes::PckRootCrl,
            root_ca_crl_url,
            headers::CRL_ISSUER_CHAIN,
            root_ca_crl,
            root_ca_chain);
        if (operation_result != SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_ERROR,
                "Error fetching Root CA CRL: %d",
                operation_result);
            return operation_result;
        }

        // Get Tcb Info & Issuer Chain
        std::string tcb_info_url;
        try
        {
            tcb_info_url = build_tcb_info_url(
                str_fmspc, custom_param, custom_param_length);
        }
        catch (exception& e)
        {
            log(SGX_QL_LOG_ERROR, "TCB_INFO_URL can't be formed. Validate the parameters passed.");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        const auto tcb_info_operation = 
            curl_easy::create(tcb_info_url, nullptr);

        operation_result = get_collateral(
            CollateralTypes::TcbInfo,
            tcb_info_url,
            headers::TCB_INFO_ISSUER_CHAIN,
            tcb_info,
            tcb_issuer_chain);
        if (operation_result != SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_ERROR,
                "Error fetching TCB Info: %d",
                operation_result);
            return operation_result;
        }

        // Get QE Identity & Issuer Chain
        std::string issuer_chain_header;
        std::string qe_identity_url;
        try
        {
            qe_identity_url = build_enclave_id_url(
                false, issuer_chain_header, custom_param, custom_param_length);
        }
        catch (exception e)
        {
            log(SGX_QL_LOG_ERROR,
                "QE_IDENTITY_URL can't be formed. Validate the parameters passed.");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }
        const auto qe_identity_operation =
            curl_easy::create(qe_identity_url, nullptr);

        operation_result = get_collateral(
            CollateralTypes::QeIdentity,
            qe_identity_url,
            issuer_chain_header.c_str(),
            qe_identity,
            qe_identity_issuer_chain);
        if (operation_result != SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_ERROR,
                "Error fetching QE Identity: %d",
                operation_result);
            return operation_result;
        }

        // Allocate the memory for the structure
        size_t buffer_size = sizeof(sgx_ql_qve_collateral_t);
        *pp_quote_collateral = (sgx_ql_qve_collateral_t*)new char[buffer_size];
        p_quote_collateral = *pp_quote_collateral;
        memset(p_quote_collateral, 0, buffer_size);

        // Fill in the buffer contents
        p_quote_collateral->version = 1;
        quote3_error_t result;
        result = fill_qpl_string_buffer(
            pck_issuer_chain,
            p_quote_collateral->pck_crl_issuer_chain,
            p_quote_collateral->pck_crl_issuer_chain_size);
        if (result == SGX_QL_SUCCESS)
        {
            result = fill_qpl_string_buffer(
                root_ca_crl,
                p_quote_collateral->root_ca_crl,
                p_quote_collateral->root_ca_crl_size);
            if (result == SGX_QL_SUCCESS)
            {
                result = fill_qpl_string_buffer(
                    pck_crl,
                    p_quote_collateral->pck_crl,
                    p_quote_collateral->pck_crl_size);
                if (result == SGX_QL_SUCCESS)
                {
                    result = fill_qpl_string_buffer(
                        tcb_issuer_chain,
                        p_quote_collateral->tcb_info_issuer_chain,
                        p_quote_collateral->tcb_info_issuer_chain_size);
                }
                if (result == SGX_QL_SUCCESS)
                {
                    result = fill_qpl_string_buffer(
                        tcb_info,
                        p_quote_collateral->tcb_info,
                        p_quote_collateral->tcb_info_size);
                    if (result == SGX_QL_SUCCESS)
                    {
                        result = fill_qpl_string_buffer(
                            qe_identity_issuer_chain,
                            p_quote_collateral->qe_identity_issuer_chain,
                            p_quote_collateral->qe_identity_issuer_chain_size);
                        if (result == SGX_QL_SUCCESS)
                        {
                            result = fill_qpl_string_buffer(
                                qe_identity,
                                p_quote_collateral->qe_identity,
                                p_quote_collateral->qe_identity_size);
                        }
                    }
                }
            }
        }

        return result;
    }
    catch (const std::bad_alloc&)
    {
        sgx_ql_free_quote_verification_collateral(p_quote_collateral);
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (const std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        sgx_ql_free_quote_verification_collateral(p_quote_collateral);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_QL_ERROR_UNEXPECTED;
    }
}

extern "C" quote3_error_t sgx_ql_get_quote_verification_collateral(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_quote_collateral)
{
    return sgx_ql_fetch_quote_verification_collateral(
        fmspc, fmspc_size, pck_ca, pp_quote_collateral);
}

extern "C" quote3_error_t sgx_ql_get_quote_verification_collateral_with_params(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    const void* custom_param,
    const uint16_t custom_param_length,
    sgx_ql_qve_collateral_t** pp_quote_collateral)
{
    return sgx_ql_fetch_quote_verification_collateral(
        fmspc,
        fmspc_size,
        pck_ca,
        pp_quote_collateral,
        custom_param,
        custom_param_length);
}

extern "C" quote3_error_t sgx_ql_get_qve_identity(
    char** pp_qve_identity,
    uint32_t* p_qve_identity_size,
    char** pp_qve_identity_issuer_chain,
    uint32_t* p_qve_identity_issuer_chain_size)
{
    try
    {
        log(SGX_QL_LOG_INFO, "Getting quote verification enclave identity");
        if (pp_qve_identity == nullptr)
        {
            log(SGX_QL_LOG_ERROR, "Pointer to qve identity pointer is null");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (*pp_qve_identity != nullptr)
        {
            log(SGX_QL_LOG_ERROR,
                "Qve identity pointer is not null. This memory will be "
                "allocated by "
                "this library");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (pp_qve_identity_issuer_chain == nullptr)
        {
            log(SGX_QL_LOG_ERROR, "Pointer to issuer chain pointer is null");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (*pp_qve_identity_issuer_chain != nullptr)
        {
            log(SGX_QL_LOG_ERROR,
                "Issuer chain pointer is not null. This memory will be "
                "allocated by "
                "this library");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        std::vector<uint8_t> qve_identity;
        std::string expected_issuer;
        std::string issuer_chain;
        std::string qve_url;
        try
        {
            qve_url = build_enclave_id_url(true, expected_issuer);
            if (qve_url.empty())
            {
                log(SGX_QL_LOG_ERROR, "V1 QVE is not supported");
                return SGX_QL_ERROR_INVALID_PARAMETER;
            }
        }
        catch (exception e)
        {
            log(SGX_QL_LOG_ERROR, "QVE_URL can't be formed. Validate the parameters passed.");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        quote3_error_t operation_result = get_collateral(
            CollateralTypes::QveIdentity,
            qve_url, expected_issuer.c_str(), qve_identity, issuer_chain);
        if (operation_result != SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_ERROR,
                "Error fetching QVE Identity: %d",
                operation_result);
        }

        operation_result = fill_qpl_string_buffer(
            qve_identity, *pp_qve_identity, *p_qve_identity_size);
        if (operation_result == SGX_QL_SUCCESS)
        {
            operation_result = fill_qpl_string_buffer(
                issuer_chain,
                *pp_qve_identity_issuer_chain,
                *p_qve_identity_issuer_chain_size);
        }

        return operation_result;
    }
    catch (const std::bad_alloc&)
    {
        sgx_ql_free_qve_identity(
            *pp_qve_identity, *pp_qve_identity_issuer_chain);
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (const std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        sgx_ql_free_qve_identity(
            *pp_qve_identity, *pp_qve_identity_issuer_chain);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_QL_ERROR_UNEXPECTED;
    }
}

extern "C" quote3_error_t sgx_ql_get_root_ca_crl(
    char** pp_root_ca_crl,
    uint16_t* p_root_ca_crl_size)
{
    try
    {
        log(SGX_QL_LOG_INFO, "Getting root ca crl");
        if (pp_root_ca_crl == nullptr)
        {
            log(SGX_QL_LOG_ERROR, "Pointer to crl pointer is null");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        if (*pp_root_ca_crl != nullptr)
        {
            log(SGX_QL_LOG_ERROR,
                "Crl pointer is not null. This memory will be allocated by "
                "this library");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        std::string root_ca_crl_url =
            build_pck_crl_url(ROOT_CRL_NAME, API_VERSION_02_2020);
        std::vector<uint8_t> root_ca_crl;
        std::string root_ca_chain;

        auto operation_result = get_collateral(
            CollateralTypes::PckRootCrl,
            root_ca_crl_url,
            headers::CRL_ISSUER_CHAIN,
            root_ca_crl,
            root_ca_chain);
        if (operation_result != SGX_QL_SUCCESS)
        {
            log(SGX_QL_LOG_ERROR,
                "Error fetching Root CA CRL: %d",
                operation_result);
            return operation_result;
        }

        // Set the out parameters
        uint32_t bufferSize;
        auto retval =
            fill_qpl_string_buffer(root_ca_crl, *pp_root_ca_crl, bufferSize);
        *p_root_ca_crl_size = (uint16_t)bufferSize;
        return retval;
    }
    catch (const std::bad_alloc&)
    {
        sgx_ql_free_root_ca_crl(*pp_root_ca_crl);
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (const std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        sgx_ql_free_root_ca_crl(*pp_root_ca_crl);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (const std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_QL_ERROR_UNEXPECTED;
    }
}