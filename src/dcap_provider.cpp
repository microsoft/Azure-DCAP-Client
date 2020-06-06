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
constexpr char ENCLAVE_ID_ISSUER_CHAIN[] = "SGX-Enclave-Identity-Issuer-Chain";
constexpr char REQUEST_ID[] = "Request-ID";
constexpr char CACHE_CONTROL[] = "Cache-Control";

static const std::map<std::string, std::string> default_values = {
    {"Content-Type", "application/json"}
};

}; // namespace headers

// New API version used to request PEM encoded CRLs
constexpr char API_VERSION_LEGACY[] = "api-version=2018-10-01-preview";
constexpr char API_VERSION[] = "api-version=2020-02-12-preview";

static char DEFAULT_CERT_URL[] =
    "https://global.acccache.azure.net/sgx/certificates";
static std::string cert_base_url = DEFAULT_CERT_URL;

static char DEFAULT_CLIENT_ID[] = "production_client";
static std::string prod_client_id = DEFAULT_CLIENT_ID;

static char DEFAULT_COLLATERAL_VERSION[] = "v2";
static std::string default_collateral_version = DEFAULT_COLLATERAL_VERSION;

static char CRL_CA_PROCESSOR[] = "processor";
static char CRL_CA_PLATFORM[] = "platform";
static char ROOT_CRL_NAME[] =
    "https%3a%2f%2fcertificates.trustedservices.intel.com%2fintelsgxrootca.crl";
static char PROCESSOR_CRL_NAME[] = "https%3a%2f%2fcertificates.trustedservices."
                                   "intel.com%2fintelsgxpckprocessor.crl";

enum class CollateralTypes
{
    TcbInfo,
    QeIdentity,
    QveIdentity,
    PckCert,
    PckCrl,
    PckRootCrl
};

using namespace std;

static std::string get_env_variable(std::string env_variable)
{
    auto retval = get_env_variable_no_log(env_variable);
    if (!retval.second.empty())
    {
        log(SGX_QL_LOG_ERROR, retval.second.c_str());
    }
    return retval.first;
}

static std::string get_collateral_version()
{
    std::string collateral_version =
        get_env_variable(ENV_AZDCAP_COLLATERAL_VER);

    if (collateral_version.empty())
    {
        log(SGX_QL_LOG_WARNING,
            "Using default collateral version '%s'.",
            default_collateral_version.c_str());
        return default_collateral_version;
    }
    else
    {
        if (!collateral_version.compare("v1") &&
            !collateral_version.compare("v2"))
        {
            log(SGX_QL_LOG_ERROR,
                "Value specified in environment variable '%s' is invalid. "
                "Acceptable values are empty, v1, or v2",
                collateral_version.c_str(),
                MAX_ENV_VAR_LENGTH);

            log(SGX_QL_LOG_WARNING,
                "Using default collateral version '%s'.",
                default_collateral_version.c_str());
            return default_collateral_version;
        }

        log(SGX_QL_LOG_INFO,
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
        log(SGX_QL_LOG_WARNING,
            "Using default base cert URL '%s'.",
            cert_base_url.c_str());
        return cert_base_url;
    }

    log(SGX_QL_LOG_INFO,
        "Using %s envvar for base cert URL, set to '%s'.",
        ENV_AZDCAP_BASE_URL,
        env_base_url.c_str());
    return env_base_url;
}

static std::string get_client_id()
{
    std::string env_client_id = get_env_variable(ENV_AZDCAP_CLIENT_ID);

    if (env_client_id.empty())
    {
        log(SGX_QL_LOG_WARNING,
            "Using default client id '%s'.",
            prod_client_id.c_str());
        return prod_client_id;
    }

    log(SGX_QL_LOG_INFO,
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
// Determine time cache should invalidate for given collateral
//
bool get_cache_expiration_time(const string &cache_control, const string &url, time_t &expiration_time)
{
    time_t max_age = 0;
    tm* max_age_s = localtime(&max_age);
    string match = "max-age=";
    size_t index = cache_control.find(match);
    int cache_time_seconds = 0;
    if (index != string::npos)
    {
        try 
        {
            cache_time_seconds = stoi(cache_control.substr(index + match.length()));
        }
        catch (std::invalid_argument e)
        {
            log(SGX_QL_LOG_ERROR,
                "Invalid argument thrown when parsing cache-control. Header text: '%s' Error: '%s'",
                cache_control.c_str(),
                e.what());
            cache_time_seconds = 0;
            return false;
        }
        catch (std::out_of_range e)
        {
            log(SGX_QL_LOG_ERROR,
                "Invalid argument thrown when parsing cache-control. Header "
                "text: '%s' Error: '%s'",
                cache_control.c_str(),
                e.what());
            cache_time_seconds = 0;
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
    switch(collateral_type)
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
    {
        log(SGX_QL_LOG_INFO,
            "Failed to escape header %s\n",
            header_item.c_str());
        return result;
    }

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
    if (in > (std::numeric_limits<output_t>::max)())
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

    std::string version = get_collateral_version();
    std::stringstream pck_cert_url;
    pck_cert_url << get_base_url();
    if (!version.empty())
    {
        pck_cert_url << '/';
        pck_cert_url << version;
    }
    pck_cert_url << '/' << qe_id;
    pck_cert_url << '/' << cpu_svn;
    pck_cert_url << '/' << pce_svn;
    pck_cert_url << '/' << pce_id;
    pck_cert_url << '?';

    std::string client_id = get_client_id();
    if (!client_id.empty())
    {
        pck_cert_url << "clientid=" << client_id << '&';
    }
    pck_cert_url << API_VERSION_LEGACY;
    return pck_cert_url.str();
}

//
// Build a complete cert chain from a completed curl object.
//
static std::string build_cert_chain(const curl_easy& curl)
{
    std::string leaf_cert(curl.get_body().begin(), curl.get_body().end());

    // The cache service does not return a newline in the response
    // response_body. Add one here so that we have a properly formatted chain.
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
    *out = build_pck_crl_url(crl_url, API_VERSION_LEGACY);
    return SGX_PLAT_ERROR_OK;
}

static std::string build_tcb_info_url(const std::string& fmspc)
{
    std::string version = get_collateral_version();
    std::string client_id = get_client_id();
    std::stringstream tcb_info_url;
    tcb_info_url << get_base_url();

    if (!version.empty())
    {
        tcb_info_url << "/" << version;
    }
    tcb_info_url << "/tcb/";
    tcb_info_url << format_as_hex_string(fmspc.c_str(), fmspc.size()) << "?";

    if (!client_id.empty())
    {
        tcb_info_url << "clientid=" << client_id << "&";
    }
    tcb_info_url << API_VERSION_LEGACY;
    return tcb_info_url.str();
}

//
// The expected URL for a given TCB.
//
static std::string build_tcb_info_url(
    const sgx_ql_get_revocation_info_params_t& params)
{
    std::string fmspc((char*)params.fmspc, params.fmspc_size);
    return build_tcb_info_url(fmspc);
}

//
// The expected URL for QeID or QveID
//
static std::string build_enclave_id_url(
    bool qve,
    std::string& expected_issuer_chain_header)
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
    if (qve && version != "v2")
    {
        return "";
    }

    qe_id_url << "/" << (qve ? "qveid" : "qeid") << "?";

    if (!client_id.empty())
    {
        qe_id_url << "clientid=" << client_id << '&';
    }
    qe_id_url << API_VERSION_LEGACY;
    return qe_id_url.str();
}

static std::unique_ptr<std::vector<uint8_t>> try_cache_get(
    const std::string& cert_url)
{
    try 
    {
        return local_cache_get(cert_url);
    }
    catch (std::runtime_error& error)
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
    const char issuer_chain_header[],
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

        std::string cache_control;
        auto get_cache_header_operation =
            get_unescape_header(*curl_operation, headers::CACHE_CONTROL, &cache_control);

        retval = convert_to_intel_error(get_issuer_chain_operation);

        if (retval == SGX_QL_SUCCESS)
        {
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
    catch (std::runtime_error& error)
    {
        log(SGX_QL_LOG_WARNING,
            "Runtime exception thrown, error: %s",
            error.what());
        // Swallow adding file to cache. Library can
        // operate without caching
        return retval;
    }
    catch (curl_easy::error& error)
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

static std::string build_eppid_json(const sgx_ql_pck_cert_id_t& pck_cert_id)
{
    const std::string disable_ondemand = get_env_variable(ENV_AZDCAP_DISABLE_ONDEMAND);
    if (!disable_ondemand.empty())
    {
        if (disable_ondemand == "1")
        {
            log(SGX_QL_LOG_WARNING, "On demand registration disabled by environment variable. No eppid being sent to caching service");
            return "";
        }
    }

    const std::string eppid = format_as_hex_string(
        pck_cert_id.p_encrypted_ppid, pck_cert_id.encrypted_ppid_size);

    if (eppid.empty())
    {
        log(SGX_QL_LOG_WARNING, "No eppid provided - unable to send to caching service");
        return "";
    }
    else 
    {
        log(SGX_QL_LOG_INFO, "Sending the provided eppid to caching service");
    }

    static const char json_prefix[] = "{\"eppid\":\"";
    static const char json_postfix[] = "\"}\n";

    std::stringstream json;
    json << json_prefix;
    json << eppid;
    json << json_postfix;
    return json.str();
}

extern "C" quote3_error_t sgx_ql_get_quote_config(
    const sgx_ql_pck_cert_id_t* p_pck_cert_id,
    sgx_ql_config_t** pp_quote_config)
{
    *pp_quote_config = nullptr;

    try
    {
        const std::string cert_url = build_pck_cert_url(*p_pck_cert_id);
        if (auto cache_hit = try_cache_get(cert_url))
        {
            log(SGX_QL_LOG_INFO,
                "Fetching quote config from cache: '%s'.",
                cert_url.c_str());

            *pp_quote_config =
                (sgx_ql_config_t*)(new uint8_t[cache_hit->size()]);
            memcpy(*pp_quote_config, cache_hit->data(), cache_hit->size());

            // re-aligning the p_cert_data pointer
            (*pp_quote_config)->p_cert_data =
                (uint8_t*)(*pp_quote_config) + sizeof(sgx_ql_config_t);

            return SGX_QL_SUCCESS;
        }
        
        const std::string eppid_json = build_eppid_json(*p_pck_cert_id);
        const auto curl = curl_easy::create(cert_url, &eppid_json);
        log(SGX_QL_LOG_INFO,
            "Fetching quote config from remote server: '%s'.",
            cert_url.c_str());
        curl->set_headers(headers::default_values);
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

        // parse the SVNs into a local data structure so we can handle any parse
        // errors before allocating the output buffer
        sgx_ql_config_t temp_config{};
        if (const sgx_plat_error_t err = parse_svn_values(*curl, &temp_config))
        {
            return convert_to_intel_error(err);
        }

        const std::string cert_data = build_cert_chain(*curl);

        // get the cache control header
        std::string cache_control;
        auto get_cache_header_operation = get_unescape_header(
            *curl, headers::CACHE_CONTROL, &cache_control);

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

        auto retval = convert_to_intel_error(get_cache_header_operation);
        if (retval == SGX_QL_SUCCESS)
        {
            time_t expiry;
            if (get_cache_expiration_time(cache_control, cert_url, expiry))
            {
                local_cache_add(cert_url, expiry, buf_size, *pp_quote_config);
            }
        }
    }
    catch (std::bad_alloc&)
    {
        log_message(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (curl_easy::error& error)
    {
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_QL_NO_PLATFORM_CERT_DATA
                   : SGX_QL_ERROR_UNEXPECTED;
    }
    catch (std::runtime_error& error)
    {
        log(SGX_QL_LOG_WARNING,
            "Runtime exception thrown, error: %s",
            error.what());
        // Swallow adding file to cache. Library can
        // operate without caching
        // return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (std::exception& error)
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
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_PLAT_NO_DATA_FOUND
                   : SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    catch (std::exception& error)
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
        std::string qe_id_url =
            build_enclave_id_url(false, issuer_chain_header);

        const auto curl = curl_easy::create(qe_id_url, nullptr);
        log(SGX_QL_LOG_INFO,
            "Fetching QE Identity from remote server: '%s'.",
            qe_id_url.c_str());
        curl->perform();

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
        log(SGX_QL_LOG_ERROR,
            "error thrown, error code: %x: %s",
            error.code,
            error.what());
        return error.code == CURLE_HTTP_RETURNED_ERROR
                   ? SGX_PLAT_NO_DATA_FOUND
                   : SGX_PLAT_ERROR_UNEXPECTED_SERVER_RESPONSE;
    }
    catch (std::exception& error)
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

extern "C" quote3_error_t sgx_ql_get_quote_verification_collateral(
    const uint8_t* fmspc,
    const uint16_t fmspc_size,
    const char* pck_ca,
    sgx_ql_qve_collateral_t** pp_quote_collateral)
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
                "Collateral pointer is not null. This memory will be allocated "
                "by "
                "this library");
            return SGX_QL_ERROR_INVALID_PARAMETER;
        }

        std::string requested_ca;
        if (strcmp(CRL_CA_PROCESSOR, pck_ca) == 0)
        {
            requested_ca = PROCESSOR_CRL_NAME;
        }

        if (strcmp(CRL_CA_PLATFORM, pck_ca) == 0)
        {
            log(SGX_QL_LOG_ERROR, "Platform CA CRL is not supported");
            return SGX_QL_ERROR_INVALID_PARAMETER;
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
        std::string pck_crl_url = build_pck_crl_url(requested_ca, API_VERSION);
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
            build_pck_crl_url(ROOT_CRL_NAME, API_VERSION);
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
        std::string tcb_info_url = build_tcb_info_url(str_fmspc);
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
        std::string qe_identity_url = build_enclave_id_url(false, issuer_chain_header);
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
    catch (std::bad_alloc&)
    {
        sgx_ql_free_quote_verification_collateral(p_quote_collateral);
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        sgx_ql_free_quote_verification_collateral(p_quote_collateral);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_QL_ERROR_UNEXPECTED;
    }
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
        std::string qve_url = build_enclave_id_url(true, expected_issuer);
        if (qve_url.empty())
        {
            log(SGX_QL_LOG_ERROR, "V1 QVE is not supported");
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
    catch (std::bad_alloc&)
    {
        sgx_ql_free_qve_identity(
            *pp_qve_identity, *pp_qve_identity_issuer_chain);
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        sgx_ql_free_qve_identity(
            *pp_qve_identity, *pp_qve_identity_issuer_chain);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (std::exception& error)
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
            build_pck_crl_url(ROOT_CRL_NAME, API_VERSION);
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
    catch (std::bad_alloc&)
    {
        sgx_ql_free_root_ca_crl(*pp_root_ca_crl);
        log(SGX_QL_LOG_ERROR, "Out of memory thrown");
        return SGX_QL_ERROR_OUT_OF_MEMORY;
    }
    catch (std::overflow_error& error)
    {
        log(SGX_QL_LOG_ERROR, "Overflow error. '%s'", error.what());
        sgx_ql_free_root_ca_crl(*pp_root_ca_crl);
        return SGX_QL_ERROR_UNEXPECTED;
    }
    catch (std::exception& error)
    {
        log(SGX_QL_LOG_ERROR,
            "Unknown exception thrown, error: %s",
            error.what());
        return SGX_QL_ERROR_UNEXPECTED;
    }
}