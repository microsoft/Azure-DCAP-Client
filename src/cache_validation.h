// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef CACHE_VALIDATION_H
#define CACHE_VALIDATION_H

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "sgx_ql_lib_common.h"

//
// Returns true if a cached quote config blob has the layout written by
// store_certificate_internal(): an sgx_ql_config_t header with a known
// version, followed by exactly cert_data_size bytes of NUL-terminated
// certificate data.
//
inline bool is_valid_cached_quote_config(const uint8_t* data, size_t size)
{
    if (data == nullptr || size <= sizeof(sgx_ql_config_t))
    {
        return false;
    }

    sgx_ql_config_t config;
    memcpy(&config, data, sizeof(config));

    // Compare the version as a plain integer: loading an out-of-range value
    // through the enum type is undefined behavior.
    uint32_t version = 0;
    static_assert(
        sizeof(version) == sizeof(config.version),
        "unexpected sgx_ql_config_version_t size");
    memcpy(&version, data + offsetof(sgx_ql_config_t, version), sizeof(version));
    if (version != SGX_QL_CONFIG_VERSION_1)
    {
        return false;
    }

    const size_t cert_data_size = size - sizeof(sgx_ql_config_t);
    if (config.cert_data_size == 0 || config.cert_data_size != cert_data_size)
    {
        return false;
    }

    return data[size - 1] == '\0';
}

#endif
