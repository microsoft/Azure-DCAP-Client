// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "local_cache.h"

//
// The Windows implementation of the local cache is not yet complete.
// All methods noop, so we'll never cache any data locally.
//

void local_cache_clear()
{
    // noop
}

void local_cache_add(
    const std::string& id,
    time_t expiry,
    size_t data_size,
    const void* data)
{
    (void)id;
    (void)expiry;
    (void)data_size;
    (void)data;
}

std::unique_ptr<std::vector<uint8_t>> local_cache_get(
    const std::string& id)
{
    (void)id;
    return nullptr;
}
