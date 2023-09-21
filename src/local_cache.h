// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once
#ifndef LOCAL_CACHE_H
#define LOCAL_CACHE_H

#include <string>
#include <vector>
#include <memory>
#include <time.h>

//
// Wipe all entries from the local cache.
// Throws std::exception (or subtype) on error.
//
void local_cache_clear();

//
// Returns the name and location of the cache'd file for the corresponding id.
//
std::string get_cached_file_location(const std::string& id);

//
// Add some data, with the given identifier, to the local system cache. The
// cache entry will be expired at the date time indicated by 'expiry'. Upon
// expiration, the cached item will no longer be returned.
// Throws std::exception (or subtype) on error.
//
extern "C" void local_cache_add(
    const std::string& id,
    time_t expiry,
    size_t data_size,
    const void* data);

//
// Lookup a cache entry. If found, the data is returned. If not found, nullptr
// is returned.
// Throws std::exception (or subtype) on error.
//
std::unique_ptr<std::vector<uint8_t>> local_cache_get(
    const std::string& id, bool checkExpiration = true);
	

//
// Return the expiry time of the last read cache file and the time it was compared with
//
std::string get_last_cache_read_expiry_log();


#endif
