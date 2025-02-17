// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


#include <gtest/gtest.h>

#undef NDEBUG // ensure that asserts are never compiled out
#include <cassert>
#include <cstdio>
#include <cstring>
#include <thread>
#include <stdexcept>
#if defined(__LINUX__)
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "../local_cache.h"

#if defined(__LINUX__)
typedef bool boolean;
#else
#endif

static time_t now()
{
    return time(nullptr);
}

//
// Add an item to the cache and retrieve it.
//
static boolean AddGetItem()
{
    static const std::vector<uint8_t> data = {8, 6, 7, 5, 3, 0, 9};
    local_cache_add(__FUNCTION__, now() + 60, data.size(), data.data());

    auto retrieved = local_cache_get(__FUNCTION__);
    EXPECT_TRUE(retrieved != nullptr);
    EXPECT_TRUE(*retrieved == data);

    return true;
}

//
// Add an item to the cache, then overwrite it
//
static boolean OverwriteCacheEntry()
{
    static const std::vector<uint8_t> data1 = {1, 1, 1, 1};
    local_cache_add(__FUNCTION__, now() + 60, data1.size(), data1.data());

    static const std::vector<uint8_t> data2 = {2};
    local_cache_add(__FUNCTION__, now() + 60, data2.size(), data2.data());

    auto retrieved = local_cache_get(__FUNCTION__);
    EXPECT_TRUE(*retrieved == data2);

    return true;
}

//
// Add an item to the cache, clear the cache, then ensure the entry is gone
//
static boolean VerifyClearCache()
{
    static const uint8_t data[] = "stuff goes here";
    local_cache_add(__FUNCTION__, now() + 60, sizeof(data), data);

    EXPECT_TRUE(nullptr != local_cache_get(__FUNCTION__));
    local_cache_clear();
    EXPECT_TRUE(nullptr == local_cache_get(__FUNCTION__));

    return true;
}

//
// Add an item to the cache with a short expiry, then ensure it actually
// expires.
//
static boolean VerifyExpiryWorks()
{
    int expiry_seconds = 2;

    // add an entry with expiry shortly in the future
    static const uint8_t data[] = "stuff goes here";
    local_cache_add(__FUNCTION__, now() + expiry_seconds, sizeof(data), data);

    // ensure the data is there
    EXPECT_TRUE(nullptr != local_cache_get(__FUNCTION__));

    // wait for expiry, after which the data should be gone

#if defined(__LINUX__)
    sleep(expiry_seconds);
#else
    Sleep(expiry_seconds * 1000);
#endif

    EXPECT_TRUE(nullptr == local_cache_get(__FUNCTION__));

    return true;
}

template <typename ExceptionT>
static void AssertException(void (*function)())
{
    try
    {
        function();
    }
    catch (ExceptionT&)
    {
        return;
    }

    ASSERT_TRUE(!"Expected exception was not thrown");
}

//
// Verify invalid parameter handling
//
static boolean InvalidParams()
{
    static const uint8_t data[] = "test data";

    AssertException<std::runtime_error>(
        [] { local_cache_add("", now(), sizeof(data), data); });

    AssertException<std::runtime_error>(
        [] { local_cache_add(__FUNCTION__, now(), 0, data); });

    AssertException<std::runtime_error>(
        [] { local_cache_add(__FUNCTION__, now(), sizeof(data), nullptr); });

    AssertException<std::runtime_error>([] { local_cache_get(""); });

    return true;
}

//
// Spawns multiple threads, intentionally creating a lot of contention for
// a single cache entry.
//
static boolean ThreadSafetyTest()
{
    // Pre-fill a data vector that's of sufficient size that we
    // are likely to get conflicts between threads.
    std::vector<uint8_t> data(64 * 1024);
    for (size_t i = 0; i < data.size(); ++i)
    {
        data[i] = i & 0xff;
    }

    constexpr unsigned THREAD_LOOP_COUNT = 128;
    const std::string ID = "data identifier";

    auto cache_writer = [&](void) {
        for (unsigned i = 0; i < THREAD_LOOP_COUNT; ++i)
        {
            local_cache_add(ID, now() + 60, data.size(), data.data());
        }
    };

    auto cache_reader = [&](void) {
        for (unsigned i = 0; i < THREAD_LOOP_COUNT; ++i)
        {
            auto retrieved = local_cache_get(ID);
            EXPECT_TRUE(retrieved != nullptr);
            EXPECT_TRUE(*retrieved == data);
        }
    };

    // prime the cache entry first (in case a read thread runs first)
    local_cache_add(ID, now() + 60, data.size(), data.data());

#if defined(__LINUX__)
    std::array<std::thread, 8> threads;
    for (size_t i = 0; i < threads.size(); ++i)
#else
    std::thread threads[8];
    for (size_t i = 0; i < _countof(threads); ++i)
#endif
    {
        if (i & 1)
        {
            threads[i] = std::thread(cache_writer);
        }
        else
        {
            threads[i] = std::thread(cache_reader);
        }
    }

    for (auto& t : threads)
    {
        t.join();
    }

    return true;
}

TEST(testLocalCache, AddGetItem)
{
    local_cache_clear();

    ASSERT_TRUE(AddGetItem());
}

TEST(testLocalCache, OverwriteCacheEntry)
{
    ASSERT_TRUE(OverwriteCacheEntry());
}

TEST(testLocalCache, VerifyClearCache)
{
    ASSERT_TRUE(VerifyClearCache());
}

TEST(testLocalCache, VerifyExpiryWorks)
{
    ASSERT_TRUE(VerifyExpiryWorks());
}

TEST(testLocalCache, InvalidParams)
{
    ASSERT_TRUE(InvalidParams());
}

TEST(testLocalCache, ThreadSafetyTest)
{
    ASSERT_TRUE(ThreadSafetyTest());
}

