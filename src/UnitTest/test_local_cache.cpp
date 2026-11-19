// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.


#include <gtest/gtest.h>

#undef NDEBUG // ensure that asserts are never compiled out
#include <array>
#include <cassert>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <future>
#include <thread>
#include <stdexcept>
#if defined(__LINUX__)
#include <dirent.h>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#else
#include <windows.h>
#endif

#include "../local_cache.h"
#include "../cache_validation.h"

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

//
// Helpers for writing raw (possibly malformed) cache entries. The header
// layout mirrors CacheEntryHeaderV1 in the platform local_cache.cpp.
//
#if defined(__LINUX__)
struct __attribute__((__packed__)) TestCacheHeader
#else
struct TestCacheHeader
#endif
{
    uint16_t version;
    time_t expiry;
};

static std::vector<uint8_t> MakeCacheEntry(
    uint16_t version,
    time_t expiry,
    const std::vector<uint8_t>& payload)
{
    TestCacheHeader header{};
    header.version = version;
    header.expiry = expiry;
    const auto* header_bytes = reinterpret_cast<const uint8_t*>(&header);
    std::vector<uint8_t> bytes(header_bytes, header_bytes + sizeof(header));
    bytes.insert(bytes.end(), payload.begin(), payload.end());
    return bytes;
}

static void WriteRawCacheEntry(
    const std::string& id,
    const std::vector<uint8_t>& bytes)
{
    // local_cache_add initializes the cache directory and creates the file.
    static const uint8_t seed = 1;
    local_cache_add(id, now() + 60, sizeof(seed), &seed);

    std::ofstream out(
        get_cached_file_location(id), std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

static bool CacheEntryExists(const std::string& id)
{
    std::ifstream in(get_cached_file_location(id), std::ios::binary);
    return in.good();
}

static void ExpectRejectedAndRemoved(const std::string& id)
{
    EXPECT_THROW(local_cache_get(id), std::runtime_error);
    EXPECT_FALSE(CacheEntryExists(id));
}

TEST(testLocalCache, AcceptsWellFormedRawEntry)
{
    const std::string id = "AcceptsWellFormedRawEntry";
    const std::vector<uint8_t> payload = {9, 8, 7};
    WriteRawCacheEntry(id, MakeCacheEntry(1, now() + 60, payload));

    auto retrieved = local_cache_get(id);
    ASSERT_TRUE(retrieved != nullptr);
    EXPECT_TRUE(*retrieved == payload);
}

TEST(testLocalCache, RejectsTruncatedHeader)
{
    const std::string id = "RejectsTruncatedHeader";
    WriteRawCacheEntry(id, {1, 0, 0});
    ExpectRejectedAndRemoved(id);
}

TEST(testLocalCache, RejectsUnknownVersion)
{
    const std::string id = "RejectsUnknownVersion";
    WriteRawCacheEntry(id, MakeCacheEntry(2, now() + 60, {1, 2, 3}));
    ExpectRejectedAndRemoved(id);
}

TEST(testLocalCache, RejectsEmptyPayload)
{
    const std::string id = "RejectsEmptyPayload";
    WriteRawCacheEntry(id, MakeCacheEntry(1, now() + 60, {}));
    ExpectRejectedAndRemoved(id);
}

TEST(testLocalCache, RejectsOversizedEntry)
{
    const std::string id = "RejectsOversizedEntry";
    WriteRawCacheEntry(id, MakeCacheEntry(1, now() + 60, {1}));

    // Extend the file past the 64 MiB payload limit.
    {
        std::fstream out(
            get_cached_file_location(id),
            std::ios::binary | std::ios::in | std::ios::out);
        out.seekp(64 * 1024 * 1024 + sizeof(TestCacheHeader) + 1);
        out.put(0);
    }

    ExpectRejectedAndRemoved(id);
}

TEST(testLocalCache, RemoveEntry)
{
    const std::string id = "RemoveEntry";
    static const uint8_t data[] = "remove me";
    local_cache_add(id, now() + 60, sizeof(data), data);
    ASSERT_TRUE(local_cache_get(id) != nullptr);

    local_cache_remove(id);
    EXPECT_TRUE(local_cache_get(id) == nullptr);

    // Removing a missing entry is not an error.
    EXPECT_NO_THROW(local_cache_remove(id));
    EXPECT_THROW(local_cache_remove(""), std::runtime_error);
}

//
// is_valid_cached_quote_config: shared validation used by check_cache().
//
static std::vector<uint8_t> MakeQuoteConfigBlob(
    const std::string& cert_data,
    uint32_t declared_size,
    uint32_t version = SGX_QL_CONFIG_VERSION_1)
{
    sgx_ql_config_t config{};
    config.version = SGX_QL_CONFIG_VERSION_1;
    config.cert_data_size = declared_size;
    config.p_cert_data = nullptr;
    const auto* config_bytes = reinterpret_cast<const uint8_t*>(&config);
    std::vector<uint8_t> blob(config_bytes, config_bytes + sizeof(config));
    // Write the version as raw bytes so tests can use values outside the enum.
    memcpy(blob.data() + offsetof(sgx_ql_config_t, version), &version, sizeof(version));
    blob.insert(blob.end(), cert_data.begin(), cert_data.end());
    return blob;
}

TEST(testQuoteConfigValidation, AcceptsWellFormedBlob)
{
    const std::string cert("CERT\0", 5);
    const auto blob = MakeQuoteConfigBlob(cert, 5);
    EXPECT_TRUE(is_valid_cached_quote_config(blob.data(), blob.size()));
}

TEST(testQuoteConfigValidation, RejectsNullOrTooSmall)
{
    const std::string cert("CERT\0", 5);
    const auto blob = MakeQuoteConfigBlob(cert, 5);

    EXPECT_FALSE(is_valid_cached_quote_config(nullptr, blob.size()));
    EXPECT_FALSE(is_valid_cached_quote_config(blob.data(), 0));
    EXPECT_FALSE(is_valid_cached_quote_config(blob.data(), 10));
    EXPECT_FALSE(
        is_valid_cached_quote_config(blob.data(), sizeof(sgx_ql_config_t)));
}

TEST(testQuoteConfigValidation, RejectsCertDataSizeMismatch)
{
    const std::string cert("CERT\0", 5);

    const auto too_large = MakeQuoteConfigBlob(cert, 0x00ffffff);
    EXPECT_FALSE(is_valid_cached_quote_config(too_large.data(), too_large.size()));

    const auto too_small = MakeQuoteConfigBlob(cert, 4);
    EXPECT_FALSE(is_valid_cached_quote_config(too_small.data(), too_small.size()));

    const auto zero = MakeQuoteConfigBlob(cert, 0);
    EXPECT_FALSE(is_valid_cached_quote_config(zero.data(), zero.size()));
}

TEST(testQuoteConfigValidation, RejectsMissingNulTerminator)
{
    const std::string cert("CERTX", 5);
    const auto blob = MakeQuoteConfigBlob(cert, 5);
    EXPECT_FALSE(is_valid_cached_quote_config(blob.data(), blob.size()));
}

TEST(testQuoteConfigValidation, RejectsUnknownVersion)
{
    const std::string cert("CERT\0", 5);
    const auto blob = MakeQuoteConfigBlob(cert, 5, 2);
    EXPECT_FALSE(is_valid_cached_quote_config(blob.data(), blob.size()));
}

#if defined(__LINUX__)
//
// A FIFO planted at a cache entry path must not block the reader (QGS) or
// the writer (CertRefresher) waiting for the other end of the pipe.
//
static const auto FIFO_TEST_TIMEOUT = std::chrono::seconds(5);

static std::string ReplaceWithFifo(const std::string& id)
{
    // local_cache_add initializes the cache directory.
    static const uint8_t seed = 1;
    local_cache_add(id, now() + 60, sizeof(seed), &seed);

    const std::string path = get_cached_file_location(id);
    EXPECT_EQ(0, unlink(path.c_str()));
    EXPECT_EQ(0, mkfifo(path.c_str(), 0600));
    return path;
}

static bool PathExists(const std::string& path)
{
    // lstat does not open the path, so it cannot block on a FIFO.
    struct stat buf{};
    return lstat(path.c_str(), &buf) == 0;
}

TEST(testLocalCache, GetRejectsFifoWithoutBlocking)
{
    const std::string id = "GetRejectsFifoWithoutBlocking";
    const std::string path = ReplaceWithFifo(id);

    auto rejected = std::async(std::launch::async, [&id]() {
        try
        {
            local_cache_get(id);
            return false;
        }
        catch (const std::runtime_error&)
        {
            return true;
        }
    });

    if (rejected.wait_for(FIFO_TEST_TIMEOUT) != std::future_status::ready)
    {
        // Open and close the write end so the blocked reader sees end of file
        // and the test can finish.
        const int fd = open(path.c_str(), O_WRONLY | O_NONBLOCK);
        if (fd != -1)
        {
            close(fd);
        }
        rejected.wait();
        unlink(path.c_str());
        FAIL() << "local_cache_get blocked on a FIFO cache entry";
    }

    EXPECT_TRUE(rejected.get());
    EXPECT_FALSE(PathExists(path));
}

//
// File squatting: another local user plants something at a cache entry path
// before or between writes. The cache must not follow, write through, block
// on, or return what was planted.
//
static const uint8_t squat_data[] = "fresh entry";

static std::string SeedEntry(const std::string& id)
{
    // local_cache_add initializes the cache directory.
    static const uint8_t seed = 1;
    local_cache_add(id, now() + 60, sizeof(seed), &seed);
    return get_cached_file_location(id);
}

static std::string CacheDirectory(const std::string& id)
{
    const std::string path = get_cached_file_location(id);
    return path.substr(0, path.rfind('/'));
}

// A file outside the cache directory, on the same file system.
static std::string VictimPath(const std::string& id)
{
    return CacheDirectory(id) + "/../" + id + ".victim";
}

static void WriteFileContents(const std::string& path, const std::string& contents)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << contents;
}

static std::string ReadFileContents(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(
        (std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

static bool IsRegularFile(const std::string& path)
{
    struct stat buf{};
    return lstat(path.c_str(), &buf) == 0 && S_ISREG(buf.st_mode);
}

static bool HasSquatData(const std::string& id)
{
    auto entry = local_cache_get(id);
    return entry != nullptr && entry->size() == sizeof(squat_data) &&
           memcmp(entry->data(), squat_data, sizeof(squat_data)) == 0;
}

static std::string ValidEntryBytes()
{
    const auto bytes = MakeCacheEntry(1, now() + 60, {1, 2, 3});
    return std::string(bytes.begin(), bytes.end());
}

TEST(testLocalCache, AddReplacesFifoWithoutBlocking)
{
    const std::string id = "AddReplacesFifoWithoutBlocking";
    const std::string path = ReplaceWithFifo(id);

    auto added = std::async(std::launch::async, [&id]() {
        local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);
    });

    if (added.wait_for(FIFO_TEST_TIMEOUT) != std::future_status::ready)
    {
        // Open the read end so the blocked writer returns; keep it open until
        // the writer finishes so the writer cannot get SIGPIPE.
        const int fd = open(path.c_str(), O_RDONLY | O_NONBLOCK);
        added.wait();
        if (fd != -1)
        {
            close(fd);
        }
        unlink(path.c_str());
        FAIL() << "local_cache_add blocked on a FIFO cache entry";
    }

    EXPECT_NO_THROW(added.get());
    EXPECT_TRUE(IsRegularFile(path));
    EXPECT_TRUE(HasSquatData(id));
}

TEST(testLocalCache, AddReplacesSymlinkWithoutFollowingIt)
{
    const std::string id = "AddReplacesSymlinkWithoutFollowingIt";
    const std::string path = SeedEntry(id);
    const std::string victim = VictimPath(id);
    WriteFileContents(victim, "do not overwrite");
    ASSERT_EQ(0, unlink(path.c_str()));
    ASSERT_EQ(0, symlink(victim.c_str(), path.c_str()));

    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);

    EXPECT_EQ("do not overwrite", ReadFileContents(victim));
    EXPECT_TRUE(IsRegularFile(path));
    EXPECT_TRUE(HasSquatData(id));
    unlink(victim.c_str());
}

TEST(testLocalCache, GetDoesNotFollowSymlink)
{
    const std::string id = "GetDoesNotFollowSymlink";
    const std::string path = SeedEntry(id);
    const std::string victim = VictimPath(id);
    WriteFileContents(victim, ValidEntryBytes());
    ASSERT_EQ(0, unlink(path.c_str()));
    ASSERT_EQ(0, symlink(victim.c_str(), path.c_str()));

    // Following the link would return {1, 2, 3}; it is treated as a miss.
    EXPECT_TRUE(local_cache_get(id) == nullptr);
    EXPECT_TRUE(PathExists(victim));

    unlink(path.c_str());
    unlink(victim.c_str());
}

TEST(testLocalCache, AddDoesNotWriteThroughHardLink)
{
    const std::string id = "AddDoesNotWriteThroughHardLink";
    const std::string path = SeedEntry(id);
    const std::string victim = VictimPath(id);
    WriteFileContents(victim, "do not overwrite");
    ASSERT_EQ(0, unlink(path.c_str()));
    ASSERT_EQ(0, link(victim.c_str(), path.c_str()));

    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);

    EXPECT_EQ("do not overwrite", ReadFileContents(victim));
    EXPECT_TRUE(HasSquatData(id));
    unlink(victim.c_str());
}

TEST(testLocalCache, GetRejectsHardLinkedEntry)
{
    const std::string id = "GetRejectsHardLinkedEntry";
    const std::string path = SeedEntry(id);
    const std::string victim = VictimPath(id);
    WriteFileContents(victim, ValidEntryBytes());
    ASSERT_EQ(0, unlink(path.c_str()));
    ASSERT_EQ(0, link(victim.c_str(), path.c_str()));

    EXPECT_THROW(local_cache_get(id), std::runtime_error);
    EXPECT_FALSE(PathExists(path));
    EXPECT_TRUE(PathExists(victim));
    unlink(victim.c_str());
}

TEST(testLocalCache, LockedEntryDoesNotBlock)
{
    const std::string id = "LockedEntryDoesNotBlock";
    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);
    const std::string path = get_cached_file_location(id);

    // Another open file description holding an exclusive lock, as a process
    // that planted or opened the entry could.
    const int fd = open(path.c_str(), O_RDONLY);
    ASSERT_NE(-1, fd);
    ASSERT_EQ(0, flock(fd, LOCK_EX));

    auto missed = std::async(std::launch::async, [&id]() {
        return local_cache_get(id) == nullptr;
    });

    if (missed.wait_for(FIFO_TEST_TIMEOUT) != std::future_status::ready)
    {
        flock(fd, LOCK_UN);
        missed.wait();
        close(fd);
        FAIL() << "local_cache_get blocked on a locked cache entry";
    }

    // A locked entry is treated as a miss.
    EXPECT_TRUE(missed.get());

    // The writer does not take a lock on the entry, so it is not blocked.
    EXPECT_NO_THROW(local_cache_add(id, now() + 60, sizeof(squat_data), squat_data));
    close(fd);
    EXPECT_TRUE(HasSquatData(id));
}

TEST(testLocalCache, EntriesAreNotWritableByOthersWithZeroUmask)
{
    const std::string id = "EntriesAreNotWritableByOthersWithZeroUmask";

    const mode_t old_umask = umask(0);
    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);
    umask(old_umask);

    struct stat buf{};
    ASSERT_EQ(0, lstat(get_cached_file_location(id).c_str(), &buf));
    EXPECT_EQ(0u, buf.st_mode & (S_IWGRP | S_IWOTH));
}

TEST(testLocalCache, AddLeavesNoTemporaryFiles)
{
    const std::string id = "AddLeavesNoTemporaryFiles";
    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);
    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);

    const std::string path = get_cached_file_location(id);
    const std::string prefix = path.substr(path.rfind('/') + 1) + ".tmp.";
    size_t temporary_files = 0;
    DIR* dir = opendir(CacheDirectory(id).c_str());
    ASSERT_NE(nullptr, dir);
    while (dirent* entry = readdir(dir))
    {
        if (std::string(entry->d_name).compare(0, prefix.size(), prefix) == 0)
        {
            ++temporary_files;
        }
    }
    closedir(dir);
    EXPECT_EQ(0u, temporary_files);
}

TEST(testLocalCache, RefusesWorldWritableCacheDirectory)
{
    const std::string id = "RefusesWorldWritableCacheDirectory";
    local_cache_add(id, now() + 60, sizeof(squat_data), squat_data);

    const std::string dir = CacheDirectory(id);
    struct stat buf{};
    ASSERT_EQ(0, stat(dir.c_str(), &buf));
    const mode_t original_mode = buf.st_mode & 07777;
    ASSERT_EQ(0, chmod(dir.c_str(), original_mode | S_IWOTH));

    EXPECT_THROW(local_cache_get(id), std::runtime_error);
    EXPECT_THROW(
        local_cache_add(id, now() + 60, sizeof(squat_data), squat_data),
        std::runtime_error);

    ASSERT_EQ(0, chmod(dir.c_str(), original_mode));
    EXPECT_TRUE(HasSquatData(id));
}
#endif

