// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../local_cache.h"

#include <algorithm>
#include <cstring>
#include <mutex>

#include <fcntl.h>
#include <ftw.h>
#include <locale.h>
#include <openssl/sha.h>
#include <pwd.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

constexpr uint16_t CACHE_V1 = 1;

constexpr locale_t NULL_LOCALE = reinterpret_cast<locale_t>(0);

static std::string g_cache_dirname = "";
static std::mutex cache_directory_lock;

static constexpr size_t CACHE_LOCATIONS = 5;
static const char *cache_locations[CACHE_LOCATIONS];

//
// Various exception helpers
//
static void throw_if(bool should_throw, const std::string& error)
{
    if (should_throw)
    {
        throw std::runtime_error(error);
    }
}

static void throw_errno(const std::string& description, int err)
{
    locale_t loc = newlocale(LC_ALL_MASK, "POSIX", NULL_LOCALE);
    if (loc == NULL_LOCALE)
    {
        throw std::runtime_error("Unable to allocate locale: " + std::to_string(errno));
    }

    std::string errno_string = strerror_l(err, loc);
    freelocale(loc);

    throw std::runtime_error(description + ": " + errno_string);
}

static void throw_errno(const std::string& description)
{
    throw_errno(description, errno);
}

//
// Represents an entry in our filesystem cache.
//
struct __attribute__ ((__packed__)) CacheEntryHeaderV1
{
    uint16_t version;   // The version of the cache header
    time_t expiry;      // expiration time of this cache item
};

//
// Helper class, similar to std::fstream, which also includes file locking.
//
class file
{
#define RETRY_ON_EINTR(op, desc) \
    do \
    { \
        ssize_t rc; \
        do { rc = (op); } while (rc == -1 && errno == EINTR); \
        if (rc == -1) { this->fail("Error calling " desc " on file"); } \
    } while(false)

public:
    ~file()
    {
        this->close();
    }

    bool failed() const { return this->has_failed; }

    std::string get_error_description() const { return this->error_description; }

    void throw_on_error() { this->should_throw_on_error = true; }

    void open(const std::string& name, int flags, mode_t mode = 0)
    {
        RETRY_ON_EINTR(this->fd = ::open(name.c_str(), flags, mode), "open");

        if (this->fd != -1)
        {
            const int lock_op = (flags & (O_WRONLY | O_RDWR)) ? LOCK_EX : LOCK_SH;
            RETRY_ON_EINTR(::flock(this->fd, lock_op), "flock");
        }
    }

    void close()
    {
        if (this->fd != -1)
        {
            int rc = ::close(this->fd);
            this->fd = -1;

            if (-1 == rc)
            {
                this->fail("Error closing file");
            }
        }
    }

    void truncate()
    {
        RETRY_ON_EINTR(::ftruncate(this->fd, 0), "ftruncate");
    }

    void read(void* data, size_t data_size)
    {
        RETRY_ON_EINTR(::read(this->fd, data, data_size), "read");
    }

    void write(const void* data, size_t data_size)
    {
        RETRY_ON_EINTR(::write(this->fd, data, data_size), "write");
    }

    off_t seek(off_t offset, int whence)
    {
        off_t rc = ::lseek(this->fd, offset, whence);

        if (rc == -1)
        {
            this->fail("Error seeking file");
        }

        return rc;
    }

private:
    int fd = -1;
    bool has_failed = false;
    bool should_throw_on_error = false;
    std::string error_description;

    void fail(const std::string& description)
    {
        this->has_failed = true;
        this->error_description = description;

        if (this->should_throw_on_error)
        {
            throw_errno(description);
        }
    }

#undef RETRY_ON_EINTR
};

static void make_dir(const std::string& dirname, mode_t mode)
{
    struct stat buf{};
    int rc = stat(dirname.c_str(), &buf);
    if (rc == 0)
    {
        if (S_ISDIR(buf.st_mode))
        {
            return;
        }

        throw std::runtime_error(dirname + " already exists, and is not a directory.");
    }

    rc = mkdir(dirname.c_str(), mode);
    if (rc != 0)
    {
        throw_errno("Error creating directory '" + dirname + "'");
    }
}

static void load_cache_locations()
{
    cache_locations[0] = ::getenv("AZDCAP_CACHE");
    cache_locations[1] = ::getenv("XDG_CACHE_HOME");
    cache_locations[2] = ::getenv("HOME");
    cache_locations[3] = ::getenv("TMPDIR");

    // The fallback location isn't an environment variable
    cache_locations[4] = "/tmp/";
}

static void init_callback()
{
    load_cache_locations();
    const std::string application_name("/.az-dcap-client/");
    std::string dirname;
    std::string all_locations;

    // Try the cache locations in order
    for (auto &cache_location : cache_locations)
    {
        if (cache_location != 0 && strcmp(cache_location, "") != 0)
        {
            dirname = cache_location + application_name;
            make_dir(dirname, 0777);
            g_cache_dirname = dirname;
            return;
        }
    }
    
    // Collect all of the environment variables for the error message
    std::string environment_variable_list;
    for (size_t i = 0; i < CACHE_LOCATIONS - 1; ++i)
    {
        environment_variable_list += cache_locations[i];
        if (i != CACHE_LOCATIONS - 2)
        {
            environment_variable_list += ",";
        }
    }

    throw std::runtime_error("No cache location was found. Please define one of the following environment variables to enable caching: " + environment_variable_list);
}

static void init()
{
    std::lock_guard<std::mutex> lock(cache_directory_lock);
    if (g_cache_dirname == "")
    {
        init_callback();
    }
}

static std::string sha256(size_t data_size, const void* data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_size);
    SHA256_Final(hash, &sha256);

    std::string retval;
    retval.reserve(2 * sizeof(hash) + 1);
    for (size_t i = 0; i < sizeof(hash); i++)
    {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", hash[i]);
        retval += buf;
    }

    return retval;
}

static std::string sha256(const std::string& input)
{
    return sha256(input.length(), input.data());
}

static std::string get_file_name(const std::string& id)
{
    std::lock_guard<std::mutex> lock(cache_directory_lock);
    return g_cache_dirname + "/" + sha256(id);
}

static int delete_path(
    const char* fpath,
    const struct stat* sb,
    int typeflag,
    struct FTW* ftwbuf)
{
    if (ftwbuf->level == 0)
    {
        // do not delete the root directory of the cache
        return 0;
    }

    switch (typeflag )
    {
        case FTW_SL:
        case FTW_SLN:
        case FTW_F:
            return unlink(fpath);

        case FTW_DP:
            return rmdir(fpath);

        case FTW_D:
            errno = ENOTSUP;
            return -1;

        case FTW_DNR:
        case FTW_NS:
            errno = EACCES;
            return -1;

        default:
            errno = EINVAL;
            return -1;
    }
}

void local_cache_clear()
{
    init();

    std::lock_guard<std::mutex> lock(cache_directory_lock);
    constexpr int MAX_FDS = 4;
    int rc = nftw(g_cache_dirname.c_str(), delete_path, MAX_FDS, FTW_DEPTH);
    if (rc != 0)
    {
        throw_errno("Error clearing cache");
    }
}

extern "C" void local_cache_add(
    const std::string& id,
    time_t expiry,
    size_t data_size,
    const void* data)
{
    throw_if(id.empty(), "The 'id' parameter must not be empty.");
    throw_if(data_size == 0, "Data cannot be empty.");
    throw_if(data == nullptr, "Data pointer must not be NULL.");

    init();

    CacheEntryHeaderV1 header{};
    header.version = CACHE_V1;
    header.expiry = expiry;

    file cache_entry;
    cache_entry.throw_on_error();
    cache_entry.open(get_file_name(id), O_CREAT | O_WRONLY, 0666);
    cache_entry.truncate();
    cache_entry.write(&header, sizeof(header));
    cache_entry.write(data, data_size);
}

std::unique_ptr<std::vector<uint8_t>> local_cache_get(
    const std::string& id, bool checkExpiration)
{
    throw_if(id.empty(), "The 'id' parameter must not be empty.");

    init();

    const auto file_name = get_file_name(id);
    file cache_file;
    cache_file.open(file_name, O_RDONLY);
    if (cache_file.failed())
    {
        return nullptr;
    }

    cache_file.throw_on_error();

    CacheEntryHeaderV1 header{};
    cache_file.read(reinterpret_cast<char*>(&header), sizeof(header));

    if (checkExpiration && header.expiry <= time(nullptr))
    {
        cache_file.close();
        unlink(file_name.c_str());
        // Even if unlink fails, we can just return null. Thus, the return
        // value is intentionally ignored here.
        return nullptr;
    }

    const int start_of_data = cache_file.seek(0, SEEK_CUR);
    const int end_of_data = cache_file.seek(0, SEEK_END);
    const int data_size = end_of_data - start_of_data;
    cache_file.seek(start_of_data, SEEK_SET);

    auto cache_entry = std::make_unique<std::vector<uint8_t>>(data_size);
    cache_file.read(reinterpret_cast<char*>(cache_entry->data()), data_size);
    return cache_entry;
}
