// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "local_cache.h"

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

static std::string g_cache_dirname;

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

static std::string get_user_name()
{
    // sysconf could return -1, in which case we have to guess at the max size
    size_t buf_size = std::max(sysconf(_SC_GETPW_R_SIZE_MAX), 128L);

    int rc = 0;
    do
    {
        std::vector<char> buf(buf_size);
        passwd pwd{};
        passwd* result = nullptr;
        rc = getpwuid_r(geteuid(), &pwd, buf.data(), buf.size(), &result);

        if (rc == 0)
        {
            return result->pw_name;
        }
        else if (rc == ERANGE)
        {
            buf_size *= 2;
        }
    } while (rc == ERANGE || rc == EINTR);

    throw_errno("Error getting user name", rc);
    return "";
}

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

static void init_callback()
{
    const char * env_home = ::getenv("HOME");
    const char * env_azdcapcache = ::getenv("AZDCAPCACHE");
    const std::string application_name("/.az-dcap-client/");
    
    std::string dirname = "/var/tmp/";

    if (env_azdcapcache != 0 && (strcmp(env_azdcapcache,"") != 0))
    {
        dirname = env_azdcapcache;
    }
    else if (env_home != 0 && (strcmp(env_home,"") != 0))
    {
        dirname = std::string(env_home);
    }
    else
    {
        dirname += get_user_name();

        make_dir(dirname, 0777);
    }

    dirname += application_name;

    make_dir(dirname, 0700);

    g_cache_dirname = dirname;
}

static void init()
{
    static std::once_flag init_flag;
    std::call_once(init_flag, init_callback);
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

    constexpr int MAX_FDS = 4;
    int rc = nftw(g_cache_dirname.c_str(), delete_path, MAX_FDS, FTW_DEPTH);
    if (rc != 0)
    {
        throw_errno("Error clearing cache");
    }
}

void local_cache_add(
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
    cache_entry.open(get_file_name(id), O_CREAT | O_WRONLY, 0600);
    cache_entry.truncate();
    cache_entry.write(&header, sizeof(header));
    cache_entry.write(data, data_size);
}

std::unique_ptr<std::vector<uint8_t>> local_cache_get(
    const std::string& id)
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

    if (header.expiry <= time(nullptr))
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
