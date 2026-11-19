// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../local_cache.h"

#include <algorithm>
#include <cstring>
#include <mutex>
#include <random>

#include <fcntl.h>
#include <ftw.h>
#include <locale.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <pwd.h>
#include <unistd.h>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>

constexpr uint16_t CACHE_V1 = 1;

// Upper bound on the payload of a single cache entry.
constexpr off_t MAX_CACHE_ENTRY_DATA_SIZE = 64 * 1024 * 1024;

// Modes for new cache directories and entries (further restricted by the
// umask). Neither is ever writable by other users, so other local users
// cannot plant or replace cache entries.
constexpr mode_t CACHE_DIRECTORY_MODE = 0775;
constexpr mode_t CACHE_FILE_MODE = 0644;

constexpr locale_t NULL_LOCALE = reinterpret_cast<locale_t>(0);

static std::string g_cache_dirname = "";
static std::mutex cache_directory_lock;

static long int last_cache_read_expiry = -1;
static long int last_cache_read_time = -1;

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
            // LOCK_NB: a lock held by another process (for example one that
            // planted the file) must not block the caller indefinitely.
            const int lock_op =
                ((flags & (O_WRONLY | O_RDWR)) ? LOCK_EX : LOCK_SH) | LOCK_NB;
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

    // Returns true if the open file is a regular file (not a FIFO, device,
    // directory, ...) and no other hard link refers to it. A link count of
    // 0 is fine: a writer replaced the entry after it was opened, and the
    // open file is still the complete previous entry.
    bool is_single_link_regular_file()
    {
        struct stat buf{};
        if (::fstat(this->fd, &buf) == -1)
        {
            this->fail("Error calling fstat on file");
            return false;
        }
        return S_ISREG(buf.st_mode) && buf.st_nlink <= 1;
    }

    // Creates and opens a new, empty file with a random name next to
    // `name` and returns its path. O_EXCL | O_NOFOLLOW: never opens an
    // existing file and never follows a symlink, whatever else is in the
    // directory.
    std::string create_temporary(const std::string& name, mode_t mode)
    {
        std::random_device random;
        for (int attempt = 0; attempt < 16; ++attempt)
        {
            char suffix[32];
            snprintf(suffix, sizeof(suffix), ".tmp.%08x%08x", random(), random());
            const std::string temp_name = name + suffix;

            do
            {
                this->fd = ::open(
                    temp_name.c_str(),
                    O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC,
                    mode);
            } while (this->fd == -1 && errno == EINTR);

            if (this->fd != -1)
            {
                return temp_name;
            }

            if (errno != EEXIST)
            {
                break;
            }
        }

        this->fail("Error creating temporary cache file");
        return "";
    }

    // Returns the number of bytes read; less than data_size only at end of file.
    size_t read(void* data, size_t data_size)
    {
        size_t total = 0;
        while (total < data_size)
        {
            ssize_t rc;
            do
            {
                rc = ::read(
                    this->fd,
                    static_cast<char*>(data) + total,
                    data_size - total);
            } while (rc == -1 && errno == EINTR);

            if (rc == -1)
            {
                this->fail("Error calling read on file");
                break;
            }

            if (rc == 0)
            {
                break;
            }

            total += static_cast<size_t>(rc);
        }

        return total;
    }

    void write(const void* data, size_t data_size)
    {
        size_t total = 0;
        while (total < data_size)
        {
            ssize_t rc;
            do
            {
                rc = ::write(
                    this->fd,
                    static_cast<const char*>(data) + total,
                    data_size - total);
            } while (rc == -1 && errno == EINTR);

            if (rc <= 0)
            {
                if (rc == 0)
                {
                    errno = EIO;
                }
                this->fail("Error calling write on file");
                break;
            }

            total += static_cast<size_t>(rc);
        }
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
            make_dir(dirname, CACHE_DIRECTORY_MODE);
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

// Refuses a cache directory that any local user can create files in:
// entries planted there could replace or redirect cached data.
static void check_cache_directory(const std::string& dirname)
{
    struct stat buf{};
    if (stat(dirname.c_str(), &buf) != 0)
    {
        throw_errno("Error checking cache directory '" + dirname + "'");
    }

    if ((buf.st_mode & S_IWOTH) != 0)
    {
        throw std::runtime_error(
            "Cache directory '" + dirname +
            "' is writable by all users; refusing to use it.");
    }
}

static void init()
{
    std::lock_guard<std::mutex> lock(cache_directory_lock);
    if (g_cache_dirname == "")
    {
        init_callback();
    }

    // Checked on every use so a directory whose permissions change while
    // the process runs is not trusted.
    check_cache_directory(g_cache_dirname);
}

static std::string sha256(size_t data_size, const void* data)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    const EVP_MD *digestType = EVP_sha256();
    int rc = EVP_Digest(data, data_size, hash, NULL, digestType, NULL);
    if (rc != 1)
    {
        throw std::runtime_error("EVP_Digest failed to generate a hash for the cached file name");
    }

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

std::string get_cached_file_location(const std::string& id){
	return get_file_name(id);
}

std::string get_last_cache_read_expiry_log(){
	std::string result("Last cache read expiry is unset. This could be because there's been no cache reads yet, it has been read without checking for cache expiry or an error during cache read before cache expiry is checked.");
	if(last_cache_read_expiry != -1){
		result = "Last cache read expiry value is " + std::to_string(last_cache_read_expiry) + " and it was read when time(nullptr) value was " + std::to_string(last_cache_read_time);
	}
	return result;
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

    // Write the entry to a new temporary file, then rename it over the entry
    // path. rename() replaces whatever is at that path (a symlink, hard link,
    // FIFO or file planted there) without following or writing through it,
    // and readers only ever see a complete entry.
    const std::string file_name = get_file_name(id);
    file cache_entry;
    cache_entry.throw_on_error();
    const std::string temp_name =
        cache_entry.create_temporary(file_name, CACHE_FILE_MODE);
    try
    {
        cache_entry.write(&header, sizeof(header));
        cache_entry.write(data, data_size);
        cache_entry.close();
        if (rename(temp_name.c_str(), file_name.c_str()) != 0)
        {
            throw_errno("Error replacing cache entry");
        }
    }
    catch (...)
    {
        unlink(temp_name.c_str());
        throw;
    }
}

std::unique_ptr<std::vector<uint8_t>> local_cache_get(
    const std::string& id, bool checkExpiration)
{
    throw_if(id.empty(), "The 'id' parameter must not be empty.");

    init();
	last_cache_read_expiry = -1;
	last_cache_read_time = -1;

    const auto file_name = get_file_name(id);
    file cache_file;
    // O_NONBLOCK: opening a FIFO planted at this path returns immediately
    // instead of blocking until a writer appears.
    // O_NOFOLLOW: a symlink planted at this path is not followed; the open
    // fails and the entry is treated as missing.
    cache_file.open(file_name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW);
    if (cache_file.failed())
    {
        return nullptr;
    }

    cache_file.throw_on_error();

    // Malformed entries are removed so they are refetched instead of re-read.
    auto reject = [&](const char* reason) {
        cache_file.close();
        unlink(file_name.c_str());
        throw std::runtime_error(reason);
    };

    // Only regular files are valid cache entries (not FIFOs, devices or
    // directories), and only with a single link: a hard link planted at
    // this path would expose another file's contents.
    if (!cache_file.is_single_link_regular_file())
    {
        reject("Cache entry is not a regular file with a single link");
    }

    CacheEntryHeaderV1 header{};
    if (cache_file.read(&header, sizeof(header)) != sizeof(header))
    {
        reject("Incomplete read of cache header");
    }

    if (header.version != CACHE_V1)
    {
        reject("Unsupported cache entry version");
    }
	
    if (checkExpiration)
    {
		last_cache_read_expiry = static_cast<long int> (header.expiry);
		last_cache_read_time = static_cast<long int> (time(nullptr));
		if(header.expiry <= time(nullptr)){
			cache_file.close();
			unlink(file_name.c_str());
			// Even if unlink fails, we can just return null. Thus, the return
			// value is intentionally ignored here.
			return nullptr;
		}
    }

    const off_t start_of_data = cache_file.seek(0, SEEK_CUR);
    const off_t end_of_data = cache_file.seek(0, SEEK_END);
    const off_t data_size = end_of_data - start_of_data;
    if (data_size <= 0 || data_size > MAX_CACHE_ENTRY_DATA_SIZE)
    {
        reject("Cache entry has an invalid size");
    }
    cache_file.seek(start_of_data, SEEK_SET);

    auto cache_entry =
        std::make_unique<std::vector<uint8_t>>(static_cast<size_t>(data_size));
    if (cache_file.read(cache_entry->data(), cache_entry->size()) !=
        cache_entry->size())
    {
        reject("Incomplete read of cache data");
    }
    return cache_entry;
}

void local_cache_remove(const std::string& id)
{
    throw_if(id.empty(), "The 'id' parameter must not be empty.");

    init();

    const auto file_name = get_file_name(id);
    if (unlink(file_name.c_str()) != 0 && errno != ENOENT)
    {
        throw_errno("Error removing cache entry");
    }
}
