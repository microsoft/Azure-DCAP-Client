// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <algorithm>
#include <cstring>
#include <mutex>
#include <windows.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include <sstream>
#include <time.h>
#include <iomanip> 
#include <iostream>
#include <cstdio>
#include <filesystem>
#include <wil\resource.h>

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

#define MAX_RETRY					10000
#define SLEEP_RETRY_MS				15

constexpr uint16_t CACHE_V1 = 1;

static std::wstring g_cache_dirname;

static void throw_if(bool should_throw, const std::string& error)
{
    if (should_throw)
    {
        throw std::runtime_error(error);
    }
}

struct CacheEntryHeaderV1 {
    uint16_t version;   // The version of the cache header
    time_t expiry;      // expiration time of this cache item
};

static void make_dir(const std::wstring& dirname)
{
    CreateDirectory(dirname.c_str(), NULL);
    throw_if(GetLastError() == ERROR_PATH_NOT_FOUND && GetLastError() != ERROR_ALREADY_EXISTS, "Path not found");
}

static void init_callback()
{
	const DWORD buffSize = MAX_PATH;
	
	auto env_home = std::make_unique<wchar_t[]>(buffSize);
	memset(env_home.get(), 0, buffSize);
	GetEnvironmentVariable(L"LOCALAPPDATA", env_home.get(), buffSize);
	std::wstring wenv_home(env_home.get());

	auto env_azdcap_cache = std::make_unique<wchar_t[]>(buffSize);
	memset(env_azdcap_cache.get(), 0, buffSize);
	GetEnvironmentVariable(L"AZDCAP_CACHE", env_azdcap_cache.get(), buffSize);
	std::wstring wenv_azdcap_cache(env_azdcap_cache.get());

    const std::wstring application_name(L"\\.az-dcap-client");
    std::wstring dirname;

    if (wenv_azdcap_cache != L"" && wenv_azdcap_cache[0] != 0)
    {
        dirname = wenv_azdcap_cache;
    } 
    else if (wenv_home != L"" && wenv_home[0] != 0)
    {
        dirname = wenv_home.append(L"..\\..\\LocalLow");
    } 
    else
    {
        // Throwing exception if the expected HOME
        // environment variable is not defined.
        throw std::runtime_error("LOCALAPPDATA and AZDCAPCACHE environment variables not defined");
    }

    dirname += application_name;
    make_dir(dirname);
    g_cache_dirname = dirname;
}

static void init()
{
    static std::once_flag init_flag;
    std::call_once(init_flag, init_callback);
}

static std::wstring sha256(size_t data_size, const void* data)
{
    wil::unique_bcrypt_algorithm hAlg;
    wil::unique_bcrypt_hash hHash;
    NTSTATUS status = STATUS_UNSUCCESSFUL;
    std::string errorString;
    DWORD cbData = 0;
    DWORD cbHash = 0;
	std::vector<BYTE> pbHash;
	PBYTE pHashItr = nullptr;
    std::string retval;

    //open an algorithm handle
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
        hAlg.addressof(),
        BCRYPT_SHA256_ALGORITHM,
        nullptr,
        0)))
    {
        errorString = "Error 0x" + std::to_string(status) + "returned by BCryptOpenAlgorithmProvider\n";
        goto Cleanup;
    }


    //calculate the length of the hash
    if (!NT_SUCCESS(status = BCryptGetProperty(
        hAlg.get(),
        BCRYPT_HASH_LENGTH,
        (PBYTE)&cbHash,
        sizeof(DWORD),
        &cbData,
        0)))
    {
        errorString = "Error 0x" + std::to_string(status) + "returned by BCryptGetProperty\n";
        goto Cleanup;
    }

    //allocate the hash buffer on the heap
	pbHash = std::vector<BYTE>(cbHash);

    //create a hash
    if (!NT_SUCCESS(status = BCryptCreateHash(
        hAlg.get(),
        hHash.addressof(),
        nullptr,
        0,
        nullptr,
        0,
        0)))
    {
        errorString = "Error 0x" + std::to_string(status) + "returned by BCryptCreateHash\n";
        goto Cleanup;
    }

    //hash some data
    if (!NT_SUCCESS(status = BCryptHashData(
        hHash.get(),
        (PBYTE)data,
        (ULONG)data_size,
        0)))
    {
        errorString = "Error 0x" + std::to_string(status) + "returned by BCryptHashData\n";
        goto Cleanup;
    }

    //close the hash
    if (!NT_SUCCESS(status = BCryptFinishHash(
        hHash.get(),
        pbHash.data(),
        cbHash,
        0)))
    {
        errorString = "Error 0x" + std::to_string(status) + "returned by BCryptFinishHash\n";
        goto Cleanup;
    }

	pHashItr = pbHash.data();
    retval.reserve(2 * cbHash + 1);
    for (size_t i = 0; i < cbHash; i++)
    {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", pHashItr[i]);
        retval += buf;
    }

Cleanup:
    throw_if(!NT_SUCCESS(status), errorString);

	std::wstring wretval(retval.begin(), retval.end());

    return wretval;
}

static std::wstring sha256(const std::string& input)
{
    std::wstring retVal = sha256(input.length(), input.data());
	return retVal;
}

static std::wstring get_file_name(const std::string& id)
{
    return g_cache_dirname + L"\\" + sha256(id);
}

std::string get_cached_file_location(const std::string& id){
	std::wstring fileName = get_file_name(id);
	return std::string(fileName.begin(), fileName.end());
}

std::string get_last_cache_read_expiry(){
	/*std::string result("Last cache read expiry is unset. This could be because there's been no cache reads yet, it has been read without checking for cache expiry or an error during cache read before cache expiry is checked.");
	if(last_cache_read_expiry != -1){
		result = "Last cache read expiry value is " + std::to_string(last_cache_read_expiry) + " and it was read when time(nullptr) value was " + std::to_string(last_cache_read_time);
	}
	return result;*/
	return "This function is only implemented for Linux";
}

void local_cache_clear()
{
    init();

    WIN32_FIND_DATA data;
    std::wstring baseDir(g_cache_dirname.begin(), g_cache_dirname.end());
    std::wstring searchPattern = baseDir + L"\\*";

    wil::unique_hfind hFind(FindFirstFile(searchPattern.c_str(), &data));
    if (hFind)
    {
        do {
            std::wstring fileName(data.cFileName);
            if ((fileName != L".") && (fileName != L".."))
            {
                std::wstring fullFileName = baseDir + L"\\" + fileName;
                throw_if(!DeleteFileW(fullFileName.c_str()),
                    "Deleting file failed, error code " + GetLastError());
            }
        } while (FindNextFile(hFind.get(), &data));
    }

    return;
};

wil::unique_hfile OpenHandle(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    
    wil::unique_hfile file;
    int i = 0;
    bool retry;

    do {
        file.reset(CreateFile(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
            dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile));
		retry = false;
		if (!file && (GetLastError() == ERROR_SHARING_VIOLATION) && (i < MAX_RETRY)) {
			retry = true;
		}

		if (retry)
        {
            Sleep(SLEEP_RETRY_MS);
        }

        i++;
    } while (retry);

    return std::move(file);
}


extern "C" void local_cache_add(const std::string& id, time_t expiry, size_t data_size, const void* data)
{
    throw_if(id.empty(), "The 'id' parameter must not be empty.");
    throw_if(data_size == 0, "Data cannot be empty.");
    throw_if(data == nullptr, "Data pointer must not be NULL.");

    init();
    CacheEntryHeaderV1 header{};
    header.version = CACHE_V1;
    header.expiry = expiry;

    std::wstring filename = get_file_name(id);

    wil::unique_hfile file(OpenHandle(filename.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
    throw_if(!file, "Create file failed");

    DWORD headerwritten;
    DWORD datawritten;

    throw_if(!WriteFile(file.get(), &header, sizeof(header), &headerwritten, nullptr),
        "Header write to local cache failed");

    throw_if(!WriteFile(file.get(), data, (DWORD)data_size, &datawritten, nullptr),
        "Data write to local cache failed");

}

std::unique_ptr<std::vector<uint8_t>> local_cache_get(
    const std::string& id, bool checkExpiration)
{
    throw_if(id.empty(), "The 'id' parameter must not be empty.");
    init();

    std::wstring filename = get_file_name(id);
    
    auto file = OpenHandle(filename.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (!file)
    {
        return nullptr;
    }

    CacheEntryHeaderV1 *header;
    char buf[sizeof(CacheEntryHeaderV1)] = { 0 };
    DWORD headerread = 0;

    throw_if(!ReadFile(file.get(), &buf, sizeof(CacheEntryHeaderV1), &headerread, nullptr), "Header read from local cache failed");

    throw_if(
        headerread != sizeof(CacheEntryHeaderV1),
        "Incomplete read of cache header");

    header = (CacheEntryHeaderV1*)buf;

    if (checkExpiration && header->expiry <= time(nullptr))
    {
        file.reset();
        DeleteFileW(filename.c_str());
        // Even if unlink fails, we can just return null. Thus, the return
        // value is intentionally ignored here.
        return nullptr;
    }

    DWORD size = GetFileSize(file.get(), nullptr);
    DWORD datasize = size - sizeof(CacheEntryHeaderV1);
    auto cache_entry = std::make_unique<std::vector<uint8_t>>(datasize);

    DWORD dataread = 0;
	throw_if(!ReadFile(file.get(), cache_entry->data(), datasize, &dataread, nullptr), "Error reading cached file data");
	throw_if(dataread != datasize, "Read returned fewer bytes than expected.");

    return cache_entry;
}
