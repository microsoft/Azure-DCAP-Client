#include <algorithm>
#include <cstring>
#include <mutex>
#include <locale>
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

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)

#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)

using namespace std;

namespace fs = std::experimental::filesystem;

constexpr uint16_t CACHE_V1 = 1;


constexpr _locale_t NULL_LOCALE = reinterpret_cast<_locale_t>(0);

static std::string g_cache_dirname;

static void throw_if(bool should_throw, const std::string& error)
{
	if (should_throw)
	{
		throw std::runtime_error(error);
	}
}


static void throw_errno(const std::string& description, int err)
{

	_locale_t locale = _create_locale(LC_ALL, "POSIX");
	//locale_t loc = newlocale(LC_ALL_MASK, "POSIX", NULL_LOCALE);
	if (locale == NULL_LOCALE)
	{
		throw std::runtime_error("Unable to allocate locale: " + std::to_string(errno));
	}
	//_strerror_l(err, locale);
	std::string errno_string = strerror(err);
	//strerror_l(err, locale);
	_free_locale(locale);

	throw std::runtime_error(description + ": " + errno_string);
}

static void throw_errno(const std::string& description)
{
	throw_errno(description, errno);
}


typedef struct CacheEntryHeaderV1 {
	uint16_t version;   // The version of the cache header
	time_t expiry;      // expiration time of this cache item
};

string CacheEntryHeaderV1ToSttring(CacheEntryHeaderV1 type) {
	char buff[20];
	strftime(buff, 20, "%Y-%m-%d %H:%M:%S", localtime(&type.expiry));
	string s = buff;

	char buf[6];
	sprintf(buf, "%u", type.version);
	string ss = buf;
	//string var = (char*) &type.version;
	return ss + s;
}


//typedef struct __attribute__((__packed__)) CacheEntryHeaderV1 {
//	uint16_t version;   // The version of the cache header
//	time_t expiry;      // expiration time of this cache item
//};


static void make_dir(const std::string& dirname)
{
	struct _stat buf {};
	int rc = _stat(dirname.c_str(), &buf);

	if (rc == 0)
	{

		//_S_IFDIR(buf.st_mode);
		if ((buf.st_mode & _S_IFDIR) > 0)
		{
			return;
		}

		throw std::runtime_error(dirname + " already exists, and is not a directory.");
	}

	wchar_t temp[64];
	std::mbstowcs(temp, dirname.c_str(), strlen(dirname.c_str()) + 1);//Plus null
	LPWSTR ptr = temp;

	rc = CreateDirectory(temp, NULL);
	//rc = mkdir(dirname.c_str(), mode);
	if (rc != 0)
	{
		throw_errno("Error creating directory '" + dirname + "'");
	}
}



static void init_callback()
{
	const char * env_home = ::getenv("APPDATA");
	const char * env_azdcap_cache = ::getenv("AZDCAP_CACHE");
	const std::string application_name("\\.az-dcap-client");

	std::string dirname;

	if (env_azdcap_cache != 0 && (strcmp(env_azdcap_cache, "") != 0))
	{
		dirname = env_azdcap_cache;
	}
	else if (env_home != 0 && (strcmp(env_home, "") != 0))
	{
		dirname = std::string(env_home);
	}
	else
	{
		// Throwing exception if the expected HOME
		// environment variable is not defined.

		throw std::runtime_error("HOME and AZDCAPCACHE environment variables not defined");
	}

	dirname += application_name;

	make_dir(dirname);

	//mode_t
	//make_dir(dirname, 0700);

	g_cache_dirname = dirname;
}


static void init()
{
	static std::once_flag init_flag;
	std::call_once(init_flag, init_callback);
}

static std::string sha256(size_t data_size, const void* data)
{
	BCRYPT_ALG_HANDLE hAlg = NULL;
	BCRYPT_HASH_HANDLE hHash = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	DWORD cbData = 0;
	DWORD cbHash = 0;
	DWORD cbHashObject = 0;
	PBYTE pbHashObject = NULL;
	PBYTE pbHash = NULL;
	std::string retval;

	//open an algorithm handle
	if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(
		&hAlg,
		BCRYPT_SHA256_ALGORITHM,
		NULL,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
		goto Cleanup;
	}

	if (!NT_SUCCESS(status == BCryptGetProperty(
		hAlg,
		BCRYPT_OBJECT_LENGTH,
		(PBYTE)&cbHashObject,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"*** ERROR 0x%X returned by BCryptGetProperty 1\n", status);
		goto Cleanup;
	}

	pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
	if (pbHashObject == NULL)
	{
		wprintf(L"*** memory allocation failed\n");
		goto Cleanup;
	}

	//calculate the length of the hash
	if (!NT_SUCCESS(status = BCryptGetProperty(
		hAlg,
		BCRYPT_HASH_LENGTH,
		(PBYTE)&cbHash,
		sizeof(DWORD),
		&cbData,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptGetProperty 2\n", status);
		goto Cleanup;
	}

	//allocate the hash buffer on the heap
	pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
	if (NULL == pbHash)
	{
		wprintf(L"**** memory allocation failed\n");
		goto Cleanup;
	}

	//create a hash
	if (!NT_SUCCESS(status = BCryptCreateHash(
		hAlg,
		&hHash,
		pbHashObject,
		cbHashObject,
		NULL,
		0,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
		goto Cleanup;
	}


	//hash some data
	if (!NT_SUCCESS(status = BCryptHashData(
		hHash,
		(PBYTE)data,
		data_size,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
		goto Cleanup;
	}

	//close the hash
	if (!NT_SUCCESS(status = BCryptFinishHash(
		hHash,
		pbHash,
		cbHash,
		0)))
	{
		wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
		goto Cleanup;
	}

	retval.reserve(2 * cbHash + 1);
	for (size_t i = 0; i < cbHash; i++)
	{
		char buf[3];
		snprintf(buf, sizeof(buf), "%02x", pbHash[i]);
		retval += buf;
	}

	wprintf(L"Success!\n");

Cleanup:

	if (hAlg)
	{
		BCryptCloseAlgorithmProvider(hAlg, 0);
	}

	if (hHash)
	{
		BCryptDestroyHash(hHash);
	}

	if (pbHashObject)
	{
		HeapFree(GetProcessHeap(), 0, pbHashObject);
	}

	if (pbHash)
	{
		HeapFree(GetProcessHeap(), 0, pbHash);
	}

	return retval;
}

static std::string sha256(const std::string& input)
{
	return sha256(input.length(), input.data());
}

static std::string get_file_name(const std::string& id)
{
	return g_cache_dirname + "\\" + sha256(id);
}

void local_cache_clear() {
	init();

	WIN32_FIND_DATA data;

	wstring baseDir(g_cache_dirname.begin(), g_cache_dirname.end());
	wstring searchPattern = baseDir + L"\\*";

	HANDLE hFind = FindFirstFile(searchPattern.c_str(), &data);

	if (hFind != INVALID_HANDLE_VALUE)
	{
		do {
			wstring fileName(data.cFileName);

			if (fileName.compare(L".") != 0 &&
				fileName.compare(L"..") != 0)
			{
				wstring fullFileName = baseDir + L"\\" + fileName;

				wprintf(L"About to delete %s\n", fullFileName.c_str());

				if (DeleteFileW(fullFileName.c_str()))
				{
					wprintf(L"Successfully deleted file");
				}
				else
				{
					DWORD dw = GetLastError();
					wprintf(L"Deleting file failed %d\n", dw);
				}
			}
		} while (FindNextFile(hFind, &data));
		FindClose(hFind);
	}

	return;
};



wstring s2lpcwstr(const std::string &s)
{
	std::wstring wsTmp(s.begin(), s.end());
	LPCWSTR lfilename = wsTmp.c_str();
	bool hope = (L"C:\\Users\\jochow\\AppData\\Roaming\\.az-dcap-client\\0d6e4079e36703ebd37c00722f5891d28b0e2811dc114b129215123adcce3605" == wsTmp);
	return wsTmp;
}

void local_cache_add(const std::string& id,	time_t expiry, size_t data_size, const void* data)
{
	throw_if(id.empty(), "The 'id' parameter must not be empty.");
	throw_if(data_size == 0, "Data cannot be empty.");
	throw_if(data == nullptr, "Data pointer must not be NULL.");

	init();
	CacheEntryHeaderV1 header{};
	header.version = CACHE_V1;
	header.expiry = expiry;

	string s = CacheEntryHeaderV1ToSttring(header);

	HANDLE file;

	std::string filename = get_file_name(id);
	//LPCWSTR temp = s2lpcwstr(filename);
	std::wstring wfilename(filename.begin(), filename.end());
	file = CreateFile(wfilename.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) 
	{ 
		DWORD err = GetLastError();
		return;
	}

	OVERLAPPED overlapvar = { 0 };

	if (LockFileEx(file, LOCKFILE_EXCLUSIVE_LOCK, 0, MAXDWORD, MAXDWORD, &overlapvar))
	{
		printf("File exclusive lock successful\n");
	}
	else
	{
		printf("File exclusive lock failed\n");
	}


	DWORD headerwritten;
	DWORD datawritten;
	int success;
	success = WriteFile(file, &header, sizeof(header), &headerwritten, NULL);
	if (success = 0) {
		return;
	}
	success = WriteFile(file, data, data_size, &datawritten, NULL);
	if (success = 0) {
		return;
	}

	if (UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &overlapvar))
	{
		printf("File exclusive unlocked successfully\n");
	}
	else
	{
		printf("File exclusive unlock failed\n");
	}

	CloseHandle(file);
}

std::unique_ptr<std::vector<uint8_t>> local_cache_get(
	const std::string& id)
{
	throw_if(id.empty(), "The 'id' parameter must not be empty.");

	init();

	HANDLE file;
	std::string filename = get_file_name(id);
	//LPCWSTR temp = s2lpcwstr(filename);
	std::wstring wfilename(filename.begin(), filename.end());
	file = CreateFile(wfilename.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (file == INVALID_HANDLE_VALUE) 
	{
		DWORD err = GetLastError();

		return nullptr;
	}

	OVERLAPPED overlapvar = { 0 };

	if (LockFileEx(file, 0, 0, MAXDWORD, MAXDWORD, &overlapvar))
	{
		printf("File shared lock successful\n");
	}
	else
	{
		printf("File shared lock failed\n");
	}


	bool success;
	CacheEntryHeaderV1 *header;
	char buf[sizeof(CacheEntryHeaderV1)] = { 0 };
	//int sss = sizeof(uint16_t);
	LPDWORD headerread = 0;
	success = ReadFile(file, &buf, sizeof(CacheEntryHeaderV1), headerread, NULL);
	if (success = 0) {
		return nullptr;
	}
	header = (CacheEntryHeaderV1*)buf;

	if (header->expiry <= time(nullptr))
	{
		if (UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &overlapvar))
		{
			printf("File shared unlocked successfully\n");
		}
		else
		{
			printf("File shared unlock failed\n");
		}

		CloseHandle(file);
		DeleteFileW(wfilename.c_str());

		// Even if unlink fails, we can just return null. Thus, the return
		// value is intentionally ignored here.
		return nullptr;
	}



	DWORD size = GetFileSize(file, NULL);


	//struct stat stat_buf;
	//int rc = stat(get_file_name(id).c_str(), &stat_buf);
	int datasize = size - sizeof(CacheEntryHeaderV1);


	uint8_t * data = new uint8_t[datasize]();
	auto cache_entry = std::make_unique<std::vector<uint8_t>>(datasize);
	LPDWORD dataread = 0;
	success = ReadFile(file, cache_entry->data(), size, dataread, NULL);
	if (success = 0) {
		return nullptr;
	}

	if (UnlockFileEx(file, 0, MAXDWORD, MAXDWORD, &overlapvar))
	{
		printf("File shared unlocked successfully\n");
	}
	else
	{
		printf("File shared unlock failed\n");
	}

	CloseHandle(file);

	return cache_entry;

}
