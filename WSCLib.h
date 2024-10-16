#pragma once

// Windows Self Cleaning Library
/*

This header is focused in forensic cleaning of execution traces of an application in Windows OS.

*/

#include <string>
#include <Windows.h>
#include <iostream>
#include <vector>
#include <algorithm>
#include <locale>
#include <cwctype>
#include <filesystem>
#include <fstream>
#include <Subauth.h>


class WSCLib
{
private:
	static std::wstring ROT13(std::wstring input)
	{
		std::wstring output = input;
		for (int i = 0; i < input.length(); i++)
		{
			if (input[i] >= 'a' && input[i] <= 'z')
			{
				if (input[i] > 'm')
				{
					output[i] = input[i] - 13;
				}
				else
				{
					output[i] = input[i] + 13;
				}
			}
			else if (input[i] >= 'A' && input[i] <= 'Z')
			{
				if (input[i] > 'M')
				{
					output[i] = input[i] - 13;
				}
				else
				{
					output[i] = input[i] + 13;
				}
			}
		}
		return output;
	}

	static std::string ROT13(std::string input)
	{
		std::string output = input;
		for (int i = 0; i < input.length(); i++)
		{
			if (input[i] >= 'a' && input[i] <= 'z')
			{
				if (input[i] > 'm')
				{
					output[i] = input[i] - 13;
				}
				else
				{
					output[i] = input[i] + 13;
				}
			}
			else if (input[i] >= 'A' && input[i] <= 'Z')
			{
				if (input[i] > 'M')
				{
					output[i] = input[i] - 13;
				}
				else
				{
					output[i] = input[i] + 13;
				}
			}
		}
		return output;
	}

	static std::vector<std::wstring> GetSubKeys(HKEY hKey) {

		std::vector<std::wstring> subKeys;

		TCHAR    achKey[MAX_PATH];   // buffer for subkey name
		DWORD    cbName = 0;                   // size of name string
		DWORD    cSubKeys = 0;               // number of subkeys 

		DWORD i = 0, j = 0, retCode = 0;

		// Get the class name and the value count. 
		retCode = RegQueryInfoKeyW(
			hKey,                    // key handle 
			NULL,                // buffer for class name 
			NULL,           // size of class string 
			NULL,                    // reserved 
			&cSubKeys,               // number of subkeys 
			NULL,            // longest subkey size 
			NULL,            // longest class string 
			NULL,                // number of values for this key 
			NULL,            // longest value name 
			NULL,         // longest value data 
			NULL,   // security descriptor 
			NULL);       // last write time

		if (cSubKeys)
		{
			for (i = 0; i < cSubKeys; i++)
			{
				cbName = MAX_PATH;
				retCode = RegEnumKeyExW(hKey, i,
					achKey,
					&cbName,
					NULL,
					NULL,
					NULL,
					NULL);
				if (retCode == ERROR_SUCCESS)
				{
					subKeys.push_back(achKey);
				}
			}
		}

		return subKeys;
	}

	static HKEY OpenKey(HKEY hKey, std::wstring SubKey)
	{
		HKEY hKeyResult;
		if (RegOpenKeyExW(hKey, SubKey.c_str(), 0, KEY_ALL_ACCESS, &hKeyResult) != ERROR_SUCCESS)
		{
			return (HKEY)INVALID_HANDLE_VALUE;
		}
		return hKeyResult;
	}

	struct ValueInfo {
		std::wstring Name;
		DWORD Type = 0;
		std::vector<BYTE> Data;
	};

	static std::vector<ValueInfo> GetValueList(HKEY hKey) {

		std::vector<ValueInfo> values;

		DWORD    cValues = 0;

		DWORD i, retCode;

		retCode = RegQueryInfoKeyW(
			hKey,                    // key handle 
			NULL,                // buffer for class name 
			NULL,           // size of class string 
			NULL,                    // reserved 
			NULL,            // number of subkeys 
			NULL,            // longest subkey size 
			NULL,            // longest class string 
			&cValues,                // number of values for this key 
			NULL,            // longest value name 
			NULL,        // longest value data 
			NULL,    // security descriptor 
			NULL);       // last write time


#define MAX_VALUE_NAME 16383
		auto achValue = std::make_unique<TCHAR[]>(MAX_VALUE_NAME);
		DWORD    cchValue = MAX_VALUE_NAME;
		DWORD   dwType = 0;
		auto data = std::make_unique<BYTE[]>(1024 * 1024); // 1MB is the maximum size of a registry value
		DWORD dataSize = 1024 * 1024;

		if (cValues)
		{
			for (i = 0; i < cValues; i++)
			{
				cchValue = MAX_VALUE_NAME;
				achValue[0] = '\0';
				dataSize = 1024 * 1024;

				retCode = RegEnumValueW(hKey, i,
					achValue.get(),
					&cchValue,
					NULL,
					&dwType,
					data.get(),
					&dataSize);

				if (retCode == ERROR_SUCCESS)
				{
					ValueInfo info{};
					info.Name = achValue.get();
					info.Type = dwType;
					info.Data.resize(dataSize);
					memcpy(info.Data.data(), data.get(), dataSize);
					values.push_back(info);
				}
			}
		}

		return values;
	}

	static bool ClearUserAssist(std::wstring FileName)
	{
		//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\

		auto hKey = HKEY_CURRENT_USER;
		auto userAssetKey = OpenKey(hKey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist");
		if (userAssetKey == INVALID_HANDLE_VALUE) {
			return false; // Error opening the key
		}

		auto subKeys = GetSubKeys(userAssetKey);
		for (const auto& subKey : subKeys)
		{
			auto subKeyHandle = OpenKey(userAssetKey, subKey + L"\\Count");
			if (subKeyHandle == INVALID_HANDLE_VALUE) {
				continue;
			}

			auto values = GetValueList(subKeyHandle);

			for (const auto& value : values)
			{
				//Check if the value contains the file name

				std::wstring tmpName = ROT13(value.Name);
				std::transform(tmpName.begin(), tmpName.end(), tmpName.begin(),
					[](wchar_t c) { return std::towlower(c); });

				if (tmpName.find(FileName) != std::wstring::npos)
				{
					// Clear the value
					if (RegDeleteValueW(subKeyHandle, value.Name.c_str()) != ERROR_SUCCESS)
					{
						RegCloseKey(subKeyHandle);
						RegCloseKey(userAssetKey);
						return false; // Error deleting the value
					}
				}
			}

			RegCloseKey(subKeyHandle);
		}

		RegCloseKey(userAssetKey);
		return true;
	}

	static bool ClearPrefetch(std::wstring FileName, bool SkipWaitPrefetch)
	{
		//send as parameter the start time of cleaned file may be useful to reduce waiting times

		//C:\Windows\Prefetch

		//list all files in the directory searching for the file name using std filesystem
		std::wstring PrefetchPath = L"C:\\Windows\\Prefetch";

		if (!std::filesystem::exists(PrefetchPath)) {
			return false;
		}

		int maxTries = 15;
		bool found = false;
		bool anyDeleted = false;
		while (!found) {

			try
			{
				for (const auto& entry : std::filesystem::directory_iterator(PrefetchPath))
				{
					auto FilePath = entry.path().wstring();
					std::transform(FilePath.begin(), FilePath.end(), FilePath.begin(),
						[](wchar_t c) { return std::towlower(c); });

					if (FilePath.find(FileName) != std::wstring::npos)
					{
						found = true;
						if (!SkipWaitPrefetch && (maxTries == 15 || anyDeleted)) { // The file was found in the first try probably exists from before, lets wait until the file is written, alternatively if we already deleted a file means that there is more than 1 and we have to repeat the process for security
							//Wait until file write time is modified or 15 seconds
							auto lastWriteTime = std::filesystem::last_write_time(entry.path());

							int waitTime = 0; // Prefetch is written normally in 10 seconds
							while (std::filesystem::last_write_time(entry.path()) == lastWriteTime) {
								Sleep(1000);
								waitTime += 1000;
								if (waitTime >= 15000) {
									break;
								}
							}
							//if (waitTime >= 15000) // File was already written, maybe the user just call the library too late
						}


						// Delete the file
						if (!std::filesystem::remove(entry.path())) {
							return false;
						}
						anyDeleted = true;
					}
				}
			}
			catch (std::filesystem::filesystem_error& e)
			{
				//if access denied, return false
				if (e.code().value() == ERROR_ACCESS_DENIED) {
					return false;
				}
			}

			if (maxTries-- <= 0) {
				break;
			}

			if (!found) { // The file was not found, maybe the file wasn't created yet
				Sleep(1000);
			}
		}

		return true;
	}
	
	static bool ClearRecentFiles(std::wstring FileName, std::wstring ParentFolderName) {

		//%AppData%\Microsoft\Windows\Recent

		//Resolve environment variable
		std::wstring AppData = L"%AppData%";
		std::wstring AppDataResolved;
		AppDataResolved.resize(MAX_PATH);
		DWORD dwRet = ExpandEnvironmentStringsW(AppData.c_str(), (LPWSTR)AppDataResolved.c_str(), MAX_PATH);
		if (dwRet == 0) {
			return false;
		}
		AppDataResolved.resize(dwRet - 1); // Remove null terminator

		std::wstring RecentPath = AppDataResolved + L"\\Microsoft\\Windows\\Recent";

		if (!std::filesystem::exists(RecentPath)) {
			return true;
		}

		for (const auto& entry : std::filesystem::directory_iterator(RecentPath))
		{
			auto FilePath = entry.path().wstring();
			std::transform(FilePath.begin(), FilePath.end(), FilePath.begin(),
				[](wchar_t c) { return std::towlower(c); });

			if (FilePath.find(FileName) != std::wstring::npos || 
				ParentFolderName.length() > 0 && FilePath.find(ParentFolderName) != std::wstring::npos)
			{
				// Delete the file
				if (!std::filesystem::remove(entry.path())) {
					return false;
				}
			}
		}

		return true;
	}

	static bool ClearRunMRU(std::wstring FileName) {
		//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

		auto hKey = HKEY_CURRENT_USER;

		auto runMRUKey = OpenKey(hKey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU");
		if (runMRUKey == INVALID_HANDLE_VALUE) {
			return true; // Error opening the key
		}

		auto values = GetValueList(runMRUKey);

		for (const auto& value : values)
		{
			//if REG_SZ and contains the file name
			if (value.Type != REG_SZ) {
				continue;
			}

			std::wstring valueData = std::wstring((wchar_t*)value.Data.data(), value.Data.size() / sizeof(wchar_t));

			std::transform(valueData.begin(), valueData.end(), valueData.begin(),
				[](wchar_t c) { return std::towlower(c); });

			if (valueData.find(FileName) != std::wstring::npos)
			{
				// Set value to some random value to avoid detection
				if (RegSetKeyValueW(runMRUKey, NULL, value.Name.c_str(), REG_SZ, L"%temp%\\1", 8 * sizeof(wchar_t)) != ERROR_SUCCESS) {
					RegCloseKey(runMRUKey);
					return false;
				}
			}
		}

		RegCloseKey(runMRUKey);

		return true;
	}

	static bool ClearAutomaticDestinations(std::wstring FileName, std::wstring ParentFolderName) {
		//%AppData%\Microsoft\Windows\Recent\AutomaticDestinations
		//%AppData%\Microsoft\Windows\Recent\CustomDestinations

		//We will not implement a function to really parse this files but we can find the FileName like a pattern in the byte content and delete it

		//Resolve environment variable
		std::wstring AppData = L"%AppData%";
		std::wstring AppDataResolved;
		AppDataResolved.resize(MAX_PATH);
		DWORD dwRet = ExpandEnvironmentStringsW(AppData.c_str(), (LPWSTR)AppDataResolved.c_str(), MAX_PATH);
		if (dwRet == 0) {
			return false;
		}
		AppDataResolved.resize(dwRet - 1); // Remove null terminator

		std::wstring RecentPath = AppDataResolved + L"\\Microsoft\\Windows\\Recent";
		std::wstring AutomaticDestinationsPath = RecentPath + L"\\AutomaticDestinations";
		std::wstring CustomDestinationsPath = RecentPath + L"\\CustomDestinations";

		std::vector<std::wstring> paths = { AutomaticDestinationsPath, CustomDestinationsPath };

		for (const auto& path : paths) {

			if (!std::filesystem::exists(path)) {
				continue;
			}
			for (const auto& entry : std::filesystem::directory_iterator(path))
			{
				std::vector<BYTE> fileContent;
				std::ifstream file(entry.path(), std::ios::binary);
				if (!file.is_open()) {
					continue;
				}

				file.seekg(0, std::ios::end);
				fileContent.resize(file.tellg());
				file.seekg(0, std::ios::beg);
				file.read((char*)fileContent.data(), fileContent.size());
				file.close();

				for (int i = 0; i < fileContent.size(); i++)
				{
					for (int j = 0; j < FileName.length(); j++)
					{
						if (i + j * 2 + 1 >= fileContent.size()) {
							break;
						}

						if (std::towlower(*(wchar_t*)&fileContent[i + j * 2]) != FileName[j]) {
							break;
						}

						if (j == FileName.length() - 1) {
							// Delete the file
							if (!std::filesystem::remove(entry.path())) {
								return false;
							}
						}
					}
				}
			}
		}

		return true;
	}

	static bool ClearRecentDocs(std::wstring FileName, bool ClearSys) {

		//HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

		auto hKey = HKEY_CURRENT_USER;
		auto recentDocsKey = OpenKey(hKey, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs");
		if (recentDocsKey == INVALID_HANDLE_VALUE) {
			return false; // Error opening the key
		}

		auto subKeys = GetSubKeys(recentDocsKey);

		if (ClearSys) {
			if (std::find(subKeys.begin(), subKeys.end(), L".sys") != subKeys.end()) {
				if (RegDeleteTreeW(recentDocsKey, L".sys") != ERROR_SUCCESS) {
					RegCloseKey(recentDocsKey);
					return false;
				}
			}
		}

		for (const auto& subKey : subKeys)
		{
			auto subKeyHandle = OpenKey(recentDocsKey, subKey);
			if (subKeyHandle == INVALID_HANDLE_VALUE) {
				continue;
			}

			auto values = GetValueList(subKeyHandle);

			RegCloseKey(subKeyHandle);

			bool deleteAll = false;
			for (const auto& value : values)
			{
				for (int i = 0; i < value.Data.size(); i++)
				{
					for (int j = 0; j < FileName.length(); j++)
					{
						if (i + j * 2 + 1 >= value.Data.size()) {
							break;
						}

						if (std::towlower(*(wchar_t*)&value.Data[i + j * 2]) != FileName[j]) {
							break;
						}

						if (j == FileName.length() - 1) {
							// Clear the value
							deleteAll = true;
							break;
						}

					}

					if (deleteAll) {
						break;
					}
				}

				if (deleteAll) {
					break;
				}
			}


			if (deleteAll) {
				// Clear the subkey
				if (RegDeleteTreeW(recentDocsKey, subKey.c_str()) != ERROR_SUCCESS) {
					RegCloseKey(recentDocsKey);
					return false;
				}
			}
		}

		RegCloseKey(recentDocsKey);

		return true;
	}

	static bool ClearUSNJournal(std::wstring FileName) {

		HANDLE hVolume = CreateFileW(L"\\\\.\\C:", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		if (hVolume == INVALID_HANDLE_VALUE) {
			return false;
		}

		USN_JOURNAL_DATA journalData{};
		DWORD bytesReturned;

		if (!DeviceIoControl(hVolume,
			FSCTL_QUERY_USN_JOURNAL,
			NULL,
			0,
			&journalData,
			sizeof(journalData),
			&bytesReturned,
			NULL)) {

			DWORD error = GetLastError();
			if (error == ERROR_JOURNAL_NOT_ACTIVE) {
				return false;
			}

			throw std::runtime_error("Failed to query USN journal");
		}

		//Delete the journal
		
		DELETE_USN_JOURNAL_DATA deleteData{};
		deleteData.UsnJournalID = journalData.UsnJournalID;
		deleteData.DeleteFlags = USN_DELETE_FLAG_DELETE;

		// Delete the journal
		if (!DeviceIoControl(hVolume,
			FSCTL_DELETE_USN_JOURNAL,
			&deleteData,
			sizeof(deleteData),
			NULL,
			0,
			&bytesReturned,
			NULL)) {

			DWORD error = GetLastError();
			return false;
		}

		return true;
	}


	static HKEY bruteHandle(HANDLE proc) {
		auto uproc = GetCurrentProcess();
		for (int i = 1; i < 0x10000; i++) {
			HANDLE hDup;
			if (DuplicateHandle(proc, (HKEY)i, uproc, &hDup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
				for (int i = 0;; i++) {
					WCHAR name[255];
					DWORD size = sizeof(name) / 2;
					auto result = RegEnumKeyW((HKEY)hDup, i, name, size);
					if (result != ERROR_SUCCESS) {
						break;
					}

					if (wcscmp(name, L"InventoryApplicationFile") == 0) {
						return (HKEY)hDup;
					}
				}

				CloseHandle(hDup);
			}
		}

		return 0;
	}

	static std::vector<std::wstring> GetNamedObjects() {

		std::vector<std::wstring> namedObjects;

		typedef struct _OBJECT_ATTRIBUTES {
			ULONG           Length;
			HANDLE          RootDirectory;
			PUNICODE_STRING ObjectName;
			ULONG           Attributes;
			PVOID           SecurityDescriptor;
			PVOID           SecurityQualityOfService;
		} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

		//NtOpenDirectoryObject
		typedef NTSTATUS(__stdcall* NtOpenDirectoryObject_t)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
		//NtQueryDirectoryObject
		typedef NTSTATUS(__stdcall* NtQueryDirectoryObject_t)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);


		auto ntdll = LoadLibraryA("ntdll.dll");
		if (ntdll == NULL) {
			throw std::exception("Error loading ntdll.dll");
		}
		auto NtOpenDirectoryObject = NtOpenDirectoryObject_t((ULONG64)GetProcAddress(ntdll, "NtOpenDirectoryObject"));
		if (NtOpenDirectoryObject == NULL) {
			throw std::exception("Error getting NtOpenDirectoryObject address");
		}
		auto NtQueryDirectoryObject = NtQueryDirectoryObject_t((ULONG64)GetProcAddress(ntdll, "NtQueryDirectoryObject"));
		if (NtQueryDirectoryObject == NULL) {
			throw std::exception("Error getting NtQueryDirectoryObject address");
		}


		OBJECT_ATTRIBUTES objAttr;
		UNICODE_STRING objName;
		wchar_t name[] = L"\\BaseNamedObjects";
		objName.Buffer = name;
		objName.Length = sizeof(name) - sizeof(WCHAR);
		objName.MaximumLength = sizeof(name);


		objAttr.Length = sizeof(OBJECT_ATTRIBUTES);
		objAttr.RootDirectory = NULL;
		objAttr.ObjectName = &objName;
		objAttr.Attributes = 0;
		objAttr.SecurityDescriptor = NULL;
		objAttr.SecurityQualityOfService = NULL;

#define DIRECTORY_QUERY 0x0001

		HANDLE hDir;
		auto status = NtOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &objAttr);
		if (status != 0) {
			return {};
		}

		auto buffSize = 0x1000;
		auto buffer = std::make_unique<BYTE[]>(buffSize);
		ULONG context = 0;

#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001A)

		while (true) {
			ULONG returnLength;
			status = NtQueryDirectoryObject(
				hDir,
				buffer.get(),
				buffSize,
				FALSE,
				FALSE,
				&context,
				&returnLength);

			if (status == STATUS_NO_MORE_ENTRIES) {
				break;
			}
			else if (!NT_SUCCESS(status)) {
				break;
			}

			// The buffer contains a list of OBJECT_DIRECTORY_INFORMATION
			struct OBJECT_DIRECTORY_INFORMATION {
				UNICODE_STRING Name;
				UNICODE_STRING TypeName;
			};

			OBJECT_DIRECTORY_INFORMATION* entry = (OBJECT_DIRECTORY_INFORMATION*)buffer.get();

			while (true) {
				if (entry->Name.Length == 0) {
					break;
				}

				// Convert UNICODE_STRING to std::wstring and add to the list
				namedObjects.push_back(std::wstring(entry->Name.Buffer, entry->Name.Length / sizeof(WCHAR)));

				// Move to the next entry
				entry = (OBJECT_DIRECTORY_INFORMATION*)((PBYTE)entry + sizeof(OBJECT_DIRECTORY_INFORMATION));
			}
		}

		typedef NTSTATUS(__stdcall* NtClose_t)(HANDLE);
		auto NtClose = NtClose_t((ULONG64)GetProcAddress(ntdll, "NtClose"));
		if (NtClose == NULL) {
			throw std::exception("Error getting NtClose address");
		}

		// Close the directory handle
		NtClose(hDir);

		return namedObjects;
	}

	static bool GetPrivilege(const wchar_t* priv) {

		LUID privDw;
		if (!LookupPrivilegeValueW(NULL, priv, &privDw)) {
			return false;
		}

		auto ntdll = LoadLibraryA("ntdll.dll");
		if (ntdll == NULL) {
			throw std::exception("Error loading ntdll.dll");
		}

		typedef NTSTATUS(__stdcall* RtlAdjustPrivilege_t)(ULONG, BOOLEAN, BOOLEAN, PBOOLEAN);
		auto RtlAdjustPrivilege = RtlAdjustPrivilege_t((ULONG64)GetProcAddress(ntdll, "RtlAdjustPrivilege"));
		if (RtlAdjustPrivilege == NULL) {
			throw std::exception("Error getting RtlAdjustPrivilege address");
		}

		BOOLEAN enabled;
		auto status = RtlAdjustPrivilege(privDw.LowPart, TRUE, FALSE, &enabled);
		if (status != 0) {
			return false;
		}

		return true;
	}

	static bool ClearAmCache(std::wstring fileName, std::wstring fileNameWithoutExtension) {

		HANDLE proc = INVALID_HANDLE_VALUE;
		HKEY dup = 0;
		bool manuallyLoaded = false;

		GetPrivilege(SE_BACKUP_NAME);
		GetPrivilege(SE_RESTORE_NAME);


		auto res = RegLoadKeyW(HKEY_LOCAL_MACHINE, L"AmCacheTmp", L"C:\\Windows\\appcompat\\Programs\\Amcache.hve");
		if (res != ERROR_SUCCESS) {

			auto namedObjects = GetNamedObjects();

			std::vector<DWORD> pids;
			const std::wstring inventoryHandleName = L"InventorySynchronizationInventoryApplicationFileMemory";
			for (auto& obj : namedObjects) {
				if (obj.find(inventoryHandleName) == 0) {
					auto pid = wcstoul(obj.c_str() + inventoryHandleName.length(), NULL, 10);
					pids.push_back(pid);
				}
			}

			for (auto pid : pids) {
				proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				dup = bruteHandle(proc);
				if (dup == 0) {
					CloseHandle(proc);
					proc = INVALID_HANDLE_VALUE;
					dup = 0;
				}
				else {
					break;
				}
			}

			if (dup == 0) {
				return false;
			}
		}
		else {
			manuallyLoaded = true;
			res = RegOpenKeyW(HKEY_LOCAL_MACHINE, L"AmCacheTmp\\Root", &dup);
			if (res != ERROR_SUCCESS) {
				return false;
			}
		}

		auto lambdaRemoveSubkeysWithText = [](HKEY hKey, std::wstring text) {
			auto subKeys = GetSubKeys(hKey);

			for (auto& key : subKeys) {
				std::transform(key.begin(), key.end(), key.begin(),
					[](wchar_t c) { return std::towlower(c); });
				if (key.find(text) != std::wstring::npos) {
					if (RegDeleteKeyW(hKey, key.c_str()) != ERROR_SUCCESS) {
						return false;
					}
				}
			}

			return true;
		};

		bool result = true;

		auto subkey = OpenKey(dup, L"InventoryApplicationFile");
		auto deletionOk = lambdaRemoveSubkeysWithText(subkey, fileName);
		RegCloseKey(subkey);
		if (!deletionOk) result = false;

		subkey = OpenKey(dup, L"InventoryApplicationShortcut");
		deletionOk = lambdaRemoveSubkeysWithText(subkey, fileNameWithoutExtension);
		RegCloseKey(subkey);
		if (!deletionOk) result = false;

		subkey = OpenKey(dup, L"InventoryNonArp");
		deletionOk = lambdaRemoveSubkeysWithText(subkey, fileName);
		RegCloseKey(subkey);
		if (!deletionOk) result = false;

		RegFlushKey(dup);
		CloseHandle(dup);
		if (manuallyLoaded) {
			RegUnLoadKeyW(HKEY_LOCAL_MACHINE, L"AmCacheTmp");
		}
		else {
			if (proc != INVALID_HANDLE_VALUE) {
				CloseHandle(proc);
			}
		}

		return result;
	}

public:


	/* @brief Clean
	* @param FilePath: The path or executable name of the file that generates the traces
	* @param SkipWaitPrefetch: If true, the function will not wait for the prefetch file to be written
	* @param ClearUSN: If true, the function will clear the USN journal
	*/
	static bool Clean(std::wstring InputFilePath, bool SkipWaitPrefetch, bool ClearUSN)
	{
		if (InputFilePath.length() == 0) {
			return false;
		}

		std::transform(InputFilePath.begin(), InputFilePath.end(), InputFilePath.begin(),
			[](wchar_t c) { return std::towlower(c); });

		std::wstring FilePath = InputFilePath;
		std::wstring FileName = FilePath;
		std::wstring Extension{};
		std::wstring ParentFolderName{};
		std::wstring FileNameWithoutExtension{};

		// Get the file name from the path
		auto pos = FileName.find_last_of(L"\\");
		if (pos != std::wstring::npos) {
			FileName = FileName.substr(pos + 1);
		}

		if (FileName.length() == 0) { // Invalid file name or path don't contains the file name
			return false;
		}

		// Get the extension of the file
		pos = FileName.find_last_of(L".");
		if (pos != std::wstring::npos) {
			Extension = FileName.substr(pos);
			FileNameWithoutExtension = FileName.substr(0, pos);
		}
		else {
			FileNameWithoutExtension = FileName;
		}

		// Get the parent folder name
		pos = FilePath.find_last_of(L"\\");
		if (pos != std::wstring::npos) {
			ParentFolderName = FilePath.substr(0, pos);

			pos = ParentFolderName.find_last_of(L"\\"); 
			if (pos != std::wstring::npos) {
				ParentFolderName = ParentFolderName.substr(pos + 1);
			}
		}


		//Note: File name may don't have extension
		//Note: SkipWaitPrefetch may be unsecure if used without knowledge

		if (!ClearUserAssist(FileName)) {
			std::cout << "Error clearing UserAssist" << std::endl;
			return false;
		}

		if (!ClearRecentFiles(FileName, ParentFolderName)) {
			std::cout << "Error clearing RecentFiles" << std::endl;
			return false;
		}

		if (!ClearRunMRU(FileName)) {
			std::cout << "Error clearing RunMRU" << std::endl;
			return false;
		}

		if (!ClearAutomaticDestinations(FileName, ParentFolderName)) {
			std::cout << "Error clearing AutomaticDestinations" << std::endl;
			return false;
		}

		if (!ClearRecentDocs(FileName, true)) {
			std::cout << "Error clearing RecentDocs" << std::endl;
			return false;
		}

		if (!ClearAmCache(FileName, FileNameWithoutExtension)) {
			std::cout << "Error clearing AmCache" << std::endl;
			return false;
		}

		if (!ClearPrefetch(FileName, SkipWaitPrefetch)) {
			std::cout << "Error clearing Prefetch" << std::endl;
			return false;
		}

		if (ClearUSN && !ClearUSNJournal(FileName)) {
			std::cout << "Error clearing USNJournal" << std::endl;
			return false;
		}

		return true;
	}

	static std::wstring GetCurrentProcessPath()
	{
		wchar_t buffer[MAX_PATH]{};
		GetModuleFileNameW(NULL, buffer, MAX_PATH);
		return buffer;
	}

};