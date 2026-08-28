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
#include <Aclapi.h>
#include <cstdint>
#include <cstring>
#include <memory>


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

	static HKEY OpenKeyWithAccess(HKEY hKey, const std::wstring& SubKey, REGSAM Access)
	{
		HKEY result = nullptr;
		return RegOpenKeyExW(hKey, SubKey.c_str(), 0, Access, &result) == ERROR_SUCCESS
			? result : (HKEY)INVALID_HANDLE_VALUE;
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

	static bool ContainsInsensitive(const BYTE* data, size_t size, const std::wstring& needle)
	{
		if (needle.empty()) return false;
		for (size_t i = 0; i + needle.size() <= size; ++i)
		{
			bool match = true;
			for (size_t j = 0; j < needle.size(); ++j)
			{
				if (std::towlower(static_cast<unsigned char>(data[i + j])) !=
					std::towlower(needle[j])) { match = false; break; }
			}
			if (match) return true;
		}
		const size_t wideBytes = needle.size() * sizeof(wchar_t);
		for (size_t i = 0; i + wideBytes <= size; ++i)
		{
			bool match = true;
			for (size_t j = 0; j < needle.size(); ++j)
			{
				wchar_t current = 0;
				std::memcpy(&current, data + i + j * sizeof(wchar_t), sizeof(current));
				if (std::towlower(current) != std::towlower(needle[j])) { match = false; break; }
			}
			if (match) return true;
		}
		return false;
	}

	static bool MatchesAny(const BYTE* data, size_t size,
		const std::vector<std::wstring>& needles)
	{
		for (const auto& needle : needles)
			if (ContainsInsensitive(data, size, needle)) return true;
		return false;
	}

	static bool MatchesAny(const std::wstring& text,
		const std::vector<std::wstring>& needles)
	{
		auto lower = text;
		std::transform(lower.begin(), lower.end(), lower.begin(),
			[](wchar_t c) { return std::towlower(c); });
		for (const auto& needle : needles)
		{
			auto lowerNeedle = needle;
			std::transform(lowerNeedle.begin(), lowerNeedle.end(), lowerNeedle.begin(),
				[](wchar_t c) { return std::towlower(c); });
			if (!lowerNeedle.empty() && lower.find(lowerNeedle) != std::wstring::npos) return true;
		}
		return false;
	}

	static bool ClearRegistryValues(HKEY root, const std::vector<std::wstring>& paths,
		const std::vector<std::wstring>& needles)
	{
		for (const auto& path : paths)
		{
			auto key = OpenKey(root, path);
			if (key == INVALID_HANDLE_VALUE) continue;
			for (const auto& value : GetValueList(key))
			{
				if (MatchesAny(value.Name, needles) ||
					MatchesAny(value.Data.data(), value.Data.size(), needles))
				{
					if (RegDeleteValueW(key, value.Name.c_str()) != ERROR_SUCCESS)
					{
						RegCloseKey(key);
						return false;
					}
				}
			}
			RegCloseKey(key);
		}
		return true;
	}

	static bool ReadBinaryFile(const std::filesystem::path& path, std::vector<BYTE>& data)
	{
		std::ifstream file(path, std::ios::binary | std::ios::ate);
		if (!file) return false;
		const auto length = file.tellg();
		if (length < 0 || length > 64 * 1024 * 1024) return false;
		data.resize(static_cast<size_t>(length));
		file.seekg(0, std::ios::beg);
		return data.empty() || !!file.read(reinterpret_cast<char*>(data.data()), data.size());
	}

	static bool ReplaceBinaryFile(const std::filesystem::path& path,
		const std::vector<BYTE>& data)
	{
		auto temporary = path.parent_path() /
			(L".wsclib-" + std::to_wstring(GetCurrentProcessId()) + L".tmp");
		{
			std::ofstream output(temporary, std::ios::binary | std::ios::trunc);
			if (!output || (!data.empty() &&
				!output.write(reinterpret_cast<const char*>(data.data()), data.size()))) return false;
		}
		if (!ReplaceFileW(path.c_str(), temporary.c_str(), nullptr,
			REPLACEFILE_WRITE_THROUGH, nullptr, nullptr))
		{
			DeleteFileW(temporary.c_str());
			return false;
		}
		return true;
	}

	static std::wstring Expand(const wchar_t* value)
	{
		const DWORD required = ExpandEnvironmentStringsW(value, nullptr, 0);
		if (!required) return {};
		std::wstring result(required, L'\0');
		if (!ExpandEnvironmentStringsW(value, result.data(), required)) return {};
		result.resize(required - 1);
		return result;
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

	static bool ClearMuiCache(const std::vector<std::wstring>& needles)
	{
		return ClearRegistryValues(HKEY_CURRENT_USER, {
			L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
			L"Software\\Microsoft\\Windows\\ShellNoRoam\\MUICache" }, needles);
	}

	static bool ClearFeatureUsage(const std::vector<std::wstring>& needles)
	{
		const std::wstring rootPath =
			L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage";
		auto root = OpenKey(HKEY_CURRENT_USER, rootPath);
		if (root == INVALID_HANDLE_VALUE) return true;
		for (const auto& category : GetSubKeys(root))
		{
			auto key = OpenKey(root, category);
			if (key == INVALID_HANDLE_VALUE) continue;
			for (const auto& value : GetValueList(key))
			{
				if (MatchesAny(value.Name, needles) &&
					RegDeleteValueW(key, value.Name.c_str()) != ERROR_SUCCESS)
				{
					RegCloseKey(key); RegCloseKey(root); return false;
				}
			}
			RegCloseKey(key);
		}
		RegCloseKey(root);
		return true;
	}

	class TemporarySetValueAcl
	{
		HKEY Key = nullptr;
		PSECURITY_DESCRIPTOR Descriptor = nullptr;
		PACL OriginalDacl = nullptr;
		PACL TemporaryDacl = nullptr;

	public:
		TemporarySetValueAcl() = default;
		TemporarySetValueAcl(const TemporarySetValueAcl&) = delete;
		TemporarySetValueAcl& operator=(const TemporarySetValueAcl&) = delete;

		bool Grant(HKEY root, const std::wstring& path)
		{
			if (RegOpenKeyExW(root, path.c_str(), 0, READ_CONTROL | WRITE_DAC, &Key) != ERROR_SUCCESS)
				return false;

			if (GetSecurityInfo(Key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
				nullptr, nullptr, &OriginalDacl, nullptr, &Descriptor) != ERROR_SUCCESS ||
				!Descriptor || !OriginalDacl)
			{
				Reset(false);
				return false;
			}

			BYTE administratorsSid[SECURITY_MAX_SID_SIZE]{};
			DWORD sidSize = sizeof(administratorsSid);
			if (!CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr,
				administratorsSid, &sidSize))
			{
				Reset(false);
				return false;
			}

			EXPLICIT_ACCESSW access{};
			access.grfAccessPermissions = KEY_SET_VALUE;
			access.grfAccessMode = GRANT_ACCESS;
			access.grfInheritance = NO_INHERITANCE;
			access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
			access.Trustee.TrusteeType = TRUSTEE_IS_UNKNOWN;
			access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(administratorsSid);
			if (SetEntriesInAclW(1, &access, OriginalDacl, &TemporaryDacl) != ERROR_SUCCESS ||
				!TemporaryDacl || SetSecurityInfo(Key, SE_REGISTRY_KEY,
					DACL_SECURITY_INFORMATION, nullptr, nullptr, TemporaryDacl, nullptr) != ERROR_SUCCESS)
			{
				Reset(false);
				return false;
			}
			return true;
		}

		~TemporarySetValueAcl() { Reset(true); }

	private:
		void Reset(bool restore)
		{
			if (restore && Key && OriginalDacl)
				SetSecurityInfo(Key, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION,
					nullptr, nullptr, OriginalDacl, nullptr);
			if (TemporaryDacl) LocalFree(TemporaryDacl);
			if (Descriptor) LocalFree(Descriptor);
			if (Key) RegCloseKey(Key);
			Key = nullptr;
			Descriptor = nullptr;
			OriginalDacl = nullptr;
			TemporaryDacl = nullptr;
		}
	};

	static bool ClearBamSid(HKEY root, const std::wstring& path,
		const std::vector<std::wstring>& needles)
	{
		auto key = OpenKeyWithAccess(root, path, KEY_QUERY_VALUE | KEY_SET_VALUE);
		std::unique_ptr<TemporarySetValueAcl> temporaryAcl;
		if (key == INVALID_HANDLE_VALUE)
		{
			temporaryAcl = std::make_unique<TemporarySetValueAcl>();
			if (!temporaryAcl->Grant(root, path)) return false;
			key = OpenKeyWithAccess(root, path, KEY_QUERY_VALUE | KEY_SET_VALUE);
			if (key == INVALID_HANDLE_VALUE) return false;
		}
		for (const auto& value : GetValueList(key))
		{
			if (MatchesAny(value.Name, needles) &&
				RegDeleteValueW(key, value.Name.c_str()) != ERROR_SUCCESS)
			{
				RegCloseKey(key);
				return false;
			}
		}
		RegCloseKey(key);
		return true;
	}

	static bool ClearBam(const std::vector<std::wstring>& needles)
	{
		const std::vector<std::wstring> roots = {
			L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
			L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
			L"SYSTEM\\CurrentControlSet\\Services\\dam\\State\\UserSettings",
			L"SYSTEM\\CurrentControlSet\\Services\\dam\\UserSettings" };
		for (const auto& path : roots)
		{
			auto root = OpenKeyWithAccess(HKEY_LOCAL_MACHINE, path, KEY_READ);
			if (root == INVALID_HANDLE_VALUE) continue;
			for (const auto& sid : GetSubKeys(root))
			{
				if (!ClearBamSid(HKEY_LOCAL_MACHINE, path + L"\\" + sid, needles))
				{
					RegCloseKey(root);
					return false;
				}
			}
			RegCloseKey(root);
		}
		return true;
	}

	static bool FilterDelimitedFile(const std::filesystem::path& path,
		const std::vector<BYTE>& delimiter, const std::vector<std::wstring>& needles)
	{
		std::vector<BYTE> input;
		if (!ReadBinaryFile(path, input)) return !std::filesystem::exists(path);
		std::vector<BYTE> output;
		output.reserve(input.size());
		size_t start = 0;
		bool changed = false;
		while (start < input.size())
		{
			auto found = std::search(input.begin() + start, input.end(),
				delimiter.begin(), delimiter.end());
			const size_t end = static_cast<size_t>(found - input.begin());
			const size_t next = found == input.end() ? input.size() : end + delimiter.size();
			if (MatchesAny(input.data() + start, end - start, needles)) changed = true;
			else
			{
				output.insert(output.end(), input.begin() + start, input.begin() + end);
				if (found != input.end()) output.insert(output.end(), delimiter.begin(), delimiter.end());
			}
			start = next;
		}
		return !changed || ReplaceBinaryFile(path, output);
	}

	static bool ClearCompatibilityAssistant(const std::vector<std::wstring>& needles)
	{
		if (!ClearRegistryValues(HKEY_CURRENT_USER, {
			L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
			L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Persisted",
			L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers" }, needles)) return false;
		const auto root = Expand(L"%SystemRoot%");
		if (root.empty()) return false;
		const auto pca = std::filesystem::path(root) / L"appcompat" / L"pca";
		return FilterDelimitedFile(pca / L"PcaAppLaunchDic.txt", { '\r', '\n' }, needles) &&
			FilterDelimitedFile(pca / L"PcaGeneralDb0.txt", { '\n', 0 }, needles) &&
			FilterDelimitedFile(pca / L"PcaGeneralDb1.txt", { '\n', 0 }, needles);
	}

	static bool RemoveMruIndex(HKEY key, DWORD index)
	{
		DWORD type = 0, size = 0;
		if (RegQueryValueExW(key, L"MRUListEx", nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
			return true;
		if (type != REG_BINARY || size % sizeof(DWORD)) return false;
		std::vector<BYTE> data(size);
		if (RegQueryValueExW(key, L"MRUListEx", nullptr, &type, data.data(), &size) != ERROR_SUCCESS)
			return false;
		std::vector<BYTE> filtered;
		for (size_t i = 0; i < data.size(); i += sizeof(DWORD))
		{
			DWORD value = 0; std::memcpy(&value, data.data() + i, sizeof(value));
			if (value != index) filtered.insert(filtered.end(), data.begin() + i, data.begin() + i + sizeof(DWORD));
		}
		return RegSetValueExW(key, L"MRUListEx", 0, REG_BINARY,
			filtered.data(), static_cast<DWORD>(filtered.size())) == ERROR_SUCCESS;
	}

	static bool ClearShellBagKey(HKEY root, const std::vector<std::wstring>& needles, int depth)
	{
		if (depth > 64) return false;
		for (const auto& child : GetSubKeys(root))
		{
			auto key = OpenKey(root, child);
			if (key != INVALID_HANDLE_VALUE)
			{
				const bool ok = ClearShellBagKey(key, needles, depth + 1);
				RegCloseKey(key);
				if (!ok) return false;
			}
		}
		for (const auto& value : GetValueList(root))
		{
			wchar_t* end = nullptr;
			const auto index = wcstoul(value.Name.c_str(), &end, 10);
			if (!value.Name.empty() && end && *end == 0 &&
				MatchesAny(value.Data.data(), value.Data.size(), needles))
			{
				if (RegDeleteValueW(root, value.Name.c_str()) != ERROR_SUCCESS) return false;
				const auto treeResult = RegDeleteTreeW(root, value.Name.c_str());
				if (treeResult != ERROR_SUCCESS && treeResult != ERROR_FILE_NOT_FOUND) return false;
				if (!RemoveMruIndex(root, index)) return false;
			}
		}
		return true;
	}

	static bool ClearShellbags(const std::vector<std::wstring>& needles)
	{
		for (const auto& path : {
			L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
			L"Software\\Microsoft\\Windows\\Shell\\BagMRU" })
		{
			auto root = OpenKey(HKEY_CURRENT_USER, path);
			if (root == INVALID_HANDLE_VALUE) continue;
			const bool ok = ClearShellBagKey(root, needles, 0);
			RegCloseKey(root);
			if (!ok) return false;
		}
		return true;
	}

	// TypedPaths: paths typed into the Explorer address bar. Values are
	// Path1..Path26 (REG_SZ with the path); the order lives in the MRUList
	// REG_SZ, where PathN maps to the N-th letter. Only matching PathN
	// values are removed and their letter is repaired out of MRUList.
	static bool RemoveMruListLetter(HKEY key, wchar_t letter)
	{
		DWORD type = 0, size = 0;
		if (RegQueryValueExW(key, L"MRUList", nullptr, &type, nullptr, &size) != ERROR_SUCCESS)
			return true;
		if (type != REG_SZ || size < sizeof(wchar_t)) return false;
		std::wstring list(size / sizeof(wchar_t), L'\0');
		if (RegQueryValueExW(key, L"MRUList", nullptr, &type,
			reinterpret_cast<BYTE*>(list.data()), &size) != ERROR_SUCCESS)
			return false;
		list.resize(size / sizeof(wchar_t));
		std::wstring filtered;
		for (const wchar_t c : list)
			if (c != L'\0' && c != letter && c != std::towlower(letter) && c != std::towupper(letter))
				filtered.push_back(c);
		filtered.push_back(L'\0');
		return RegSetValueExW(key, L"MRUList", 0, REG_SZ,
			reinterpret_cast<const BYTE*>(filtered.c_str()),
			static_cast<DWORD>(filtered.size() * sizeof(wchar_t))) == ERROR_SUCCESS;
	}

	static bool ClearTypedPaths(const std::vector<std::wstring>& needles)
	{
		auto key = OpenKey(HKEY_CURRENT_USER,
			L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths");
		if (key == INVALID_HANDLE_VALUE) return true;
		for (const auto& value : GetValueList(key))
		{
			if (value.Name.rfind(L"Path", 0) != 0) continue;
			wchar_t* end = nullptr;
			const auto index = wcstoul(value.Name.c_str() + 4, &end, 10);
			if (!end || *end != 0 || index == 0) continue;
			if (!MatchesAny(value.Data.data(), value.Data.size(), needles)) continue;
			if (RegDeleteValueW(key, value.Name.c_str()) != ERROR_SUCCESS)
			{
				RegCloseKey(key);
				return false;
			}
			if (!RemoveMruListLetter(key, wchar_t(L'a' + (index - 1) % 26)))
			{
				RegCloseKey(key);
				return false;
			}
		}
		RegCloseKey(key);
		return true;
	}

	// Common dialog MRUs: OpenSavePidlMRU keeps the last files chosen through
	// GetOpenFileName/GetSaveFileName per executable, and LastVisitedPidlMRU
	// the last folder per executable. Values are MRUItemN blobs (pidl with the
	// path embedded as UTF-16) ordered by MRUListEx. A subkey named like one
	// of the needles belongs to the application and goes away whole; foreign
	// subkeys only lose the matching MRUItemN values, repairing MRUListEx.
	static bool ClearCommonDialogsMruKey(HKEY root, const std::vector<std::wstring>& needles)
	{
		for (const auto& child : GetSubKeys(root))
		{
			if (MatchesAny(child, needles))
			{
				if (RegDeleteTreeW(root, child.c_str()) != ERROR_SUCCESS) return false;
				continue;
			}
			auto key = OpenKey(root, child);
			if (key == INVALID_HANDLE_VALUE) continue;
			for (const auto& value : GetValueList(key))
			{
				if (value.Name.rfind(L"MRUItem", 0) != 0) continue;
				wchar_t* end = nullptr;
				const auto index = wcstoul(value.Name.c_str() + 7, &end, 10);
				if (!end || *end != 0) continue;
				if (!MatchesAny(value.Data.data(), value.Data.size(), needles)) continue;
				if (RegDeleteValueW(key, value.Name.c_str()) != ERROR_SUCCESS)
				{
					RegCloseKey(key);
					return false;
				}
				if (!RemoveMruIndex(key, index))
				{
					RegCloseKey(key);
					return false;
				}
			}
			RegCloseKey(key);
		}
		return true;
	}

	static bool ClearCommonDialogsMru(const std::vector<std::wstring>& needles)
	{
		for (const auto& path : {
			L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU",
			L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU" })
		{
			auto root = OpenKey(HKEY_CURRENT_USER, path);
			if (root == INVALID_HANDLE_VALUE) continue;
			const bool ok = ClearCommonDialogsMruKey(root, needles);
			RegCloseKey(root);
			if (!ok) return false;
		}
		return true;
	}

	static uint16_t U16(const BYTE* p) { uint16_t value; std::memcpy(&value, p, 2); return value; }
	static uint32_t U32(const BYTE* p) { uint32_t value; std::memcpy(&value, p, 4); return value; }

	struct NvidiaRecentApp
	{
		uint16_t Type = 0;
		std::wstring Identifier;
		int64_t LastRun = 0;
	};

	template <typename T>
	static bool ReadNvidiaField(const std::vector<BYTE>& input, size_t& cursor, T& value)
	{
		if (cursor > input.size() || sizeof(value) > input.size() - cursor) return false;
		std::memcpy(&value, input.data() + cursor, sizeof(value));
		cursor += sizeof(value);
		return true;
	}

	static bool ReadNvidiaRecentApp(const std::vector<BYTE>& input, size_t& cursor,
		NvidiaRecentApp& app)
	{
		uint16_t identifierBytes = 0;
		if (!ReadNvidiaField(input, cursor, app.Type) ||
			!ReadNvidiaField(input, cursor, identifierBytes)) return false;
		if ((app.Type != 1 && app.Type != 2) || identifierBytes < sizeof(wchar_t) ||
			identifierBytes % sizeof(wchar_t) || cursor > input.size() ||
			identifierBytes > input.size() - cursor)
			return false;

		const auto characterCount = identifierBytes / sizeof(wchar_t);
		app.Identifier.resize(characterCount);
		std::memcpy(app.Identifier.data(), input.data() + cursor, identifierBytes);
		cursor += identifierBytes;
		if (app.Identifier.back() != L'\0') return false;
		app.Identifier.pop_back();
		return ReadNvidiaField(input, cursor, app.LastRun);
	}

	static bool ClearNvidiaRecent(const std::vector<std::wstring>& needles)
	{
		const auto programData = Expand(L"%ProgramData%");
		if (programData.empty()) return false;
		const auto path = std::filesystem::path(programData) / L"NVIDIA Corporation" / L"Drs" / L"nvAppTimestamps";
		std::vector<BYTE> input;
		if (!ReadBinaryFile(path, input)) return !std::filesystem::exists(path);
		if (input.size() < 2 || U16(input.data()) != 1) return false;
		std::vector<BYTE> output(input.begin(), input.begin() + 2);
		size_t cursor = 2; bool changed = false;
		while (cursor < input.size())
		{
			if (std::all_of(input.begin() + cursor, input.end(), [](BYTE b) { return b == 0; }))
			{ output.insert(output.end(), input.begin() + cursor, input.end()); break; }

			const auto recordStart = cursor;
			NvidiaRecentApp app;
			if (!ReadNvidiaRecentApp(input, cursor, app)) return false;
			if (MatchesAny(app.Identifier, needles)) changed = true;
			else output.insert(output.end(), input.begin() + recordStart, input.begin() + cursor);
		}
		if (!changed) return true;
		output.resize(input.size(), 0);
		return ReplaceBinaryFile(path, output);
	}

	static bool ClearShimcache(const std::vector<std::wstring>& needles)
	{
		auto key = OpenKey(HKEY_LOCAL_MACHINE,
			L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache");
		if (key == INVALID_HANDLE_VALUE) return true;
		DWORD type = 0, size = 0;
		if (RegQueryValueExW(key, L"AppCompatCache", nullptr, &type, nullptr, &size) != ERROR_SUCCESS ||
			type != REG_BINARY || size > 16 * 1024 * 1024) { RegCloseKey(key); return false; }
		std::vector<BYTE> input(size);
		if (RegQueryValueExW(key, L"AppCompatCache", nullptr, &type, input.data(), &size) != ERROR_SUCCESS)
		{ RegCloseKey(key); return false; }
		if (input.size() < 0x30) { RegCloseKey(key); return false; }
		const auto header = U32(input.data());
		if ((header != 0x30 && header != 0x34) || input.size() < header) { RegCloseKey(key); return false; }
		// The DWORD at header - 12 is not a reliable live-record count on
		// current Windows 11 builds. Preserve the complete header byte-for-byte
		// and validate consecutive 10ts records until the end of the blob.
		std::vector<BYTE> output(input.begin(), input.begin() + header);
		size_t offset = header; bool changed = false;
		while (offset < input.size())
		{
			if (input.size() - offset < 14 || std::memcmp(input.data() + offset, "10ts", 4))
			{ RegCloseKey(key); return false; }
			const auto payload = U32(input.data() + offset + 8);
			const size_t end = offset + 12ULL + payload;
			const auto pathBytes = U16(input.data() + offset + 12);
			if (end > input.size() || pathBytes % 2 || 14ULL + pathBytes > 12ULL + payload)
			{ RegCloseKey(key); return false; }
			if (MatchesAny(input.data() + offset + 14, pathBytes, needles)) changed = true;
			else output.insert(output.end(), input.begin() + offset, input.begin() + end);
			offset = end;
		}
		if (!changed) { RegCloseKey(key); return true; }
		const bool ok = RegSetValueExW(key, L"AppCompatCache", 0, REG_BINARY,
			output.data(), static_cast<DWORD>(output.size())) == ERROR_SUCCESS;
		if (ok) RegFlushKey(key);
		RegCloseKey(key);
		return ok;
	}

	static bool ClearWer(const std::vector<std::wstring>& needles)
	{
		for (const auto variable : { L"LOCALAPPDATA", L"ProgramData" })
		{
			wchar_t base[MAX_PATH]{};
			const auto length = GetEnvironmentVariableW(variable, base, MAX_PATH);
			if (!length || length >= MAX_PATH) continue;
			const auto root = std::filesystem::path(base) /
				L"Microsoft" / L"Windows" / L"WER";
			for (const auto reportRoot : { L"ReportQueue", L"ReportArchive", L"ReportStore" })
			{
				const auto directory = root / reportRoot;
				std::error_code error;
				std::filesystem::directory_iterator entries(directory, error);
				if (error) continue;
				for (const auto& entry : entries)
				{
					if (!MatchesAny(entry.path().filename().wstring(), needles)) continue;
					std::filesystem::remove_all(entry.path(), error);
					if (error) return false;
				}
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
		std::vector<std::wstring> needles = { FilePath };
		if (FileName.length() >= 6) needles.push_back(FileName);
		if (ParentFolderName.length() >= 6) needles.push_back(ParentFolderName);

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

		if (!ClearTypedPaths(needles)) {
			std::cout << "Error clearing TypedPaths" << std::endl;
			return false;
		}

		if (!ClearCommonDialogsMru(needles)) {
			std::cout << "Error clearing common dialogs MRU" << std::endl;
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

		if (!ClearMuiCache(needles)) {
			std::cout << "Error clearing MuiCache" << std::endl;
			return false;
		}

		if (!ClearFeatureUsage(needles)) {
			std::cout << "Error clearing FeatureUsage" << std::endl;
			return false;
		}

		if (!ClearBam(needles)) {
			std::cout << "Error clearing BAM/DAM" << std::endl;
			return false;
		}

		if (!ClearCompatibilityAssistant(needles)) {
			std::cout << "Error clearing Compatibility Assistant" << std::endl;
			return false;
		}

		if (!ClearShellbags(needles)) {
			std::cout << "Error clearing Shellbags" << std::endl;
			return false;
		}

		if (!ClearNvidiaRecent(needles)) {
			std::cout << "Error clearing NVIDIA recent programs" << std::endl;
			return false;
		}

		if (!ClearShimcache(needles)) {
			std::cout << "Error clearing Shimcache" << std::endl;
			return false;
		}

		if (!ClearWer(needles)) {
			std::cout << "Error clearing Windows Error Reporting" << std::endl;
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
