#include "stdafx.h"
#include "HandleSearcher.h"

int ForceDelete(std::string& file) {
	NTSTATUS status;
	wchar_t* full_path = (wchar_t*)malloc(1024 * sizeof(wchar_t));
	wchar_t* file_name_uni = (wchar_t*)malloc(1024 * sizeof(wchar_t));

	int wchars_num = MultiByteToWideChar(CP_UTF8, 0, file.c_str(), -1, NULL, 0);
	MultiByteToWideChar(CP_UTF8, 0, file.c_str(), -1, file_name_uni, wchars_num);

	UNICODE_STRING NtPath;
	OBJECT_ATTRIBUTES ObjectAttributes;

	// Resolve ntdll functions
	HMODULE ntdllMod = GetModuleHandleA("ntdll.dll");
	_NtDeleteFile NtDeleteFile = (_NtDeleteFile)GetProcAddress(ntdllMod, "NtDeleteFile");
	RtlDosPathNameToNtPathName_U_t RtlDosPathNameToNtPathName_U = (RtlDosPathNameToNtPathName_U_t)GetProcAddress(ntdllMod, "RtlDosPathNameToNtPathName_U");
	_RtlFreeUnicodeString RtlFreeUnicodeString = (_RtlFreeUnicodeString)GetProcAddress(ntdllMod, "RtlFreeUnicodeString");
	if (!NtDeleteFile || !RtlDosPathNameToNtPathName_U || !RtlFreeUnicodeString) {
		std::cout << "Failed to resolve ntdll functions" << std::endl;
		free(full_path);
		free(file_name_uni);
		return 0;
	}

	if (!SearchPathW(NULL, file_name_uni, NULL, 1024, full_path, NULL))
	{
		free(full_path);
		free(file_name_uni);
		return 0;
	}

	if (!RtlDosPathNameToNtPathName_U(full_path, &NtPath, NULL, NULL))
	{
		free(full_path);
		free(file_name_uni);
		return 0;
	}

	InitializeObjectAttributes(&ObjectAttributes, &NtPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = NtDeleteFile(&ObjectAttributes);

	RtlFreeUnicodeString(&NtPath);
	return NT_SUCCESS(status);
}

DWORD ScanForModule(HANDLE hProcess, std::string& modulePath)
{
	MEMORY_BASIC_INFORMATION mbi;
	HMODULE ntdllMod = GetModuleHandleA("ntdll.dll");
	_NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)GetProcAddress(ntdllMod, "NtUnmapViewOfSection");
	SYSTEM_INFO msi;
	ZeroMemory(&mbi, sizeof(mbi));
	GetSystemInfo(&msi);
	int ret = 1;
	for (LPBYTE lpAddress = (LPBYTE)msi.lpMinimumApplicationAddress; lpAddress <= (LPBYTE)msi.lpMaximumApplicationAddress; lpAddress += mbi.RegionSize) {
		if (VirtualQueryEx(hProcess, lpAddress, &mbi, sizeof(mbi))) {
			if (mbi.Type & MEM_MAPPED || mbi.Type & MEM_IMAGE) {
				char name[256];
				if (K32GetMappedFileNameA(hProcess, (LPBYTE)mbi.BaseAddress, name, sizeof(name))) {
					std::string mappedFileName(name);
					/*if(mappedFileName.compare(name) == 0) {
						if (NT_SUCCESS(NtUnmapViewOfSection(hProcess, (LPBYTE)mbi.BaseAddress))) {
							return 2;
						}
						else {
							return 0;
						}
					}*/
				}
			}
		}
		else break;
	}
	return 1;
}

BOOL DoProcessScan(std::string& filePath, BOOL killIt) {
	HANDLE hProcessSnap;
	PROCESSENTRY32 pe32;

	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		return(FALSE);
	}

	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);

	// Retrieve information about the first process,
	// and exit if unsuccessful
	if (!Process32First(hProcessSnap, &pe32))
	{
		CloseHandle(hProcessSnap);          // clean the snapshot object
		return(FALSE);
	}

	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

		//int ret = 0;
		if (h) {
			//Mapped file scan
			int success = ScanForModule(h, filePath);
			if (success == 2) {
				printf("Unmapped from : %d\n", pe32.th32ProcessID);
			}
			else if (success == 0) {
				printf("Failed to unmap from : %d\n", pe32.th32ProcessID);
				CloseHandle(h);
				break;
			}
			//File handle scan
			int retVal = searchHandle(h, (char*)filePath.c_str(), pe32.th32ProcessID);
			if (retVal == 1) {
				printf("Closed handles in %d\n", pe32.th32ProcessID);
				CloseHandle(h);
				break;
			}
			else if (retVal == 0) {
				printf("Failed to close handles in %d\n", pe32.th32ProcessID);
				CloseHandle(h);
				break;
			}
			CloseHandle(h);
		}

	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return TRUE;
}

int HandleFile(std::string path, BOOL killIt, BOOL deleteIt) {
	int ret = 1;
	char dosPath[MAX_PATH];
	QueryDosDeviceA(path.substr(0,2).c_str(), dosPath, sizeof(dosPath));
	std::string dosPathStr(dosPath);
	dosPathStr += "\\" + path.substr(3);
	if (DoProcessScan(dosPathStr, killIt)) {
		if (ForceDelete(path)) {
			printf("Deleted successfully %s\n", path.c_str());
			ret = 1;
		}
		else {
			printf("Failed to delete %s\n", path.c_str());
			ret = 0;
		}
	}
	return ret;
}

BOOL EnableDebugPrivileges(void)
{
	HANDLE token;
	TOKEN_PRIVILEGES priv;
	BOOL ret = FALSE;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
	{
		priv.PrivilegeCount = 1;
		priv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValueA(NULL, SE_DEBUG_NAME, &priv.Privileges[0].Luid) != FALSE &&
			AdjustTokenPrivileges(token, FALSE, &priv, 0, NULL, NULL) != FALSE)
		{
			ret = TRUE;
		}
		CloseHandle(token);
	}
	return ret;
}

int main(int argc, char* argv[])
{
	if (argc <= 1) {
		return 0;
	}
	HandleFile(argv[1], FALSE, FALSE);
	getchar();
    return 0;
}