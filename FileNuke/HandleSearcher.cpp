#include "stdafx.h"
#include "HandleSearcher.h"

int searchHandle(HANDLE processHandle,char *filePath,DWORD PID){
	// Resolve ntdll functions
	HMODULE ntdllMod = GetModuleHandleA("ntdll.dll");
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdllMod, "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(ntdllMod, "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(ntdllMod, "NtQueryObject");
	if (!NtQueryObject || !NtDuplicateObject || !NtQuerySystemInformation) {
		std::cout << "Failed to resolve ntdll.dll functions" << std::endl;
		return -1;
	}

	NTSTATUS status;
	PSYSTEM_HANDLE_INFORMATION handleInfo;
	ULONG handleInfoSize = 0x10000;
	int retVal = -2;

	handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

	// NtQuerySystemInformation doesn't give required buffer size so keep increasing until there is enough space
	while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH) {
		handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
	}

	if (!NT_SUCCESS(status))
	{
		free(handleInfo);
		return -1;
	}
	// Iterate the handles of the process
	DWORD written;
	for (DWORD i = 0; i < handleInfo->HandleCount; i++)
	{
		SYSTEM_HANDLE handle = handleInfo->Handles[i];
		HANDLE dupHandle = NULL;
		POBJECT_TYPE_INFORMATION objectTypeInfo;
		PVOID objectNameInfo;
		UNICODE_STRING objectName;
		ULONG returnLength;

		// Check that the handle belongs to the queried process
		if (handle.ProcessId != PID)
			continue;

		// Duplicate handle so we can process the information
		if ((NtDuplicateObject(
			processHandle,
			(HANDLE)handle.Handle,
			GetCurrentProcess(),
			&dupHandle,
			0,
			0,
			0
			)))
		{
			// Failed to duplicate handle so skip it
			continue;
		}
		// Query type of the handle
		objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(
			dupHandle,
			ObjectTypeInformation,
			objectTypeInfo,
			0x1000,
			NULL
			)))
		{
			free(objectTypeInfo);
			continue;
		}
		/* Query the object name (unless it has an access of
		0x0012019f, on which NtQueryObject could hang. */
		if (handle.GrantedAccess == 0x0012019f)
		{
			free(objectTypeInfo);
			CloseHandle(dupHandle);
			continue;
		}

		// Query name information of the handle
		objectNameInfo = malloc(0x1000);
		if (!NT_SUCCESS(NtQueryObject(dupHandle,ObjectNameInformation,objectNameInfo,0x1000,&returnLength))) {
			// Reallocate the buffer with enough space
			objectNameInfo = realloc(objectNameInfo, returnLength);
			if (!NT_SUCCESS(NtQueryObject(
				dupHandle,
				ObjectNameInformation,
				objectNameInfo,
				returnLength,
				NULL
				)))
			{
				// Still failed to query the object, skip
				free(objectTypeInfo);
				free(objectNameInfo);
				CloseHandle(dupHandle);
				continue;
			}
		}
		// Process the handle name
		objectName = *(PUNICODE_STRING)objectNameInfo;
		if (objectName.Length)
		{
			// We are only interested in file handles
			if (lstrcmpW(objectTypeInfo->Name.Buffer, L"File") == 0) {
				char realName[MAX_PATH];
				int size_needed = WideCharToMultiByte(CP_UTF8, 0, objectName.Buffer, objectName.Length, realName, sizeof(realName), NULL, NULL);
				// Check if file names match
				if (_strnicmp(realName, filePath, sizeof(realName)) == 0) {
					CloseHandle(dupHandle);
					// Process holds open file handle to a file free are trying to free
					// Remote file handle can be closed with NtDuplicateObject with DUPLICATE_CLOSE_SOURCE
					dupHandle = 0;
					if (NtDuplicateObject(processHandle, (HANDLE)handle.Handle, NULL, NULL, 0, 0, DUPLICATE_CLOSE_SOURCE)) {
						retVal = 0;
					}
					else if (retVal != 0) {
						retVal = 1;
					}
				}
			}
		}
		// Free allocations
		free(objectTypeInfo);
		free(objectNameInfo);
		if(dupHandle)
			CloseHandle(dupHandle);
	}
	free(handleInfo);
	return retVal;
}