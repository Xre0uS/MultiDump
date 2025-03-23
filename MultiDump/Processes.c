#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>

#include "Common.h"
#include "Debug.h"

// https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/thread.htm?ts=0,313
#define STATUS_SUCCESS              0x00000000
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

#define MAX_THREADS					64

BOOL GetRemoteProcessInfo(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {
	fnNtQuerySystemInformation   pNtQuerySystemInformation = NULL;
	ULONG                        uReturnLen1 = NULL, uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION  SystemProcInfo = NULL;
	NTSTATUS                     STATUS = NULL;
	PVOID                        pValueToFree = NULL;

	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
#ifdef DEBUG
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

	pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

	SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
	if (SystemProcInfo == NULL) {
#ifdef DEBUG
		printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

	pValueToFree = SystemProcInfo;

	STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
	if (STATUS != 0x0) {
#ifdef DEBUG
		printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		HeapFree(GetProcessHeap(), 0, pValueToFree);
		return FALSE;
	}

	while (TRUE) {
		// Comparing the enumerated process name to the intended target process
		if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {
			*pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;

			if (phProcess != NULL) { // Only open a handle if phProcess is not NULL
				*phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
			}
			break;
		}

		if (!SystemProcInfo->NextEntryOffset) {
			break;
		}

		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	HeapFree(GetProcessHeap(), 0, pValueToFree);

	if (*pdwPid == NULL)
		return FALSE;
	else
		return TRUE;
}

DWORD* GetRemoteProcessSuspendedThreads(IN LPCWSTR szProcName, OUT DWORD* threadCount) {

	fnNtQuerySystemInformation		pNtQuerySystemInformation = NULL;
	ULONG							uReturnLen1 = NULL,
									uReturnLen2 = NULL;
	PSYSTEM_PROCESS_INFORMATION		SystemProcInfo = NULL,
									pOriginalSystemProcInfo = NULL;
	PSYSTEM_THREAD_INFORMATION      SystemThreadInfo = NULL;
	PVOID							pValueToFree = NULL;
	NTSTATUS						STATUS = NULL;
	*threadCount = 0;

	DWORD* suspendedThreadIds = (DWORD*)malloc(MAX_THREADS * sizeof(DWORD));

	// Fetching NtQuerySystemInformation's address from ntdll.dll
	pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
	if (pNtQuerySystemInformation == NULL) {
#ifdef DEBUG
		printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
#endif // DEBUG
		goto _EndOfFunc;
	}

	// First NtQuerySystemInformation call - retrieve the size of the return buffer (uReturnLen1)
	if ((STATUS = pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1)) != STATUS_SUCCESS && STATUS != STATUS_INFO_LENGTH_MISMATCH) {
#ifdef DEBUG
		printf("[!] NtQuerySystemInformation [1] Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		goto _EndOfFunc;
	}

	while (TRUE) {
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, uReturnLen1);
		if (SystemProcInfo == NULL) {
#ifdef DEBUG
			printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
#endif // DEBUG
			return;
		}

		STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
		if (STATUS == STATUS_SUCCESS) {
			break; // Success, break from the loop
		}
		else if (STATUS == STATUS_INFO_LENGTH_MISMATCH) {
			// Buffer was too small, free it and try again with a larger size
			HeapFree(GetProcessHeap(), 0, SystemProcInfo);
			uReturnLen1 = uReturnLen2; // Use the returned size for the next attempt
		}
		else {
#ifdef DEBUG
			printf("[!] NtQuerySystemInformation [2] Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
			HeapFree(GetProcessHeap(), 0, SystemProcInfo);
			goto _EndOfFunc;
		}
	}
	pOriginalSystemProcInfo = SystemProcInfo;  // Keep original pointer

	// Enumerating SystemProcInfo, looking for process "szProcName"
	while (TRUE) {

		// Searching for thr process name
		if (SystemProcInfo->ImageName.Length && wcsncmp(SystemProcInfo->ImageName.Buffer, szProcName, SystemProcInfo->ImageName.Length / sizeof(WCHAR)) == 0) {
			// Enumerate threads of the found process
			for (ULONG i = 0; i < SystemProcInfo->NumberOfThreads; i++) {
				PSYSTEM_THREAD_INFORMATION SystemThreadInfo = &SystemProcInfo->Threads[i];
				if (SystemThreadInfo->ThreadState == 5 && SystemThreadInfo->WaitReason == 5) { // Both ThreadState and WaitReason are 5
					if (*threadCount < MAX_THREADS) {
						suspendedThreadIds[*threadCount] = (DWORD)SystemThreadInfo->ClientId.UniqueThread;
						(*threadCount)++;
					}
				}
			}
			// Break from while
			break;
		}

		// If we reached the end of the SYSTEM_PROCESS_INFORMATION structure
		if (!SystemProcInfo->NextEntryOffset)
			break;

		// Calculate the next SYSTEM_PROCESS_INFORMATION element in the array
		SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
	}

	free(pOriginalSystemProcInfo); // Free the buffer allocated for system process information

	if (*threadCount == 0) { // No matching threads found, clean up
		goto _EndOfFunc;
	}

	return suspendedThreadIds; // Return the array of matching thread IDs

	// Free the SYSTEM_PROCESS_INFORMATION structure
_EndOfFunc:
	free(suspendedThreadIds);
	if (pValueToFree)
		HeapFree(GetProcessHeap(), 0, pValueToFree);
	return NULL;
}


VOID ResumeThreads(DWORD* threadIDs, DWORD threadCount, BOOL verboseMode) {
	if (threadIDs == NULL || threadCount == 0) {
#ifdef DEBUG
		printf("No threads to resume.\n");
#endif // DEBUG
		return;
	}

	for (DWORD i = 0; i < threadCount; ++i) {
		HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, threadIDs[i]);
		if (hThread == NULL) {
#ifdef DEBUG
			printf("Failed to open thread %lu: %lu\n", threadIDs[i], GetLastError());
#endif // DEBUG
			continue;
		}

		// Resume the thread
		DWORD suspendCount = 0;
		do {
			suspendCount = ResumeThread(hThread);
			if (suspendCount == (DWORD)-1) {
#ifdef DEBUG
				printf("Failed to resume thread %lu: %lu\n", threadIDs[i], GetLastError());
#endif // DEBUG
				break; // If failed, break the loop
			}
		} while (suspendCount > 1); // Ensure the thread is fully resumed

		if (suspendCount == 1 || suspendCount == 0) {
#ifdef DEBUG
			if (verboseMode) {
				printf("[i]Thread %lu resumed successfully.\n", threadIDs[i]);
			}
#endif // DEBUG
		}
		CloseHandle(hThread);
	}
}