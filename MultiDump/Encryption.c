#include <Windows.h>
#include <stdio.h>

#include "Common.h"
#include "Debug.h"

BOOL Rc4EncryptionViaSystemFunc032(IN PBYTE pRc4Key, IN PBYTE pData, IN DWORD dwRc4KeySize, IN DWORD sDataSize) {

	NTSTATUS	STATUS = NULL;

	USTRING		Key = { .Buffer = pRc4Key, 	.Length = dwRc4KeySize,	.MaximumLength = dwRc4KeySize },
				Img = { .Buffer = pData,	.Length = sDataSize,	.MaximumLength = sDataSize };

	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
#ifdef DEBUG
		printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
#endif // DEBUG
		return FALSE;

	}

	return TRUE;
}

// generate random bytes of size "sSize"
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {

	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}

}

VOID PrintKey(const unsigned char* byteArray, SIZE_T size) {
	printf("[i] Key: ");
	for (size_t i = 0; i < size; i++) {
		printf("%02x", byteArray[i]);
	}
	printf("\n");
}

VOID GenerateFileName(char *str, int length) {
    const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";
    int alphabetLength = sizeof(alphabet) - 1; // Exclude the null terminator

    for (int i = 0; i < length; i++) {
        int key = rand() % alphabetLength;
        str[i] = alphabet[key];
    }

    str[length] = '\0'; // Null-terminate the string
}