#include <stdio.h>
#include <Windows.h>

//const WCHAR* FILE_NAME = L"C:\\Program Files\\HxD\\HxD.exe";
const WCHAR* FILE_NAME = L"C:\\Windows\\System32\\notepad.exe";

#define RvaToVa(Base, Offset) ((PVOID)((ULONG64)Base + (ULONG)Offset))

int main() {
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    LPVOID pMapImage = NULL;
    PIMAGE_NT_HEADERS pNT_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    DWORD* NumberOfRvaAndSize = NULL;
    LONG e_lfanew;
    WORD check_MZ = 0;

    hFile = CreateFile(FILE_NAME, FILE_READ_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: cannot open file!\n");
        return (-1);
    }
    else {
        fprintf(stdout, "Info: file \"%ws\" was open;\n", FILE_NAME);
    }

    fprintf(stdout, "\nIMAGE_DOS_HEADER\n");
    SetFilePointer(hFile, 0, 0, FILE_BEGIN);
    if (ReadFile(hFile, &check_MZ, 0x02, NULL, NULL)) {
        if (check_MZ == IMAGE_DOS_SIGNATURE) {
            fprintf(stdout, "\te_magic:  MZ\n");
        }
        else {
            fprintf(stderr, "\tError: File format is not PE\n");
            return (-3);
        }
    }
    else {
        fprintf(stderr, "Error: ReadFile() return FALSE;");
        return (-2);
    }


    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMap == NULL) {
        fprintf(stderr, "Error: cannot map \"%ws\"", FILE_NAME);
        CloseHandle(hFile);
        return (-4);
    }

    pMapImage = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (pMapImage == NULL) {
        fprintf(stderr, "Error: cannot create view of file\n");
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-5);
    }

    // _IMAGE_DOS_HEADER
    if (*(BYTE*)((ULONG64)pMapImage + 0x18) < 0x40) {
        fprintf(stderr, "\tError: e_lfarlc less then 40h\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-6);
    }
    else {
        fprintf(stdout, "\te_lfarlc: %X\n", *(BYTE*)((ULONG64)pMapImage + 0x18));
    }

    e_lfanew = *(LONG*)((ULONG64)pMapImage + 0x3C);
    fprintf(stdout, "\te_lfanew: %X\n", e_lfanew);

    //PIMAGE_NT_HEADERS64
    fprintf(stdout, "IMAGE_NT_HEADER\n");
    pNT_HEADER = (PIMAGE_NT_HEADERS)((ULONG64)pMapImage + e_lfanew);
    if (*(DWORD*)(pNT_HEADER) != IMAGE_NT_SIGNATURE){
        fprintf(stderr, "\tSignature: \"PE\" not found\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-7);
    }
    else {
        fprintf(stdout, "\tSignature: \"%s\"\n", (PCHAR)(pNT_HEADER));
        
    }

    fprintf(stdout, "\n\tIMAGE_FILE_HEADER\n");
    switch (*(WORD*)((ULONG64)pNT_HEADER + 0x04)) {
    default: {
        fprintf(stdout, "\t\tMachine: unknown or not added;\n");
        break;
    }
    case IMAGE_FILE_MACHINE_I386: {
        fprintf(stdout, "\t\tMachine: - x86\n");
        break;
    }
    case IMAGE_FILE_MACHINE_IA64: {
        fprintf(stdout, "\t\tMachine: Intel Itanium\n");
        break;
    }
    case IMAGE_FILE_MACHINE_AMD64: {
        fprintf(stdout, "\t\tMachine: x64\n");
        break;
    }
    }

    if (*(WORD*)((ULONG64)pNT_HEADER + 0x06) >= 0x60) {
        fprintf(stderr, "\t\tNumberOfSections: incorrect value\n");
        return(-7);
    }
    else {
        fprintf(stdout, "\t\tNumberOfSections: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x06));
    }

    fprintf(stdout, "\t\tSizeOfOptionalHeader: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x14));
    fprintf(stdout, "\t\tCharacteristics: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x16));

    fprintf(stdout, "\n\tIMAGE_OPTIONAL_HEADER\n");
    if (*(WORD*)((ULONG64)pNT_HEADER + 0x18) != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fprintf(stderr, "\t\tMagic: Application is not 64-bit;\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-8);
    }
    else {
        fprintf(stdout, "\t\tMagic: x64\n");
    }

    if (*(DWORD*)((ULONG64)pNT_HEADER + 0x28) <= 0) {
        fprintf(stderr, "\t\tAddressOfEntryPoint: incorrect value\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-9);
    }
    else {
        fprintf(stdout, "\t\tAddressOfEntryPoint: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x28));
    }

    fprintf(stdout, "\t\tImageBase: %016llX\n", *(ULONGLONG*)((ULONG64)pNT_HEADER + 0x30));
    fprintf(stdout, "\t\tSectionAligment: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x38));
    fprintf(stdout, "\t\tFileAligment: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x3C));
    fprintf(stdout, "\t\tMajorSybsystemVersion: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x48));
    fprintf(stdout, "\t\tSizeOfImage: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x50));
    fprintf(stdout, "\t\tSizeOfHeaders: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x54));
    fprintf(stdout, "\t\tSubsystem: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x5C));
    NumberOfRvaAndSize = (DWORD*)((ULONG64)pNT_HEADER + 0x84);
    fprintf(stdout, "\t\tNumberOfRvaAndSize: %08X\n", *NumberOfRvaAndSize);

    fprintf(stdout, "\n\t\tIMAGE_DATA_DIRECTORY\n");
    pDataDirectory = (PIMAGE_DATA_DIRECTORY)((ULONG64)pNT_HEADER + 0x88);
    for (UINT i = 0; i < *NumberOfRvaAndSize; i++) {
        if (pDataDirectory[i].VirtualAddress == 0) {
            continue;
        }
        else {
            fprintf(stdout, "\t\tDirectory %d\n", (i+1));
            fprintf(stdout, "\t\t RVA:  %08X\n", pDataDirectory[i].VirtualAddress);
            fprintf(stdout, "\t\t Size: %08X\n", pDataDirectory[i].Size);
        }
    }

    return 0;
}
