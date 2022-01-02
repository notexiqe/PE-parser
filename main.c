#include <stdio.h>
#include <Windows.h>

//const WCHAR* FILE_NAME = L"C:\\Program Files\\HxD\\HxD.exe";
const WCHAR* FILE_NAME = L"C:\\Windows\\System32\\notepad.exe";

int main() {
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    LPVOID pMapImage = NULL;
    WORD check_MZ;

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
            fprintf(stdout, "\te_magic: \"MZ\"\n");
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
        return (-6);
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
    }
    else {
        fprintf(stdout, "\te_lfarlc: %x\n", *(BYTE*)((ULONG64)pMapImage + 0x18));
    }

    fprintf(stdout, "\te_lfanew: %x\n", *(LONG*)((ULONG64)pMapImage + 0x3C));

    //PIMAGE_NT_HEADERS64
    fprintf(stdout, "IMAGE_NT_HEADER\n");
    if (*(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C)) == IMAGE_NT_SIGNATURE) {
        fprintf(stdout, "\tSignature: \"%s\"\n", (char*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C)));
    }
    else {
        fprintf(stderr, "\tSignature: \"PE\" not found\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-6);
    }

    fprintf(stdout, "\n\tIMAGE_FILE_HEADER\n");

    switch (*(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3c) + 0x04)) {
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

    if (*(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x06) < 0x60) {
        fprintf(stdout, "\t\tNumberOfSections: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x06));
    }
    else {
        fprintf(stderr, "\t\tNumberOfSections: incorrect value\n");
        return(-7);
    }

    fprintf(stdout, "\t\tTimeDateStamp: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x08));
    fprintf(stdout, "\t\tPointerToSymbolTable: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0xC));
    fprintf(stdout, "\t\tNumberOfSymbols: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x10));
    fprintf(stdout, "\t\tSizeOfOptionalHeader: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x14));
    fprintf(stdout, "\t\tCharacteristics: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x16));
    fprintf(stdout, "\n\tIMAGE_OPTIONAL_HEADER\n");
    if (*(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x18) == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        fprintf(stdout, "\t\tMagic: x64\n");
    }
    else {
        fprintf(stderr, "\t\tMagic: Application is not 64-bit;\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-8);
    }

    fprintf(stdout, "\t\tMajorLinkerVersion: %02x\n", *(BYTE*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x1A));
    fprintf(stdout, "\t\tMinorLinkerVersion: %02x\n", *(BYTE*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x1B));
    fprintf(stdout, "\t\tSizeOfCode: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x1C));
    fprintf(stdout, "\t\tSizeOfInitializedData: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x20));
    fprintf(stdout, "\t\tSizeOfUninitializedData: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x24));

    if (*(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x28) > 0) {
        fprintf(stdout, "\t\tAddressOfEntryPoint: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x28));
    }
    else {
        fprintf(stderr, "\t\tAddressOfEntryPoint: incorrect value\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-9);
    }

    fprintf(stdout, "\t\tBaseOfCode: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x2C));
    fprintf(stdout, "\t\tImageBase: %016llx\n", *(ULONGLONG*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x30));
    fprintf(stdout, "\t\tSectionAligment: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x38));
    fprintf(stdout, "\t\tFileAligment: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x3C));
    fprintf(stdout, "\t\tMajorOperatingSystemVersion: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x40));
    fprintf(stdout, "\t\tMinorOperatingSystemVersion: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x42));
    fprintf(stdout, "\t\tMajorImageVersion: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x44));
    fprintf(stdout, "\t\tMinorImageVersion: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x46));
    fprintf(stdout, "\t\tMajorSybsystemVersion: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x48));
    fprintf(stdout, "\t\tMinorSybsystemVersion: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x4A));
    fprintf(stdout, "\t\tWin32VersionValue: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x4C));
    fprintf(stdout, "\t\tSizeOfImage: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x50));
    fprintf(stdout, "\t\tSizeOfHeaders: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x54));
    fprintf(stdout, "\t\tCheckSum: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x58));
    fprintf(stdout, "\t\tSubsystem: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x5C));
    fprintf(stdout, "\t\tDllCharacteristics: %04x\n", *(WORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x5E));
    fprintf(stdout, "\t\tSizeOfStackReserve: %016llx\n", *(ULONGLONG*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x60));
    fprintf(stdout, "\t\tSizeOfStackCommit: %016llx\n", *(ULONGLONG*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x68));
    fprintf(stdout, "\t\tSizeOfHeapReserve: %016llx\n", *(ULONGLONG*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x70));
    fprintf(stdout, "\t\tSizeOfHeapCommit: %016llx\n", *(ULONGLONG*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x78));
    fprintf(stdout, "\t\tLoaderFlags: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x80));
    fprintf(stdout, "\t\tNumberOfRvaAndSize: %08x\n", *(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3C) + 0x84));
    fprintf(stdout, "\n\t\tIMAGE_DATA_DIRECTORY\n");

    return 0;
}
