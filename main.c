#include <stdio.h>
#include <Windows.h>

//const WCHAR* FILE_NAME = L"C:\\Program Files\\HxD\\HxD.exe";
const WCHAR* FILE_NAME = L"C:\\Windows\\System32\\notepad.exe";

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD RVA, PIMAGE_NT_HEADERS pNT_HEADER);

int main() {
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    LPVOID pMapImage = NULL;
    PIMAGE_NT_HEADERS pNT_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    //
    DWORD* pExport_VA = NULL;
    //
    DWORD* pImport_VA = NULL;
    PIMAGE_SECTION_HEADER pImportSection = NULL;
    //
    WORD* NumberOfSections = NULL;
    DWORD* NumberOfRvaAndSize = NULL;
    DWORD* ImportRVA = NULL;
    LONG e_lfanew;
    WORD check_MZ = 0;
    INT startRVA = 0;

    hFile = CreateFile(FILE_NAME, FILE_READ_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: cannot open file!\n");
        return (-1);
    }
    else {
        fprintf(stdout, "Info: file \"%ws\" was open;\n", FILE_NAME);
    }

    fprintf(stdout, "\nDOS_HEADER\n");
    SetFilePointer(hFile, 0, 0, FILE_BEGIN);
    if (ReadFile(hFile, &check_MZ, 0x02, NULL, NULL)) {
        if (check_MZ == IMAGE_DOS_SIGNATURE) {
            fprintf(stdout, "\te_magic:  MZ\n");
        }
        else {
            fprintf(stderr, "\tError: File format is not PE\n");
            CloseHandle(hFile);
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
    if (*(DWORD*)(pNT_HEADER) != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "\tSignature: \"PE\" not found\n");
        UnmapViewOfFile(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-7);
    }
    else {
        fprintf(stdout, "\tSignature: \"%s\"\n", (PCHAR)(pNT_HEADER));

    }

    fprintf(stdout, "\n\tFILE_HEADER\n");
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

    NumberOfSections = (WORD*)((ULONG64)pNT_HEADER + 0x06);
    if (*NumberOfSections >= 0x60) {
        fprintf(stderr, "\t\tNumberOfSections: incorrect value\n");
        return(-7);
    }
    else {
        fprintf(stdout, "\t\tNumberOfSections: %04X\n", *NumberOfSections);
    }

    fprintf(stdout, "\t\tSizeOfOptionalHeader: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x14));
    fprintf(stdout, "\t\tCharacteristics: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x16));

    fprintf(stdout, "\n\tOPTIONAL_HEADER\n");
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

    fprintf(stdout, "\n\t\tDATA_DIRECTORY\n");
    pDataDirectory = (PIMAGE_DATA_DIRECTORY)((ULONG64)pNT_HEADER + 0x88);
    for (UINT i = 0; i < *NumberOfRvaAndSize; i++) {
        if (pDataDirectory[i].VirtualAddress == 0) {
            continue;
        }
        else {
            fprintf(stdout, "\t\tDirectory %d\n", (i + 1));
            fprintf(stdout, "\t\t RVA:  %08X\n", pDataDirectory[i].VirtualAddress);
            fprintf(stdout, "\t\t Size: %08X\n", pDataDirectory[i].Size);
        }
    }

    fprintf(stdout, "\n\t\tSECTION_HEADER\n");
    pSectionHeader = (PIMAGE_SECTION_HEADER)(&pDataDirectory[*NumberOfRvaAndSize]);
    fprintf(stdout, "\t\t_NAME_\tVirtualSize\tVirtualAddress \tRawSize \tRawAddress\n");
    for (UINT i = 0; i < *NumberOfSections; ++i) {
        fprintf(stdout, "\t\t%-9s%08X\t %08X\t%08X\t%08X\n",
            pSectionHeader[i].Name, pSectionHeader[i].Misc.VirtualSize, pSectionHeader[i].VirtualAddress, pSectionHeader[i].SizeOfRawData, pSectionHeader[i].PointerToRawData
        );
    }

//EXPORT
    pExport_VA = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!*pExport_VA) {
        fprintf(stderr, "\n\t\tDIRECTORY_EXPORT not exist!\n");
        goto IMPORT;
    }

IMPORT:
    pImport_VA = &pDataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (!*pImport_VA) {
        fprintf(stderr, "\n\t\tDIRECTORY_IMPORT not exist!\n");
        return (-11);
    }

    return 0;
}

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD RVA, PIMAGE_NT_HEADERS pNT_HEADER) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(pNT_HEADER);
    for (UINT i = 0; i < pNT_HEADER->FileHeader.NumberOfSections; i++, section++)
    {
        if ((RVA >= section->VirtualAddress) && (RVA < (section->VirtualAddress + section->Misc.VirtualSize)))
        {
            return section;
        }
    }
    return 0;
}
