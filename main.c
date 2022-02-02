#include <stdio.h>
#include <Windows.h>

#define ALIGN_DOWN(x, align)  (x & ~(align-1))
#define ALIGN_UP(x, align)    ((x & (align-1)) ? ALIGN_DOWN(x,align) + align : x)
#define RvaToVa(Base, offset) (PVOID)((ULONG64)Base + (ULONG)offset)

//const WCHAR* FILE_NAME = L"C:\\Program Files\\HxD\\HxD.exe";
const WCHAR* FILE_NAME = L"C:\\Windows\\System32\\notepad.exe";

VOID HandleImport(LPVOID MapImageBase, PIMAGE_NT_HEADERS NtHeaders);

ULONG
RvaToRaw(
    PIMAGE_NT_HEADERS NtHeaders,
    PVOID ImageBase,
    ULONG RVA
);

PIMAGE_SECTION_HEADER GetEnclosingSectionHeader(DWORD rva, PIMAGE_NT_HEADERS pNTHeader);

int main() {
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    LPVOID pMapImageBase = NULL;
    PIMAGE_NT_HEADERS pNT_HEADER = NULL;
    PIMAGE_DATA_DIRECTORY pDataDirectories = NULL;
    PIMAGE_SECTION_HEADER pSectionHeaders = NULL;
    //
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
    HANDLE pImportDirectory = NULL;
    //
    WORD* NumberOfSections = NULL;
    DWORD* NumberOfRvaAndSize = NULL;
    WORD check_MZ = 0;
    LONG e_lfanew = 0;

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

    pMapImageBase = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (pMapImageBase == NULL) {
        fprintf(stderr, "Error: cannot create view of file\n");
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-5);
    }

    if (*(BYTE*)((ULONG64)pMapImageBase + 0x18) < 0x40) {
        fprintf(stderr, "\tError: e_lfarlc less then 40h\n");
        UnmapViewOfFile(pMapImageBase);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-6);
    }
    else {
        fprintf(stdout, "\te_lfarlc: %X\n", *(BYTE*)((ULONG64)pMapImageBase + 0x18));
    }

    e_lfanew = *(LONG*)((ULONG64)pMapImageBase + 0x3C);
    fprintf(stdout, "\te_lfanew: %X\n", e_lfanew);

    //PIMAGE_NT_HEADERS64
    fprintf(stdout, "IMAGE_NT_HEADER\n");
    pNT_HEADER = (PIMAGE_NT_HEADERS)((ULONG64)pMapImageBase + e_lfanew);
    if (*(DWORD*)(pNT_HEADER) != IMAGE_NT_SIGNATURE) {
        fprintf(stderr, "\tSignature: \"PE\" not found\n");
        UnmapViewOfFile(pMapImageBase);
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
        UnmapViewOfFile(pMapImageBase);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-8);
    }
    else {
        fprintf(stdout, "\t\tMagic: PE32+ (64-bit application)\n");
    }

    if (*(DWORD*)((ULONG64)pNT_HEADER + 0x28) <= 0) {
        fprintf(stderr, "\t\tAddressOfEntryPoint: incorrect value\n");
        UnmapViewOfFile(pMapImageBase);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-9);
    }
    else {
        fprintf(stdout, "\t\tAddressOfEntryPoint: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x28));
    }

    fprintf(stdout, "\t\tImageBase: %016llX\n", *(DWORDLONG*)((ULONG64)pNT_HEADER + 0x30));
    fprintf(stdout, "\t\tSectionAligment: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x38));
    fprintf(stdout, "\t\tFileAligment: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x3C));
    fprintf(stdout, "\t\tMajorSybsystemVersion: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x48));
    fprintf(stdout, "\t\tSizeOfImage: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x50));
    fprintf(stdout, "\t\tSizeOfHeaders: %08X\n", *(DWORD*)((ULONG64)pNT_HEADER + 0x54));
    fprintf(stdout, "\t\tSubsystem: %04X\n", *(WORD*)((ULONG64)pNT_HEADER + 0x5C));
    NumberOfRvaAndSize = (DWORD*)((ULONG64)pNT_HEADER + 0x84);
    fprintf(stdout, "\t\tNumberOfRvaAndSize: %08X\n", *NumberOfRvaAndSize);

    fprintf(stdout, "\n\t\tDATA_DIRECTORY\n");
    pDataDirectories = (PIMAGE_DATA_DIRECTORY)((ULONG64)pNT_HEADER + 0x88);
    for (UINT i = 0; i < *NumberOfRvaAndSize; i++) {
        if (pDataDirectories[i].VirtualAddress == 0) {
            continue;
        }
        else {
            fprintf(stdout, "\t\tDirectory %d\n", i);
            fprintf(stdout, "\t\t offset:  %08X\n", pDataDirectories[i].VirtualAddress);
            fprintf(stdout, "\t\t Size: %08X\n", pDataDirectories[i].Size);
        }
    }

    fprintf(stdout, "\n\tSECTION_HEADER\n");
    pSectionHeaders = (PIMAGE_SECTION_HEADER)(&pDataDirectories[*NumberOfRvaAndSize]);
    fprintf(stdout, "\t_NAME_\tVirtualSize\tVirtualAddress \tRawSize \tRawAddress\n");
    for (UINT i = 0; i < *NumberOfSections; ++i) {
        fprintf(stdout, "\t%-9s%08X\t %08X\t%08X\t%08X\n",
            pSectionHeaders[i].Name, pSectionHeaders[i].Misc.VirtualSize, pSectionHeaders[i].VirtualAddress, pSectionHeaders[i].SizeOfRawData, pSectionHeaders[i].PointerToRawData
        );
    }

//EXPORT
    if (!pDataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress || !pDataDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size) {
        fprintf(stderr, "\n\tEXPORT_DIRECTORY is empty!\n");
        goto IMPORT;
    }
    fprintf(stdout, "\n\tIMPORT_DIRECTORY\n");

IMPORT:
    if (!pDataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !pDataDirectories[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) {
        fprintf(stderr, "\n\tIMPORT_DIRECTORY is empty!\n");
        return (-11);
    }

    fprintf(stdout, "\n\tIMPORT_DIRECTORY\n");
    HandleImport(pMapImageBase, pNT_HEADER);
    return 0;
}

VOID HandleImport(LPVOID MapImageBase, PIMAGE_NT_HEADERS NtHeaders)
{
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = NULL;
    PCHAR pName = NULL;
    DWORD offset = 0;
    PIMAGE_THUNK_DATA pNameThunk = NULL;
    PIMAGE_THUNK_DATA pAddrThunk = NULL;
    PIMAGE_IMPORT_BY_NAME pImportByName = NULL;
    PCHAR pProcName = NULL;

    offset = RvaToRaw(NtHeaders, MapImageBase, NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)MapImageBase + offset);

    while (pImportDescriptor->Name && pImportDescriptor->OriginalFirstThunk) 
    {
        pName = (PCHAR)RvaToVa(MapImageBase, RvaToRaw(NtHeaders, MapImageBase, pImportDescriptor->Name));
        printf("\t\t%s\n", pName);

        pNameThunk = (PIMAGE_THUNK_DATA)RvaToVa(MapImageBase, RvaToRaw(NtHeaders, MapImageBase, pImportDescriptor->OriginalFirstThunk));
        //pAddrThunk = (PIMAGE_THUNK_DATA)RvaToVa(MapImageBase, RvaToRaw(NtHeaders, MapImageBase, pImportDescriptor->FirstThunk));

        while (pNameThunk->u1.AddressOfData)
        {
            if (!(pNameThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                pImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToVa(MapImageBase, RvaToRaw(NtHeaders, MapImageBase, pNameThunk->u1.AddressOfData));
                pProcName = pImportByName->Name;
                printf("\t\t\t%s\n", pProcName);
            }

            pNameThunk++;
            //pAddrThunk++;
        }

        pImportDescriptor++;
    }
}

ULONG
RvaToRaw(
    PIMAGE_NT_HEADERS NtHeaders,
    PVOID ImageBase,
    ULONG offset
)
{
    PIMAGE_SECTION_HEADER pSection;
    ULONG i;

    pSection = IMAGE_FIRST_SECTION(NtHeaders);

    for (i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (pSection[i].VirtualAddress <= offset)
        {
            if ((pSection[i].VirtualAddress + pSection[i].Misc.VirtualSize) > offset)
            {
                return offset - (pSection[i].VirtualAddress - pSection[i].PointerToRawData);
            }
        }
    }

    return 0;
}
