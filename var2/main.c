#include "utils.h"

const WCHAR* FILE_NAME = L"C:\\Windows\\System32\\notepad.exe";

INT main()
{
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    LPVOID pMapImageBase = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    //
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    //
    WORD checkMZ = 0;

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
    if (ReadFile(hFile, &checkMZ, 0x02, NULL, NULL)) {
        if (checkMZ == IMAGE_DOS_SIGNATURE) {
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

    // DOS_HEADER
    pDosHeader = (PIMAGE_DOS_HEADER)pMapImageBase;
    if ((CheckAndPrintDosHeader(pDosHeader)) != 0)
    {
        goto EXIT;
    }

    // NT_HEADERS
    fprintf(stdout, "NT_HEADERS\n");

    pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pMapImageBase + pDosHeader->e_lfanew);
    if ((CheckAndPrintNtHeaders(pNtHeaders)) != 0)
    {
        goto EXIT;
    }
    
    // SECTION_HEADERS
    fprintf(stdout, "\n\tSECTION_HEADER\n");

    pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pNtHeaders + sizeof(*pNtHeaders));
    //pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    if ((CheckAndPrintSectionHeaders(pSectionHeader, pNtHeaders->FileHeader.NumberOfSections)) != 0)
    {
        goto EXIT;
    }

EXPORT:
    if (!pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress || !pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
    {
        fprintf(stdout, "\n\tEXPORT_DIRECTORY is empty;\n");
        goto IMPORT;
    }
IMPORT:
    if (!pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        fprintf(stdout, "\n\tIMPORT_DIRECTORY is empty;\n");
        goto IMPORT;
    }
    fprintf(stdout, "\n\tIMPORT_DIRECTORY\n");

    pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)pMapImageBase + DirRvaToRaw(IMAGE_DIRECTORY_ENTRY_IMPORT, pNtHeaders));
    VievImport(pMapImageBase, pNtHeaders, pImportDesc);

EXIT:
    UnmapViewOfFile(pMapImageBase);
    CloseHandle(hFileMap);
    CloseHandle(hFile);
    return 0;
}