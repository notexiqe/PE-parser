#include "utils.h"

const WCHAR* FILE_NAME = L"C:\\Windows\\System32\\notepad.exe";
//const WCHAR* FILE_NAME = L"C:\\Program Files\\Sublime Text 3\\libcrypto-1_1-x64.dll";

INT main()
{
    HANDLE hFile = NULL;
    HANDLE hFileMap = NULL;
    LPVOID pMapImageBase = NULL;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    //
    PIMAGE_EXPORT_DIRECTORY pExportDesc = NULL;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = NULL;
    //
    WORD checkMZ = 0;

    hFile = CreateFile(FILE_NAME, FILE_READ_DATA, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_READONLY, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        fprintf(stdout, "\nDOS_HEADER\n");
        SetFilePointer(hFile, 0, 0, FILE_BEGIN);
        if (ReadFile(hFile, &checkMZ, 0x02, NULL, NULL))
        {
            if (checkMZ == IMAGE_DOS_SIGNATURE)
            {
                fprintf(stdout, "\te_magic:  MZ\n");

                hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
                if (hFileMap != NULL) 
                {
                    pMapImageBase = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
                    if (pMapImageBase != NULL)
                    {

                    }
                    else
                    {
                        fprintf(stderr, "Error: cannot create view of file\n");
                        CloseHandle(hFileMap);
                        CloseHandle(hFile);
                        return (-5);
                    }
                }
                else
                {
                    fprintf(stderr, "Error: cannot map \"%ws\"", FILE_NAME);
                    CloseHandle(hFile);
                    return (-4);
                }
            }
            else
            {
                fprintf(stderr, "\tError: File format is not PE\n");
                CloseHandle(hFile);
                return (-3);
            }
        }
        else
        {
            fprintf(stderr, "Error: ReadFile() return FALSE;");
            return (-2);
        }
    }
    else
    {
        fprintf(stderr, "Error: cannot open file!\n");
        return (-1);
    }

    CloseHandle(hFileMap);
    CloseHandle(hFile);

    // DOS_HEADER

    pDosHeader = (PIMAGE_DOS_HEADER)pMapImageBase;
    if (CheckAndPrintDosHeader(pDosHeader))
    {
        // NT_HEADERS

        pNtHeaders = (PIMAGE_NT_HEADERS64)((ULONG64)pMapImageBase + pDosHeader->e_lfanew);
        if (CheckAndPrintNtHeaders(pNtHeaders))
        {
            // SECTION_HEADERS

            pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG64)pNtHeaders + sizeof(*pNtHeaders));
            //pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);

            CheckAndPrintSectionHeader(pSectionHeader, pNtHeaders->FileHeader.NumberOfSections);

            // EXPORT
            if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
            {
                pExportDesc = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)pMapImageBase + DirRvaToRaw(IMAGE_DIRECTORY_ENTRY_EXPORT, pNtHeaders));
                ViewExport(pMapImageBase, pNtHeaders, pExportDesc);
            }
            else
            {
                fprintf(stdout, "\n\tEXPORT_DIRECTORY is empty;\n");
            }

            // IMPORT
            if (pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
            {
                pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)((ULONG64)pMapImageBase + DirRvaToRaw(IMAGE_DIRECTORY_ENTRY_IMPORT, pNtHeaders));
                ViewImport(pMapImageBase, pNtHeaders, pImportDesc);
            }
            else
            {
                fprintf(stdout, "\n\tIMPORT_DIRECTORY is empty;\n");
            }
        }
        else
        {
            fprintf(stderr, "CheckAndPrintNtHeaders return error;\n");
        }
    }
    else 
    {
        fprintf(stderr, "CheckAndPrintDosHeader return error;\n");
    }

    UnmapViewOfFile(pMapImageBase);
    return 0;
}
