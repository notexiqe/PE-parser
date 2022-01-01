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
   
    SetFilePointer(hFile, 0, 0, FILE_BEGIN);
    if (ReadFile(hFile, &check_MZ, 0x02, NULL, NULL)) {
        if (check_MZ == IMAGE_DOS_SIGNATURE) {
            fprintf(stdout, "Info: sign \"MZ\" was found;\n");
        }
        else {
            fprintf(stderr, "Error: File format is not PE;\n");
            return (-3);
        }
    }
    else {
        fprintf(stderr, "Error: ReadFile() return FALSE;");
        return (-2);
    }
    

    hFileMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hFileMap == NULL) {
        fprintf(stderr, "Error: cannot map \"%ws\";", FILE_NAME);
        CloseHandle(hFile);
        return (-4);
    }

    pMapImage = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (pMapImage == NULL) {
        fprintf(stderr, "Error: cannot create viev of file;\n");
        CloseHandle(hFileMap);
        CloseHandle(hFile);
        return (-5);
    }
    
    if (*(BYTE*)((ULONG64)pMapImage + 0x18) < 0x40) {
        fprintf(stderr, "Error: e_lfarlc less then 40h\n");
        return (-6);
        CloseHandle(pMapImage);
        CloseHandle(hFileMap);
        CloseHandle(hFile);
    }
    else {
        fprintf(stdout, "Info: e_lfarlc have correct value;\n");
    }

    if (*(DWORD*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3c)) == IMAGE_NT_SIGNATURE) {
        fprintf(stdout, "Info: sign \"%s\" found;\n", (char*)(((ULONG64)pMapImage) + *(LONG*)((ULONG64)pMapImage + 0x3c)));
    }
    else {
        fprintf(stderr, "Error: sign \"PE\" not found;\n");
        return (-6);
    }
    return 0;
}
