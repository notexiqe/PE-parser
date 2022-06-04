#include <stdio.h>
#include <Windows.h>

#define RvaToVa(Base, offset) (PVOID)((ULONG64)Base + (ULONG)offset)

BOOL CheckAndPrintDosHeader(const PIMAGE_DOS_HEADER DosHeader)
{
    if (DosHeader->e_lfarlc < 0x40)
    {
        fprintf(stderr, "\tError: e_lfarlc less then 40h\n");
        return FALSE;
    }
    else
    {
        fprintf(stdout, "\te_lfarlc: %X\n", DosHeader->e_lfarlc);
    }

    fprintf(stdout, "\te_lfanew: %X\n", DosHeader->e_lfanew);
    return TRUE;
}

VOID CheckAndPrintNtHeadersMachine(const WORD Machine)
{
    switch (Machine)
    {
        default:
        {
            fprintf(stdout, "\tMachine: unknown or not added;\n");
            break;
        }
        case IMAGE_FILE_MACHINE_I386:
        {
            fprintf(stdout, "\tMachine: x86\n");
            break;
        }
        case IMAGE_FILE_MACHINE_IA64:
        {
            fprintf(stdout, "\tMachine: Intel Itanium\n");
            break;
        }
        case IMAGE_FILE_MACHINE_AMD64:
        {
            fprintf(stdout, "\t Machine: x64\n");
            break;
        }
    }
}

VOID CheckAndPrintNtHeadersFileCharacteristics(const WORD Characteristics)
{
    fprintf(stdout, "\t Characteristics: %04X\n", Characteristics);

    Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE ? fprintf(stdout, "\t\tFile is executable;\n") : printf("");

    Characteristics & IMAGE_FILE_SYSTEM ? fprintf(stdout, "\t\tSystem File;\n") : printf("");

    Characteristics & IMAGE_FILE_DLL ? fprintf(stdout, "\t\tFile is a DLL;\n") : printf("");

    Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE ? fprintf(stdout, "\t\tApp can handle >2-GB addresses;\n") : printf("");

    Characteristics & IMAGE_FILE_32BIT_MACHINE ? fprintf(stdout, "\t\t32 bit word machine;\n") : printf("");
}

VOID CheckAndPrintNtHeadersDLLCharacteristics(const WORD DllCharacteristics)
{
    fprintf(stdout, "\t DllCharacteristics: %04X\n", DllCharacteristics);

    DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE ? fprintf(stderr, "\t\tDLL can be relocated at load time;\n") : printf("");

    DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT ? fprintf(stderr, "\t\tImage is NX compatible;\n") : printf("");
}

BOOL CheckAndPrintNtHeaders(const PIMAGE_NT_HEADERS NtHeaders)
{
    fprintf(stdout, "NT_HEADERS\n");

    if (NtHeaders->Signature == IMAGE_NT_SIGNATURE)
    {
        fprintf(stdout, "\tSignature: %08X\n", NtHeaders->Signature);

        fprintf(stdout, "\n\tFILE_HEADER\n");

        CheckAndPrintNtHeadersMachine(NtHeaders->FileHeader.Machine);

        if (NtHeaders->FileHeader.NumberOfSections < 0x60)
        {
            fprintf(stdout, "\t NumberOfSections: %04X\n", NtHeaders->FileHeader.NumberOfSections);

            fprintf(stdout, "\t SizeOfOptionalHeader: %04X\n", NtHeaders->FileHeader.SizeOfOptionalHeader);

            CheckAndPrintNtHeadersFileCharacteristics(NtHeaders->FileHeader.Characteristics);

            fprintf(stdout, "\n\tOPTIONAL_HEADER\n");
            if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
            {
                fprintf(stdout, "\t Magic: PE32+ (64 bit application)\n");

                if (NtHeaders->OptionalHeader.AddressOfEntryPoint > 0)
                {
                    fprintf(stdout, "\t AddressOfEntryPoint: %08X\n", NtHeaders->OptionalHeader.AddressOfEntryPoint);
                    fprintf(stdout, "\t ImageBase: %016llX\n", NtHeaders->OptionalHeader.ImageBase);
                    fprintf(stdout, "\t SectionAligment: %08X\n", NtHeaders->OptionalHeader.SectionAlignment);
                    fprintf(stdout, "\t FileAligment: %08X\n", NtHeaders->OptionalHeader.FileAlignment);
                    fprintf(stdout, "\t MajorSybsystemVersion: %04X\n", NtHeaders->OptionalHeader.MajorSubsystemVersion);
                    fprintf(stdout, "\t SizeOfImage: %08X\n", NtHeaders->OptionalHeader.SizeOfImage);
                    fprintf(stdout, "\t SizeOfHeaders: %08X\n", NtHeaders->OptionalHeader.SizeOfHeaders);
                    fprintf(stdout, "\t Subsystem: %04X\n", NtHeaders->OptionalHeader.Subsystem);

                    CheckAndPrintNtHeadersDLLCharacteristics(NtHeaders->OptionalHeader.DllCharacteristics);

                    fprintf(stdout, "\t NumberOfRvaAndSize: %08X\n", NtHeaders->OptionalHeader.NumberOfRvaAndSizes);

                    fprintf(stdout, "\n\t DATA_DIRECTORIES\n");

                    for (INT i = 0; i < (INT)NtHeaders->OptionalHeader.NumberOfRvaAndSizes; i++)
                    {
                        if (NtHeaders->OptionalHeader.DataDirectory[i].VirtualAddress == 0)
                        {
                            continue;
                        }
                        else
                        {
                            fprintf(stdout, "\t  Directory %d\n\t   RVA: %08X\n\t   Size: %08X\n", i, NtHeaders->OptionalHeader.DataDirectory[i].VirtualAddress, NtHeaders->OptionalHeader.DataDirectory[i].Size);
                        }
                    }
                }
                else
                {
                    fprintf(stderr, "\t\tAddressOfEntryPoint: incorrect value\n");
                    return FALSE;
                }
            }
            else
            {
                fprintf(stderr, "\t Magic: Application is not 64 bit;\n");
                return FALSE;
            }
        }
        else
        {
            fprintf(stderr, "\tNumberOfSections: incorrect value\n");
            return FALSE;
        }
    }
    else
    {
        fprintf(stderr, "\tSignature: \"PE\" not found\n");
        return FALSE;
    }

    return TRUE;
}

VOID CheckAndPrintSectionHeader(const PIMAGE_SECTION_HEADER SectionHeader, const INT Number)
{
    fprintf(stdout, "\n\tSECTION_HEADER\n");

    fprintf(stdout, "\t Name \tVirtualSize\tVirtualAddress \tRawSize \tRawAddress\n");

    for (INT i = 0; i < Number; i++)
    {
        fprintf(stdout, "\t%-9s%08X\t %08X\t%08X\t%08X\n",
            SectionHeader[i].Name, SectionHeader[i].Misc.VirtualSize, SectionHeader[i].VirtualAddress, SectionHeader[i].SizeOfRawData, SectionHeader[i].PointerToRawData
        );
    }
    return;
}

ULONG RvaToRaw(ULONG RVA, PIMAGE_NT_HEADERS NtHeaders)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtHeaders);

    for (INT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (RVA >= section[i].VirtualAddress)
        {
            if (RVA < (section[i].VirtualAddress + section[i].Misc.VirtualSize))
            {
                RVA -= section[i].VirtualAddress;
                RVA += section[i].PointerToRawData;
                return RVA;
            }
        }
    }

    return 0;
}

ULONG DirRvaToRaw(INT DirIndex, PIMAGE_NT_HEADERS NtHeaders) {
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtHeaders);

    DWORD DirRVA = NtHeaders->OptionalHeader.DataDirectory[DirIndex].VirtualAddress;
    INT indexSection = -1;

    for (INT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (DirRVA >= section[i].VirtualAddress)
        {
            if (DirRVA < (section[i].VirtualAddress + section[i].Misc.VirtualSize))
            {
                indexSection = i;
                break;
            }
        }
    }

    if (indexSection != -1)
    {
        DirRVA -= section[indexSection].VirtualAddress;
        DirRVA += section[indexSection].PointerToRawData;
        return DirRVA;
    }

    return 0;
}

VOID ViewExport(LPVOID MapImageBase, PIMAGE_NT_HEADERS NtHeaders, PIMAGE_EXPORT_DIRECTORY ExportDescriptor)
{
    LPDWORD procAddr = (LPDWORD)RvaToVa(MapImageBase, RvaToRaw(ExportDescriptor->AddressOfFunctions, NtHeaders));
    LPDWORD procNameRVA = (LPDWORD)RvaToVa(MapImageBase, RvaToRaw(ExportDescriptor->AddressOfNames, NtHeaders));
    LPWORD procOrdinalNames = (LPWORD)RvaToVa(MapImageBase, RvaToRaw(ExportDescriptor->AddressOfNameOrdinals, NtHeaders));

    PCHAR procName = NULL;

    fprintf(stdout, "\n\tEXPORT_DIRECTORY\n");

    for (UINT i = 0; i < ExportDescriptor->NumberOfFunctions; i++)
    {
        procName = (PCHAR)RvaToVa(MapImageBase, RvaToRaw(procNameRVA[i], NtHeaders));
        fprintf(stdout, "\t %s()\n", procName);
    }
    return;
}

VOID ViewImport(LPVOID MapImageBase, PIMAGE_NT_HEADERS NtHeaders, PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor)
{
    PCHAR moduleName = NULL;
    PCHAR moduleProcName = NULL;
    PIMAGE_THUNK_DATA pThunk = NULL;
    PIMAGE_IMPORT_BY_NAME ImportByName = NULL;

    fprintf(stdout, "\n\tIMPORT_DIRECTORY\n");

    while (ImportDescriptor->Name && ImportDescriptor->OriginalFirstThunk)
    {
        moduleName = (PCHAR)RvaToVa(MapImageBase, RvaToRaw(ImportDescriptor->Name, NtHeaders));
        fprintf(stdout, "\t [%s]\n", moduleName);

        pThunk = (PIMAGE_THUNK_DATA)RvaToVa(MapImageBase, RvaToRaw(ImportDescriptor->OriginalFirstThunk, NtHeaders));

        while (pThunk->u1.AddressOfData)
        {
            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                ImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToVa(MapImageBase, RvaToRaw(pThunk->u1.AddressOfData, NtHeaders));
                moduleProcName = ImportByName->Name;
                fprintf(stdout, "\t -> %s()\n", moduleProcName);
            }
            pThunk++;
        }

        ImportDescriptor++;
    }
    return;
}
