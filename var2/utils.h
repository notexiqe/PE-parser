#include <stdio.h>
#include <Windows.h>

#define RvaToVa(Base, offset) (PVOID)((ULONG64)Base + (ULONG)offset)

INT CheckAndPrintDosHeader(PIMAGE_DOS_HEADER DosHeader)
{
    if (DosHeader->e_lfarlc < 0x40)
    {
        fprintf(stderr, "\tError: e_lfarlc less then 40h\n");
        return -1;
    }
    else
    {
        fprintf(stdout, "\te_lfarlc: %X\n", DosHeader->e_lfarlc);
    }

    fprintf(stdout, "\te_lfanew: %X\n", DosHeader->e_lfanew);
    return 0;
}

INT CheckAndPrintNtHeaders(PIMAGE_NT_HEADERS NtHeaders)
{
    if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        fprintf(stderr, "\tSignature: \"PE\" not found\n");
        return -1;
    }
    else
    {
        fprintf(stdout, "\tSignature: %08X\n", NtHeaders->Signature);
    }

    fprintf(stdout, "\n\tFILE_HEADER\n");
    switch (NtHeaders->FileHeader.Machine)
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

    if (NtHeaders->FileHeader.NumberOfSections >= 0x60)
    {
        fprintf(stderr, "\tNumberOfSections: incorrect value\n");
        return -1;
    }
    else
    {
        fprintf(stdout, "\t NumberOfSections: %04X\n", NtHeaders->FileHeader.NumberOfSections);
    }

    fprintf(stdout, "\t SizeOfOptionalHeader: %04X\n", NtHeaders->FileHeader.SizeOfOptionalHeader);
    fprintf(stdout, "\t Characteristics: %04X\n", NtHeaders->FileHeader.Characteristics);

    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        fprintf(stdout, "\t\tFile is executable;\n");
    }
    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_SYSTEM)
    {
        fprintf(stdout, "\t\tSystem File;\n");
    }
    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL)
    {
        fprintf(stdout, "\t\tFile is a DLL;\n");
    }

    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_LARGE_ADDRESS_AWARE)
    {
        fprintf(stdout, "\t\tApp can handle >2-GB addresses;\n");
    }

    if (NtHeaders->FileHeader.Characteristics & IMAGE_FILE_32BIT_MACHINE)
    {
        fprintf(stdout, "\t\t32 bit word machine;\n");
    }


    fprintf(stdout, "\n\tOPTIONAL_HEADER\n");

    if (NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        fprintf(stderr, "\t Magic: Application is not 64 bit;\n");
        return -1;
    }
    else
    {
        fprintf(stdout, "\t Magic: PE32+ (64 bit application)\n");
    }

    if (NtHeaders->OptionalHeader.AddressOfEntryPoint <= 0)
    {
        fprintf(stderr, "\t\tAddressOfEntryPoint: incorrect value\n");
    }
    else
    {
        fprintf(stdout, "\t AddressOfEntryPoint: %08X\n", NtHeaders->OptionalHeader.AddressOfEntryPoint);
    }

    fprintf(stdout, "\t ImageBase: %016llX\n", NtHeaders->OptionalHeader.ImageBase);
    fprintf(stdout, "\t SectionAligment: %08X\n", NtHeaders->OptionalHeader.SectionAlignment);
    fprintf(stdout, "\t FileAligment: %08X\n", NtHeaders->OptionalHeader.FileAlignment);
    fprintf(stdout, "\t MajorSybsystemVersion: %04X\n", NtHeaders->OptionalHeader.MajorSubsystemVersion);
    fprintf(stdout, "\t SizeOfImage: %08X\n", NtHeaders->OptionalHeader.SizeOfImage);
    fprintf(stdout, "\t SizeOfHeaders: %08X\n", NtHeaders->OptionalHeader.SizeOfHeaders);
    fprintf(stdout, "\t Subsystem: %04X\n", NtHeaders->OptionalHeader.Subsystem);

    fprintf(stdout, "\t DllCharacteristics: %04X\n", NtHeaders->OptionalHeader.DllCharacteristics);
    if (NtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
    {
        fprintf(stderr, "\t\tDLL can be relocated at load time;\n");
    }
    if (NtHeaders->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT)
    {
        fprintf(stderr, "\t\tImage is NX compatible;\n");
    }

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

    return 0;
}

INT CheckAndPrintSectionHeaders(PIMAGE_SECTION_HEADER SectionHeader, INT Number)
{
    fprintf(stdout, "\t Name \tVirtualSize\tVirtualAddress \tRawSize \tRawAddress\n");

    for (INT i = 0; i < Number; i++)
    {
        fprintf(stdout, "\t%-9s%08X\t %08X\t%08X\t%08X\n",
            SectionHeader[i].Name, SectionHeader[i].Misc.VirtualSize, SectionHeader[i].VirtualAddress, SectionHeader[i].SizeOfRawData, SectionHeader[i].PointerToRawData
        );
    }
    return 0;
}

ULONG RvaToRaw(ULONG RVA, PIMAGE_NT_HEADERS NtHeaders)
{
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(NtHeaders);

    for (INT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        if (section[i].VirtualAddress <= RVA)
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
    DWORD SectionAlignment = NtHeaders->OptionalHeader.SectionAlignment;
    INT indexSection = -1;

    for (INT i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
    {
        //DWORD start = section[i].VirtualAddress;
        //DWORD end = section[i].VirtualAddress + ALIGN_UP(section[i].Misc.VirtualSize, SectionAlignment);

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

    for (UINT i = 0; i < ExportDescriptor->NumberOfFunctions; i++)
    {
        procName = (PCHAR)RvaToVa(MapImageBase, RvaToRaw(procNameRVA[i], NtHeaders));
        fprintf(stdout, "\t %s()\n", procName);
        //fprintf(stdout, "\t [%06d] Addr [0x%08X] : Ordinal [0x%04d] : [%s()]\n",
        //    i,
        //    procAddr[i],
        //    procOrdinalNames[i],
        //    procName
        //);
    }
    return;
}

VOID ViewImport(LPVOID MapImageBase, PIMAGE_NT_HEADERS NtHeaders, PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor)
{
    PCHAR moduleName = NULL;
    PCHAR moduleProcName = NULL;
    PIMAGE_THUNK_DATA pThunk = NULL;
    PIMAGE_IMPORT_BY_NAME ImportByName = NULL;

    while (ImportDescriptor->Name && ImportDescriptor->OriginalFirstThunk)
    {
        moduleName = (PCHAR)RvaToVa(MapImageBase, RvaToRaw(ImportDescriptor->Name, NtHeaders));
        fprintf(stdout, "\t %s\n", moduleName);

        pThunk = (PIMAGE_THUNK_DATA)RvaToVa(MapImageBase, RvaToRaw(ImportDescriptor->OriginalFirstThunk, NtHeaders));

        while (pThunk->u1.AddressOfData)
        {
            if (!(pThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG))
            {
                ImportByName = (PIMAGE_IMPORT_BY_NAME)RvaToVa(MapImageBase, RvaToRaw(pThunk->u1.AddressOfData, NtHeaders));
                moduleProcName = ImportByName->Name;
                fprintf(stdout, "\t  %s()\n", moduleProcName);
            }
            pThunk++;
        }

        ImportDescriptor++;
    }
    return;
}
