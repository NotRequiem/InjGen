#include "krnljmper.h"
#include <stdio.h>

Ke_SYSCALL_LIST Ke_SyscallList;

DWORD __fastcall Ke_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = Ke_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((ULONG_PTR)FunctionName + i++);
        Hash ^= PartialName + Ke_ROR8(Hash);
    }

    return Hash;
}

PVOID __fastcall SC_Address(PVOID NtApiAddress)
{
    (NtApiAddress);
    return NULL;
}

BOOL __fastcall Ke_PopulateSyscallList()
{
    if (Ke_SyscallList.Count) return TRUE;

    PKe_PEB Peb = (PKe_PEB)__readgsqword(0x60);

    PKe_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    PKe_LDR_DATA_TABLE_ENTRY LdrEntry;
    for (LdrEntry = (PKe_LDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PKe_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = Ke_RVA2VA(PIMAGE_NT_HEADERS, DllBase, DosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0) continue;

        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)Ke_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        PCHAR DllName = Ke_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        if ((*(ULONG*)DllName | 0x20202020) != 0x6c64746e) continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 0x6c642e6c) break;
    }

    if (!ExportDirectory) return FALSE;

    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = Ke_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = Ke_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = Ke_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    DWORD i = 0;
    PKe_SYSCALL_ENTRY Entries = Ke_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = Ke_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        if (*(USHORT*)FunctionName == 0x775a)
        {
            Entries[i].Hash = Ke_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];
            Entries[i].SyscallAddress = SC_Address(Ke_RVA2VA(PVOID, DllBase, Entries[i].Address));

            i++;
            if (i == Ke_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    Ke_SyscallList.Count = i;

    for (i = 0; i < Ke_SyscallList.Count - 1; i++)
    {
        for (DWORD j = 0; j < Ke_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                Ke_SYSCALL_ENTRY TempEntry = { 0 };

                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;
                TempEntry.SyscallAddress = Entries[j].SyscallAddress;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;
                Entries[j].SyscallAddress = Entries[j + 1].SyscallAddress;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
                Entries[j + 1].SyscallAddress = TempEntry.SyscallAddress;
            }
        }
    }

    return TRUE;
}

EXTERN_C DWORD __fastcall Ke_GetSyscallNumber(DWORD FunctionHash)
{
    if (!Ke_PopulateSyscallList()) return (DWORD)-1;

    for (DWORD i = 0; i < Ke_SyscallList.Count; i++)
    {
        if (FunctionHash == Ke_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return (DWORD)-1;
}

EXTERN_C PVOID __fastcall Ke_GetSyscallAddress(DWORD FunctionHash)
{
    if (!Ke_PopulateSyscallList()) return NULL;

    for (DWORD i = 0; i < Ke_SyscallList.Count; i++)
    {
        if (FunctionHash == Ke_SyscallList.Entries[i].Hash)
        {
            return Ke_SyscallList.Entries[i].SyscallAddress;
        }
    }

    return NULL;
}

EXTERN_C PVOID __fastcall Ke_GetRandomSyscallAddress(DWORD FunctionHash)
{
    if (!Ke_PopulateSyscallList()) return NULL;

    DWORD index = ((DWORD)rand()) % Ke_SyscallList.Count;

    while (FunctionHash == Ke_SyscallList.Entries[index].Hash) {
        index = ((DWORD)rand()) % Ke_SyscallList.Count;
    }
    return Ke_SyscallList.Entries[index].SyscallAddress;
}