#include "proc.hh"
#include "krnljmper.h"

static _inline bool __fastcall ends_with(std::wstring_view value, std::wstring_view ending) {
    return value.size() >= ending.size() &&
        value.compare(value.size() - ending.size(), ending.size(), ending) == 0;
}

void __fastcall detect_all_instances(std::unordered_set<DWORD>& processes) {
    std::unordered_set<DWORD> validProcesses;

    static DWORD processIds[1024], bytesReturned;

    if (!K32EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        return;
    }

    DWORD numberOfProcesses = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < numberOfProcesses; ++i) {
        HANDLE handle;
        OBJECT_ATTRIBUTES objAttr{};
        CLIENT_ID clientId{};

        clientId.UniqueProcess = ULongToHandle(processIds[i]);

        (&objAttr)->Length = sizeof(OBJECT_ATTRIBUTES);
        (&objAttr)->RootDirectory = nullptr;
        (&objAttr)->Attributes = 0;
        (&objAttr)->ObjectName = nullptr;
        (&objAttr)->SecurityDescriptor = nullptr;
        (&objAttr)->SecurityQualityOfService = 0;

        NTSTATUS status = KeNtOpenProcess(&handle, (0x0400), &objAttr, &clientId);
        if (((NTSTATUS)(status) >= 0)) {
            BYTE buffer[sizeof(UNICODE_STRING) + MAX_PATH * sizeof(WCHAR)] = { 0 };
            PUNICODE_STRING pImageName = (PUNICODE_STRING)buffer;
            pImageName->MaximumLength = MAX_PATH * sizeof(WCHAR);
            pImageName->Buffer = (PWSTR)(pImageName + 1);

            KeNtQueryInformationProcess(
                handle,
                ProcessImageFileName,
                pImageName,
                sizeof(buffer),
                0
            );

            std::wstring_view imageName(pImageName->Buffer, pImageName->Length / sizeof(WCHAR));
            if (ends_with(imageName, L"javaw.exe")) {
                validProcesses.insert(processIds[i]);
            }

            KeNtClose(handle);
        }
    }

    processes.swap(validProcesses);
}

std::pair<DWORD_PTR, DWORD_PTR> __fastcall __get_mem_range(const DWORD processID) {
    DWORD_PTR baseAddress = 0;
    DWORD_PTR endAddress = 0;
    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = UlongToHandle(processID);

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    KeNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);

    if (hProcess) {
        HMODULE hModules[1024];
        DWORD cbNeeded;

        if (K32EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t moduleName[MAX_PATH];
                if (K32GetModuleFileNameExW(hProcess, hModules[i], moduleName, sizeof(moduleName) / sizeof(WCHAR))) {
                    if (wcsstr(moduleName, L"jvm.dll") != NULL) {
                        baseAddress = (DWORD_PTR)hModules[i];

                        IMAGE_DOS_HEADER dosHeader{};
                        SIZE_T bytesRead = 0;
                        const NTSTATUS readStatus = KeNtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(baseAddress), &dosHeader, sizeof(dosHeader), &bytesRead);

                        if (readStatus >= 0 && bytesRead == sizeof(dosHeader) && dosHeader.e_magic == 0x5A4D) {
                            IMAGE_NT_HEADERS ntHeaders{};
                            const NTSTATUS ntReadStatus = KeNtReadVirtualMemory(hProcess, reinterpret_cast<PVOID>(baseAddress + dosHeader.e_lfanew), &ntHeaders, sizeof(ntHeaders), &bytesRead);

                            if (ntReadStatus >= 0 && bytesRead == sizeof(ntHeaders)) {
                                endAddress = baseAddress + ntHeaders.OptionalHeader.SizeOfImage;
                            }
                        }
                        break;
                    }
                }
            }
        }
        KeNtClose(hProcess);
    }

    return std::make_pair(baseAddress, endAddress);
}