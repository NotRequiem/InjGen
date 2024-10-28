#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>

bool trace(HANDLE hProcess, DWORD_PTR baseAddress, DWORD_PTR endAddress, DWORD targetValue) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR address = baseAddress;
    while (address < endAddress) {
        if (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
                SIZE_T bytesToRead = (SIZE_T)(mbi.RegionSize);
                std::vector<unsigned char> buffer(bytesToRead);
                SIZE_T bytesRead;
                if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), bytesToRead, &bytesRead)) {
                    for (SIZE_T i = 0; i < bytesRead - sizeof(DWORD); ++i) {
                        DWORD value = *(DWORD*)(buffer.data() + i);
                        if (value == targetValue) {
                            return true;
                        }
                    }
                }
            }
            address += mbi.RegionSize;
        }
        else {
            break;
        }
    }
    return false;
}

bool scanForString(HANDLE hProcess, const char* searchString) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD_PTR address = 0;
    SIZE_T searchLength = strlen(searchString);
    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect & PAGE_READWRITE) &&
            !(mbi.Protect & PAGE_GUARD) &&
            !(mbi.Protect & PAGE_NOACCESS)) {
            SIZE_T bytesToRead = (SIZE_T)(mbi.RegionSize);
            std::vector<unsigned char> buffer(bytesToRead);
            SIZE_T bytesRead;
            if (ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), bytesToRead, &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - searchLength; ++i) {
                    if (memcmp(buffer.data() + i, searchString, searchLength) == 0) {
                        return true;
                    }
                }
            }
        }
        address += mbi.RegionSize;
    }
    return false;
}

void start_memory_scan(HANDLE hProcess) {
    HMODULE hModules[1024];
    DWORD cbNeeded;
    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        bool foundJVM = false;
        MODULEINFO jvmModuleInfo = { 0 };
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            TCHAR moduleName[MAX_PATH];
            if (GetModuleFileNameEx(hProcess, hModules[i], moduleName, MAX_PATH)) {
                #ifdef UNICODE
                    std::wstring moduleNameStr = moduleName;
                #else
                    std::wstring moduleNameStr = std::wstring(moduleName, moduleName + strlen(moduleName));
                #endif
                if (moduleNameStr.find(L"jvm.dll") != std::wstring::npos) {
                    if (GetModuleInformation(hProcess, hModules[i], &jvmModuleInfo, sizeof(jvmModuleInfo))) {
                        foundJVM = true;
                        break;
                    }
                }
            }
        }

        if (!foundJVM) {
            std::cerr << "jvm.dll not found in process.\n";
            return;
        }

        DWORD_PTR baseAddress = (DWORD_PTR)jvmModuleInfo.lpBaseOfDll;
        DWORD_PTR endAddress = baseAddress + jvmModuleInfo.SizeOfImage;

        bool flag = true;
        flag &= trace(hProcess, baseAddress, endAddress, 524294);
        flag &= trace(hProcess, baseAddress, endAddress, 4242546329);

        if (flag) {
            std::cout << "Validating detection...\n";
            if (scanForString(hProcess, "v2.17.5-2442")) {
                std::cout << "[!] DoomsDay Client detected.\n";
            }
            else {
                std::cout << "[-] DoomsDay Client was detected outside Lunar Client. Be careful.\n";
            }
        }
        else {
            std::cout << "[+] DoomsDay Client not found in game's memory.\n";
        }
    }
}

int main() {
    DWORD processIds[1024], bytesReturned;
    if (!EnumProcesses(processIds, sizeof(processIds), &bytesReturned)) {
        std::cerr << "Failed to enumerate processes.\n";
        return 1;
    }

    DWORD numberOfProcesses = bytesReturned / sizeof(DWORD);

    for (DWORD i = 0; i < numberOfProcesses; ++i) {
        DWORD pid = processIds[i];
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProcess) {
            TCHAR imageName[MAX_PATH];
            if (GetProcessImageFileName(hProcess, imageName, MAX_PATH) > 0) {
                #ifdef UNICODE
                    std::wstring processName = imageName;
                #else
                    std::wstring processName = std::wstring(imageName, imageName + strlen(imageName));
                #endif
                if (processName.find(L"javaw.exe") != std::wstring::npos) {
                    std::wcout << L"Reading virtual memory in 'javaw.exe' process with PID " << pid << L"\n";
                    start_memory_scan(hProcess);
                }
            }
            CloseHandle(hProcess);
        }
    }
    return 0;
}
