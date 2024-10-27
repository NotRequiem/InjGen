#include "mem.hpp"
#include "proc.hh"
#include "krnljmper.h"

static inline inst_set __intr() {
    int info[4];
    __cpuidex(info, 0, 0);
    int nIds = info[0];

    __cpuidex(info, 0x80000000, 0);

    inst_set instructionSet = INSTRUCTION_SET_NONE;

    if (nIds >= 0x00000001) {
        __cpuidex(info, 0x00000001, 0);
        if (info[3] & (1 << 25)) {
            instructionSet = static_cast<inst_set>(INSTRUCTION_SET_SSE);
        }
        if (info[2] & (1 << 28)) {
            instructionSet = static_cast<inst_set>(INSTRUCTION_SET_AVX);
        }
    }

    if (nIds >= 0x00000007) {
        __cpuidex(info, 0x00000007, 0);
        if (info[1] & (1 << 16)) {
            instructionSet = static_cast<inst_set>(INSTRUCTION_SET_AVX512);
        }
    }

    return instructionSet;
}

inline static std::vector<std::string> __vectorcall avx512_mem_scn(unsigned char* buffer, size_t bytesRead) {
    std::vector<std::string> __mm_dump;
    constexpr size_t s512 = 64;
    const size_t numBlocks512 = bytesRead / s512;
    std::string partialString;

    for (size_t i = 0; i < numBlocks512; ++i) {
        __m512i data512 = _mm512_loadu_si512((__m512i*)(buffer + i * s512));
        __mmask64 isPrintable512 = _mm512_cmpgt_epi8_mask(data512, _mm512_set1_epi8(31)) &
            _mm512_cmplt_epi8_mask(data512, _mm512_set1_epi8(127));

        size_t j = 0;
        while (j < s512) {
            if (isPrintable512 & (1ULL << j)) {
                size_t k = j;
                while (k < s512 && (isPrintable512 & (1ULL << k))) {
                    ++k;
                }

                if (k - j + partialString.size() >= MIN_STRING_LENGTH) {
                    std::string foundString = partialString + std::string((char*)(buffer + i * s512 + j), k - j);
                    __mm_dump.push_back(foundString);
                    partialString.clear();
                }
                else {
                    partialString += std::string((char*)(buffer + i * s512 + j), k - j);
                }
                j = k;
            }
            else {
                ++j;
            }
        }
    }

    return __mm_dump;
}

inline static std::vector<std::string> __fastcall generic_memory_scan(unsigned char* buffer, size_t bytesRead) {
    std::vector<std::string> __mm_dump;
    std::string currentString;
    bool insidePrintableSeq = false;

    for (size_t i = 0; i < bytesRead; ++i) {
        if (buffer[i] >= 32 && buffer[i] <= 126) /* ASCII range */ {
            if (!insidePrintableSeq) {
                insidePrintableSeq = true;
            }
            currentString += buffer[i];
        }
        else {
            if (insidePrintableSeq && currentString.size() >= MIN_STRING_LENGTH) {
                __mm_dump.push_back(currentString);
            }
            insidePrintableSeq = false;
            currentString.clear();
        }
    }

    if (insidePrintableSeq && currentString.size() >= MIN_STRING_LENGTH) {
        __mm_dump.push_back(currentString);
    }

    return __mm_dump;
}

inline static std::vector<std::string> __fastcall __trigger_pattern(unsigned char* buffer, size_t bytesRead, inst_set instructionSet) {
    switch (instructionSet) {
    case INSTRUCTION_SET_AVX512:
        return avx512_mem_scn(buffer, bytesRead);
    default:
        return generic_memory_scan(buffer, bytesRead);
    }
}

static __forceinline bool __fastcall __vld_pattern(const HANDLE hProcess) {
    inst_set cpu_instruction = __intr();
    const HANDLE hCurrentProcess = GetCurrentProcess();
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    unsigned char* address = nullptr;

    while (KeNtQueryVirtualMemory(hProcess, address, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr) == 0) {
        if ((mbi.State == MEM_COMMIT) &&
            (mbi.Protect & PAGE_READWRITE) &&
            (!(mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)))) {

            unsigned char* baseAddress = nullptr;
            SIZE_T bufferSize = 0;

            bufferSize = mbi.RegionSize / 2;

            const NTSTATUS allocStatus = KeNtAllocateVirtualMemory(
                hCurrentProcess,
                reinterpret_cast<PVOID*>(&baseAddress),
                0,
                &bufferSize,
                MEM_COMMIT,
                PAGE_READWRITE
            );

            if (allocStatus != ((NTSTATUS)0x00000000L)) {
                continue; 
            }

            unsigned char* pageStart = reinterpret_cast<unsigned char*>(mbi.BaseAddress);
            SIZE_T bytesRead = 0;
            const NTSTATUS rpm = KeNtReadVirtualMemory(hProcess, pageStart, baseAddress, bufferSize, &bytesRead);

            if (rpm == 0 && bytesRead > 0) {
                std::vector<std::string> memory_dump = __trigger_pattern(baseAddress, bytesRead, cpu_instruction);

                for (const auto& version : memory_dump) {
                    if (version.find("v2.17.5-2442") != std::string::npos) {
                        KeNtFreeVirtualMemory(hCurrentProcess, reinterpret_cast<PVOID*>(&baseAddress), &bufferSize, MEM_RELEASE);
                        return true;
                    }
                }
            }

            KeNtFreeVirtualMemory(hCurrentProcess, reinterpret_cast<PVOID*>(&baseAddress), &bufferSize, MEM_RELEASE);
        }

        address = reinterpret_cast<unsigned char*>(mbi.BaseAddress) + mbi.RegionSize;
    }

    return false;
}

static __forceinline bool __fastcall trace(const HANDLE hProcess, const DWORD_PTR baseAddress, const DWORD_PTR endAddress, const DWORD x /* expected */) {
    MEMORY_BASIC_INFORMATION mbi = { 0 };
    unsigned char* currentAddress = reinterpret_cast<unsigned char*>(baseAddress);
    const HANDLE hCurrentProcess = GetCurrentProcess();

    while (currentAddress < reinterpret_cast<unsigned char*>(endAddress)) {
        if (KeNtQueryVirtualMemory(hProcess, currentAddress, MemoryBasicInformation, &mbi, sizeof(mbi), nullptr) != 0) {
            break;
        }

        if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
            SIZE_T bytesRead = 0;
            size_t bufferSize = mbi.RegionSize;

            PVOID buffer = nullptr;
            const NTSTATUS __mm_alloc = KeNtAllocateVirtualMemory(hCurrentProcess, &buffer, 0, &bufferSize, MEM_COMMIT, PAGE_READWRITE);
            if (__mm_alloc != 0)
                return false;       

            const NTSTATUS _mm_read = KeNtReadVirtualMemory(hProcess, currentAddress, buffer, bufferSize, &bytesRead);
            if (_mm_read >= 0 && bytesRead == bufferSize) {
                for (size_t i = 0; i < bytesRead; i += sizeof(DWORD)) {
                    if (i + sizeof(DWORD) <= bytesRead) {
                        const DWORD value = *reinterpret_cast<DWORD*>(static_cast<unsigned char*>(buffer) + i);
                        if (value == x) {
                            KeNtFreeVirtualMemory(hProcess, &buffer, &bufferSize, MEM_RELEASE);
                            return true;
                        }
                    }
                }
            }

            KeNtFreeVirtualMemory(hProcess, &buffer, &bufferSize, MEM_RELEASE);
        }

        currentAddress += mbi.RegionSize;
    }

    return false;
}

static __forceinline void __fastcall __trigger_err() {
    const DWORD mseconds = 10000;
    fprintf((__acrt_iob_func(2)), "Minecraft Java not detected. Closing program in 10s...\n");
    LARGE_INTEGER delay = { 0 };

    const __int64 dwmseconds64 = (__int64)mseconds;
    const __int64 conversionFactor = 10000;
    const __int64 result = -(dwmseconds64 * conversionFactor);

    delay.QuadPart = result;
    KeNtDelayExecution(0, &delay);
    __fastfail(ERROR_SUCCESS);
}

void __fastcall start_memory_scan(const DWORD pid) {
    auto [baseAddress, endAddress] = __get_mem_range(pid);
    if (baseAddress == 0 || endAddress == 0) __trigger_err();

    HANDLE hProcess;
    OBJECT_ATTRIBUTES objAttr = { 0 };
    CLIENT_ID clientId = { 0 };
    clientId.UniqueProcess = UlongToHandle(pid);

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);
    const NTSTATUS status = KeNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &objAttr, &clientId);
    if (!((NTSTATUS)(status) >= 0)) __trigger_err();

    bool flag = true;
    flag &= trace(hProcess, baseAddress, endAddress, 524294); // +B8F450 - 06- push es
    flag &= trace(hProcess, baseAddress, endAddress, 4242546329); /* +B8F400 - 99 - cdq +B8F401 - 1E - push ds +B8F402 - E0 FC - loopne +B8F400 */

    if (flag) {
        std::cout << "Validating detection...\n";
        if (__vld_pattern(hProcess)) {
            std::cout << "[!] DoomsDay Client detected.\n";
        }
        else {
            std::cout << "[-] DoomsDay Client was detected outside Lunar Client. I only tested Vanilla, Lunar and Feather so be careful! :)" << std::endl;
        }
    }
    else {
        std::cout << "[+] DoomsDay Client not found in game's memory.\n";
    }

    KeNtClose(hProcess);
    system("pause");
}