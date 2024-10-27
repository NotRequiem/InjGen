#include <intrin.h>
#include <vector>
#include <string>
#include <windows.h>
#include <iostream>

constexpr size_t MIN_STRING_LENGTH = 12;

enum inst_set : int {
    INSTRUCTION_SET_NONE,
    INSTRUCTION_SET_SSE,
    INSTRUCTION_SET_AVX,
    INSTRUCTION_SET_AVX512
};

void __fastcall start_memory_scan(const DWORD pid);