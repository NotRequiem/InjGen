#pragma once

#include <windows.h>
#include <unordered_set>
#include <string>
#include <utility>
#include <psapi.h>

void __fastcall detect_all_instances(std::unordered_set<DWORD>& processes);
std::pair<DWORD_PTR, DWORD_PTR> __fastcall __get_mem_range(const DWORD processID);