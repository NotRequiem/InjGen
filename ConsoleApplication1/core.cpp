#include "proc.hh"
#include "mem.hpp"

auto main() ->
__int32
{

    std::unordered_set<DWORD> x;

    detect_all_instances(x);

    for (const DWORD pid : x) {
        printf("Reading virtual memory in 'javaw.exe' process with PID %d\n", pid);
        start_memory_scan(pid);
    }

    return 0;

}