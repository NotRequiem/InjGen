#pragma once

#ifndef Ke_HEADER_H_
#define Ke_HEADER_H_

#include <windows.h>

#ifndef _NTDEF_
typedef _Return_type_success_(return >= 0) LONG NTSTATUS;
typedef NTSTATUS* PNTSTATUS;
#endif

#define Ke_SEED 0x28C5192F
#define Ke_ROL8(v) (v << 8 | v >> 24)
#define Ke_ROR8(v) (v >> 8 | v << 24)
#define Ke_ROX8(v) ((Ke_SEED % 2) ? Ke_ROL8(v) : Ke_ROR8(v))
#define Ke_MAX_ENTRIES 600
#define Ke_RVA2VA(Type, DllBase, Rva) (Type)((ULONG_PTR) DllBase + Rva)

typedef struct _Ke_SYSCALL_ENTRY
{
	DWORD Hash;
	DWORD Address;
	PVOID SyscallAddress;
} Ke_SYSCALL_ENTRY, * PKe_SYSCALL_ENTRY;

typedef struct _Ke_SYSCALL_LIST
{
	DWORD Count;
	Ke_SYSCALL_ENTRY Entries[Ke_MAX_ENTRIES];
} Ke_SYSCALL_LIST, * PKe_SYSCALL_LIST;

typedef struct _Ke_PEB_LDR_DATA {
	BYTE Reserved1[8];
	PVOID Reserved2[3];
	LIST_ENTRY InMemoryOrderModuleList;
} Ke_PEB_LDR_DATA, * PKe_PEB_LDR_DATA;

typedef struct _Ke_LDR_DATA_TABLE_ENTRY {
	PVOID Reserved1[2];
	LIST_ENTRY InMemoryOrderLinks;
	PVOID Reserved2[2];
	PVOID DllBase;
} Ke_LDR_DATA_TABLE_ENTRY, * PKe_LDR_DATA_TABLE_ENTRY;

typedef struct _Ke_PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PKe_PEB_LDR_DATA Ldr;
} Ke_PEB, * PKe_PEB;

DWORD Ke_HashSyscall(PCSTR FunctionName);
BOOL Ke_PopulateSyscallList();
EXTERN_C DWORD Ke_GetSyscallNumber(DWORD FunctionHash);
EXTERN_C PVOID Ke_GetSyscallAddress(DWORD FunctionHash);
EXTERN_C PVOID internal_cleancall_wow64_gate(VOID);
typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

#pragma once

#include <Windows.h>

#ifndef InitializeObjectAttributes
#define InitializeObjectAttributes( p, n, a, r, s ) { \
	(p)->Length = sizeof( OBJECT_ATTRIBUTES );        \
	(p)->RootDirectory = r;                           \
	(p)->Attributes = a;                              \
	(p)->ObjectName = n;                              \
	(p)->SecurityDescriptor = s;                      \
	(p)->SecurityQualityOfService = NULL;             \
}
#endif

typedef enum _PROCESSINFOCLASS
{
	ProcessBasicInformation,            // q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
	ProcessQuotaLimits,                 // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
	ProcessIoCounters,                  // q: IO_COUNTERS
	ProcessVmCounters,                  // q: VM_COUNTERS, VM_COUNTERS_EX, VM_COUNTERS_EX2
	ProcessTimes,                       // q: KERNEL_USER_TIMES
	ProcessBasePriority,                // s: KPRIORITY
	ProcessRaisePriority,               // s: ULONG
	ProcessDebugPort,                   // q: HANDLE
	ProcessExceptionPort,               // s: PROCESS_EXCEPTION_PORT (requires SeTcbPrivilege)
	ProcessAccessToken,                 // s: PROCESS_ACCESS_TOKEN
	ProcessLdtInformation,              // qs: PROCESS_LDT_INFORMATION // 10
	ProcessLdtSize,                     // s: PROCESS_LDT_SIZE
	ProcessDefaultHardErrorMode,        // qs: ULONG
	ProcessIoPortHandlers,              // (kernel-mode only) // PROCESS_IO_PORT_HANDLER_INFORMATION
	ProcessPooledUsageAndLimits,        // q: POOLED_USAGE_AND_LIMITS
	ProcessWorkingSetWatch,             // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
	ProcessUserModeIOPL,                // qs: ULONG (requires SeTcbPrivilege)
	ProcessEnableAlignmentFaultFixup,   // s: BOOLEAN
	ProcessPriorityClass,               // qs: PROCESS_PRIORITY_CLASS
	ProcessWx86Information,             // qs: ULONG (requires SeTcbPrivilege) (VdmAllowed)
	ProcessHandleCount,                 // q: ULONG, PROCESS_HANDLE_INFORMATION // 20
	ProcessAffinityMask,                // (q >WIN7)s: KAFFINITY, qs: GROUP_AFFINITY
	ProcessPriorityBoost,               // qs: ULONG
	ProcessDeviceMap,                   // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
	ProcessSessionInformation,          // q: PROCESS_SESSION_INFORMATION
	ProcessForegroundInformation,       // s: PROCESS_FOREGROUND_BACKGROUND
	ProcessWow64Information,            // q: ULONG_PTR
	ProcessImageFileName,               // q: UNICODE_STRING
	ProcessLUIDDeviceMapsEnabled,       // q: ULONG
	ProcessBreakOnTermination,          // qs: ULONG
	ProcessDebugObjectHandle,           // q: HANDLE // 30
	ProcessDebugFlags,                  // qs: ULONG
	ProcessHandleTracing,               // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
	ProcessIoPriority,                  // qs: IO_PRIORITY_HINT
	ProcessExecuteFlags,                // qs: ULONG
	ProcessTlsInformation,              // PROCESS_TLS_INFORMATION // ProcessResourceManagement
	ProcessCookie,                      // q: ULONG
	ProcessImageInformation,            // q: SECTION_IMAGE_INFORMATION
	ProcessCycleTime,                   // q: PROCESS_CYCLE_TIME_INFORMATION // since VISTA
	ProcessPagePriority,                // qs: PAGE_PRIORITY_INFORMATION
	ProcessInstrumentationCallback,     // s: PVOID or PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION // 40
	ProcessThreadStackAllocation,       // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
	ProcessWorkingSetWatchEx,           // q: PROCESS_WS_WATCH_INFORMATION_EX[]
	ProcessImageFileNameWin32,          // q: UNICODE_STRING
	ProcessImageFileMapping,            // q: HANDLE (input)
	ProcessAffinityUpdateMode,          // qs: PROCESS_AFFINITY_UPDATE_MODE
	ProcessMemoryAllocationMode,        // qs: PROCESS_MEMORY_ALLOCATION_MODE
	ProcessGroupInformation,            // q: USHORT[]
	ProcessTokenVirtualizationEnabled,  // s: ULONG
	ProcessConsoleHostProcess,          // q: ULONG_PTR // ProcessOwnerInformation
	ProcessWindowInformation,           // q: PROCESS_WINDOW_INFORMATION // 50
	ProcessHandleInformation,           // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
	ProcessMitigationPolicy,            // s: PROCESS_MITIGATION_POLICY_INFORMATION
	ProcessDynamicFunctionTableInformation,
	ProcessHandleCheckingMode,         // qs: ULONG; s: 0 disables, otherwise enables
	ProcessKeepAliveCount,             // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
	ProcessRevokeFileHandles,          // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
	ProcessWorkingSetControl,          // s: PROCESS_WORKING_SET_CONTROL
	ProcessHandleTable,                // q: ULONG[] // since WINBLUE
	ProcessCheckStackExtentsMode,      // qs: ULONG // KPROCESS->CheckStackExtents (CFG)
	ProcessCommandLineInformation,     // q: UNICODE_STRING // 60
	ProcessProtectionInformation,      // q: PS_PROTECTION
	ProcessMemoryExhaustion,           // PROCESS_MEMORY_EXHAUSTION_INFO // since THRESHOLD
	ProcessFaultInformation,           // PROCESS_FAULT_INFORMATION
	ProcessTelemetryIdInformation,     // q: PROCESS_TELEMETRY_ID_INFORMATION
	ProcessCommitReleaseInformation,   // PROCESS_COMMIT_RELEASE_INFORMATION
	ProcessDefaultCpuSetsInformation,  // SYSTEM_CPU_SET_INFORMATION[5]
	ProcessAllowedCpuSetsInformation,  // SYSTEM_CPU_SET_INFORMATION[5]
	ProcessSubsystemProcess,
	ProcessJobMemoryInformation,                  // q: PROCESS_JOB_MEMORY_INFO
	ProcessInPrivate,                             // s: void // ETW // since THRESHOLD2 // 70
	ProcessRaiseUMExceptionOnInvalidHandleClose,  // qs: ULONG; s: 0 disables, otherwise enables
	ProcessIumChallengeResponse,
	ProcessChildProcessInformation,          // q: PROCESS_CHILD_PROCESS_INFORMATION
	ProcessHighGraphicsPriorityInformation,  // qs: BOOLEAN (requires SeTcbPrivilege)
	ProcessSubsystemInformation,             // q: SUBSYSTEM_INFORMATION_TYPE // since REDSTONE2
	ProcessEnergyValues,                     // q: PROCESS_ENERGY_VALUES, PROCESS_EXTENDED_ENERGY_VALUES
	ProcessPowerThrottlingState,             // qs: POWER_THROTTLING_PROCESS_STATE
	ProcessReserved3Information,             // ProcessActivityThrottlePolicy // PROCESS_ACTIVITY_THROTTLE_POLICY
	ProcessWin32kSyscallFilterInformation,   // q: WIN32K_SYSCALL_FILTER
	ProcessDisableSystemAllowedCpuSets,      // 80
	ProcessWakeInformation,                  // PROCESS_WAKE_INFORMATION
	ProcessEnergyTrackingState,              // PROCESS_ENERGY_TRACKING_STATE
	ProcessManageWritesToExecutableMemory,   // MANAGE_WRITES_TO_EXECUTABLE_MEMORY // since REDSTONE3
	ProcessCaptureTrustletLiveDump,
	ProcessTelemetryCoverage,
	ProcessEnclaveInformation,
	ProcessEnableReadWriteVmLogging,            // PROCESS_READWRITEVM_LOGGING_INFORMATION
	ProcessUptimeInformation,                   // q: PROCESS_UPTIME_INFORMATION
	ProcessImageSection,                        // q: HANDLE
	ProcessDebugAuthInformation,                // since REDSTONE4 // 90
	ProcessSystemResourceManagement,            // PROCESS_SYSTEM_RESOURCE_MANAGEMENT
	ProcessSequenceNumber,                      // q: ULONGLONG
	ProcessLoaderDetour,                        // since REDSTONE5
	ProcessSecurityDomainInformation,           // PROCESS_SECURITY_DOMAIN_INFORMATION
	ProcessCombineSecurityDomainsInformation,   // PROCESS_COMBINE_SECURITY_DOMAINS_INFORMATION
	ProcessEnableLogging,                       // PROCESS_LOGGING_INFORMATION
	ProcessLeapSecondInformation,               // PROCESS_LEAP_SECOND_INFORMATION
	ProcessFiberShadowStackAllocation,          // PROCESS_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION // since 19H1
	ProcessFreeFiberShadowStackAllocation,      // PROCESS_FREE_FIBER_SHADOW_STACK_ALLOCATION_INFORMATION
	ProcessAltSystemCallInformation,            // qs: BOOLEAN (kernel-mode only) // INT2E // since 20H1 // 100
	ProcessDynamicEHContinuationTargets,        // PROCESS_DYNAMIC_EH_CONTINUATION_TARGETS_INFORMATION
	ProcessDynamicEnforcedCetCompatibleRanges,  // PROCESS_DYNAMIC_ENFORCED_ADDRESS_RANGE_INFORMATION // since 20H2
	ProcessCreateStateChange,                   // since WIN11
	ProcessApplyStateChange,
	ProcessEnableOptionalXStateFeatures,
	ProcessAltPrefetchParam,  // since 22H1
	ProcessAssignCpuPartitions,
	ProcessPriorityClassEx,  // s: PROCESS_PRIORITY_CLASS_EX
	ProcessMembershipInformation,
	ProcessEffectiveIoPriority,    // q: IO_PRIORITY_HINT
	ProcessEffectivePagePriority,  // q: ULONG
	MaxProcessInfoClass
} PROCESSINFOCLASS, * PPROCESSINFOCLASS;

typedef enum _MEMORY_INFORMATION_CLASS
{
	MemoryBasicInformation,
	MemoryWorkingSetInformation,
	MemoryMappedFilenameInformation,
	MemoryRegionInformation,
	MemoryWorkingSetExInformation,
	MemorySharedCommitInformation,
	MemoryImageInformation,
	MemoryRegionInformationEx,
	MemoryPrivilegedBasicInformation,
	MemoryEnclaveImageInformation,
	MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS, * PMEMORY_INFORMATION_CLASS;

typedef struct _CLIENT_ID
{
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG           Length;
	HANDLE          RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG           Attributes;
	PVOID           SecurityDescriptor;
	PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;


EXTERN_C NTSTATUS KeNtReadVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress OPTIONAL,
	OUT PVOID Buffer,
	IN SIZE_T BufferSize,
	OUT PSIZE_T NumberOfBytesRead OPTIONAL);

EXTERN_C NTSTATUS KeNtAllocateVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN ULONG ZeroBits,
	IN OUT PSIZE_T RegionSize,
	IN ULONG AllocationType,
	IN ULONG Protect);

EXTERN_C NTSTATUS KeNtFreeVirtualMemory(
	IN HANDLE ProcessHandle,
	IN OUT PVOID* BaseAddress,
	IN OUT PSIZE_T RegionSize,
	IN ULONG FreeType);

EXTERN_C NTSTATUS KeNtQueryVirtualMemory(
	IN HANDLE ProcessHandle,
	IN PVOID BaseAddress,
	IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
	OUT PVOID MemoryInformation,
	IN SIZE_T MemoryInformationLength,
	OUT PSIZE_T ReturnLength OPTIONAL);


EXTERN_C NTSTATUS KeNtQueryInformationProcess(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

EXTERN_C NTSTATUS KeNtClose(
	IN HANDLE Handle);

EXTERN_C NTSTATUS KeNtDelayExecution(
	IN BOOLEAN Alertable,
	IN PLARGE_INTEGER DelayInterval);

EXTERN_C NTSTATUS KeNtOpenProcess(
	OUT PHANDLE ProcessHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	IN PCLIENT_ID ClientId OPTIONAL);

#endif