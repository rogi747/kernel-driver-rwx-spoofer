#pragma once

extern "C" {
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>
}

#include <intrin.h>

extern "C" {

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    PUNICODE_STRING ObjectName,
    ULONG Attributes,
    PACCESS_STATE AccessState,
    ACCESS_MASK DesiredAccess,
    POBJECT_TYPE ObjectType,
    KPROCESSOR_MODE AccessMode,
    PVOID ParseContext,
    PVOID* Object
);

NTKERNELAPI POBJECT_TYPE* IoDriverObjectType;

NTKERNELAPI NTSTATUS MmCopyVirtualMemory(
    PEPROCESS SourceProcess,
    PVOID SourceAddress,
    PEPROCESS TargetProcess,
    PVOID TargetAddress,
    SIZE_T BufferSize,
    KPROCESSOR_MODE PreviousMode,
    PSIZE_T ReturnSize
);

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(PEPROCESS Process);
NTKERNELAPI PPEB PsGetProcessPeb(PEPROCESS Process);
NTKERNELAPI NTSTATUS PsGetProcessExitStatus(PEPROCESS Process);

} // extern "C"

constexpr ULONG IOCTL_STORAGE_QUERY_PROPERTY = 0x2D1400;
constexpr ULONG IOCTL_TPM_SUBMIT_COMMAND      = 0x221000;

#pragma pack(push, 1)
struct CALAMARI_CMD_BUF {
    ULONG   State;          // 0 = idle, 1 = request pending, 2 = response ready
    ULONG   Opcode;
    ULONG   Pid;
    UCHAR   Data[32];       // opcode-specific payload
    ULONG64 Result;         // 1 = success, 0 = failure
};
#pragma pack(pop)

static_assert(sizeof(CALAMARI_CMD_BUF) == 52, "command buffer size mismatch");

enum CaOp : ULONG {
    OP_GET_BASE          = 1,
    OP_READ_MEMORY       = 2,
    OP_PROBE_BYTE        = 3,
    OP_WRITE_MEMORY      = 6,
    OP_PROBE_QWORD       = 7,
    OP_GET_PEB           = 9,
    OP_SPOOF_INIT        = 14,
    OP_SPOOF_CLEANUP     = 15,
};

// util.cpp
void DbgLog(const char* Format, ...);
void SafeVsnprintf(char* Dest, SIZE_T MaxLen, const char* Format, ...);

// process.cpp
NTSTATUS ResolveDriverObjectByName(PCWSTR DriverName, PDRIVER_OBJECT* OutDriverObject);
NTSTATUS AttachToTargetProcess(HANDLE ProcessId);
PVOID    GetProcessImageBase(PEPROCESS Process);

// memory.cpp
NTSTATUS InvokeReadProcessMemory(ULONG64 SrcTargetVa, ULONG64 DstLoaderVa, SIZE_T Size);
NTSTATUS InvokeWriteProcessMemory(ULONG64 DstTargetVa, ULONG64 SrcLoaderVa, SIZE_T Size);
NTSTATUS MmCopyFromRemote(PEPROCESS SourceProc, PVOID SourceAddr, PVOID Dest, SIZE_T Size);
NTSTATUS MmCopyToRemote(PEPROCESS TargetProc, PVOID TargetAddr, PVOID Source, SIZE_T Size);

// command_dispatch.cpp
NTSTATUS CommandDispatcher(CALAMARI_CMD_BUF* CmdBuf);

// spoof.cpp
NTSTATUS SpoofInit(const void* Seed, ULONG SeedLen);
void     SpoofCleanup();
void     XorRangeWithSeed(void* Buf, ULONG Offset, ULONG Length, ULONG TotalLen);
void     SpoofSmbiosDmiStrings(void* DmiTable, ULONG Length);

// hooks.cpp
extern "C" NTSTATUS DiskHook_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS TpmHook_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
extern "C" NTSTATUS SmbiosHook_SystemControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS SmbiosHook_CompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context);

// driver_entry.cpp
void WorkerThreadMain(PVOID StartContext);
