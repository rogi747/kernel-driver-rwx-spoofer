#include "globals.h"

constexpr SIZE_T MAX_COPY_SIZE   = 0x1000000;   // 16 MB
constexpr SIZE_T STACK_BUF_SIZE  = 0x1000;      // 4 KB
constexpr ULONG  POOL_TAG_CMAL  = 'lamC';

static bool IsValidUserAddr(ULONG64 va, SIZE_T size)
{
    return va >= 0x10000
        && va + size <= 0x7FFFFFFF0000ULL
        && !(va >= 0x800000000000ULL && va <= 0x7FFEFFFFFFFFULL);
}

NTSTATUS MmCopyFromRemote(PEPROCESS SourceProc, PVOID SourceAddr, PVOID Dest, SIZE_T Size)
{
    if (!SourceProc || !SourceAddr || !Dest || !Size)
        return STATUS_INVALID_PARAMETER;
    if (PsGetProcessExitStatus(SourceProc) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_UNSUCCESSFUL;

    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(
        SourceProc, SourceAddr,
        IoGetCurrentProcess(), Dest,
        Size, KernelMode, &bytes
    );
}

NTSTATUS MmCopyToRemote(PEPROCESS TargetProc, PVOID TargetAddr, PVOID Source, SIZE_T Size)
{
    if (!TargetProc || !TargetAddr || !Source || !Size)
        return STATUS_INVALID_PARAMETER;
    if (PsGetProcessExitStatus(TargetProc) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;
    if (KeGetCurrentIrql() > APC_LEVEL)
        return STATUS_UNSUCCESSFUL;

    SIZE_T bytes = 0;
    return MmCopyVirtualMemory(
        IoGetCurrentProcess(), Source,
        TargetProc, TargetAddr,
        Size, KernelMode, &bytes
    );
}

NTSTATUS InvokeReadProcessMemory(ULONG64 SrcTargetVa, ULONG64 DstLoaderVa, SIZE_T Size)
{
    if (!g_TargetProcess || !g_LoaderProcess ||
        !SrcTargetVa || !DstLoaderVa || !Size ||
        !IsValidUserAddr(SrcTargetVa, Size) || !IsValidUserAddr(DstLoaderVa, Size))
        return STATUS_INVALID_PARAMETER;

    if (PsGetProcessExitStatus(g_TargetProcess) != STATUS_PENDING ||
        PsGetProcessExitStatus(g_LoaderProcess) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;

    if (Size > MAX_COPY_SIZE)
        return STATUS_BUFFER_OVERFLOW;

    PVOID buf;
    BOOLEAN pooled = FALSE;
    UCHAR stackBuf[STACK_BUF_SIZE];

    if (Size > STACK_BUF_SIZE) {
        buf = ExAllocatePoolWithTag(g_PoolType, Size, POOL_TAG_CMAL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
        RtlZeroMemory(buf, Size);
        pooled = TRUE;
    } else {
        RtlZeroMemory(stackBuf, STACK_BUF_SIZE);
        buf = stackBuf;
    }

    NTSTATUS status = MmCopyFromRemote(g_TargetProcess, (PVOID)SrcTargetVa, buf, Size);
    if (NT_SUCCESS(status)) {
        if (PsGetProcessExitStatus(g_LoaderProcess) != STATUS_PENDING) {
            if (pooled)
                ExFreePoolWithTag(buf, POOL_TAG_CMAL);
            return STATUS_PROCESS_IS_TERMINATING;
        }

        SIZE_T bytes = 0;
        status = MmCopyVirtualMemory(
            IoGetCurrentProcess(), buf,
            g_LoaderProcess, (PVOID)DstLoaderVa,
            Size, KernelMode, &bytes
        );
    }

    if (pooled)
        ExFreePoolWithTag(buf, POOL_TAG_CMAL);
    return status;
}

NTSTATUS InvokeWriteProcessMemory(ULONG64 DstTargetVa, ULONG64 SrcLoaderVa, SIZE_T Size)
{
    if (!g_TargetProcess || !g_LoaderProcess ||
        !DstTargetVa || !SrcLoaderVa || !Size ||
        !IsValidUserAddr(DstTargetVa, Size) || !IsValidUserAddr(SrcLoaderVa, Size))
        return STATUS_INVALID_PARAMETER;

    if (PsGetProcessExitStatus(g_TargetProcess) != STATUS_PENDING ||
        PsGetProcessExitStatus(g_LoaderProcess) != STATUS_PENDING)
        return STATUS_PROCESS_IS_TERMINATING;

    PVOID buf;
    BOOLEAN pooled = FALSE;
    UCHAR stackBuf[STACK_BUF_SIZE];

    if (Size > STACK_BUF_SIZE) {
        buf = ExAllocatePoolWithTag(g_PoolType, Size, POOL_TAG_CMAL);
        if (!buf)
            return STATUS_INSUFFICIENT_RESOURCES;
        pooled = TRUE;
    } else {
        RtlZeroMemory(stackBuf, STACK_BUF_SIZE);
        buf = stackBuf;
    }

    SIZE_T bytes = 0;
    NTSTATUS status = MmCopyVirtualMemory(
        g_LoaderProcess, (PVOID)SrcLoaderVa,
        IoGetCurrentProcess(), buf,
        Size, KernelMode, &bytes
    );

    if (NT_SUCCESS(status))
        status = MmCopyToRemote(g_TargetProcess, (PVOID)DstTargetVa, buf, Size);

    if (pooled)
        ExFreePoolWithTag(buf, POOL_TAG_CMAL);
    return status;
}
