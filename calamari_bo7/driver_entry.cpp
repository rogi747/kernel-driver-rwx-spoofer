#include "globals.h"

constexpr ULONG_PTR USERMODE_MAX = 0x7FFFFFFEFFFFULL;

void WorkerThreadMain(PVOID StartContext)
{
    auto sharedBuf = static_cast<UCHAR*>(StartContext);

    if (!sharedBuf) {
        DbgLog("null context, bailing");
        PsTerminateSystemThread(STATUS_INVALID_PARAMETER);
        return;
    }

    if ((ULONG_PTR)(sharedBuf - 0x10000) > USERMODE_MAX) {
        DbgLog("Shared buffer %p is not a valid usermode address", sharedBuf);
        PsTerminateSystemThread(STATUS_ACCESS_VIOLATION);
        return;
    }

    DbgLog("worker up, buf=%p loader=%p", sharedBuf, g_LoaderProcess);

    PMDL mdl = nullptr;
    KAPC_STATE apcState;
    KeStackAttachProcess(g_LoaderProcess, &apcState);
    __try {
        mdl = IoAllocateMdl(sharedBuf, sizeof(CALAMARI_CMD_BUF), FALSE, FALSE, nullptr);
        if (mdl)
            MmProbeAndLockPages(mdl, UserMode, IoModifyAccess);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgLog("Exception probing shared buffer pages: 0x%X", GetExceptionCode());
        if (mdl) {
            IoFreeMdl(mdl);
            mdl = nullptr;
        }
    }
    KeUnstackDetachProcess(&apcState);

    if (!mdl) {
        DbgLog("Failed to allocate MDL for shared buffer");
        PsTerminateSystemThread(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    auto mapped = static_cast<CALAMARI_CMD_BUF*>(
        MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, FALSE,
                                     g_MdlMapFlags | 0x10)
    );

    if (!mapped) {
        DbgLog("MmMapLockedPagesSpecifyCache returned NULL");
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
        PsTerminateSystemThread(STATUS_INSUFFICIENT_RESOURCES);
        return;
    }

    DbgLog("Shared buffer mapped to kernel address: %p", mapped);

    int reqCount   = 0;
    ULONG64 heartbeat = 0;
    int iterCount  = 0;
    int deadCount  = 0;
    NTSTATUS exitStatus = STATUS_SUCCESS;

    for (;;) {
        heartbeat++;

        if (++iterCount >= 10000) {
            iterCount = 0;
            if (!g_LoaderProcess) {
                DbgLog("Loader process is NULL, terminating (heartbeat=%llu, reqs=%d)",
                    heartbeat, reqCount);
                break;
            }
            if (PsGetProcessExitStatus(g_LoaderProcess) != STATUS_PENDING) {
                if (++deadCount > 50) {
                    DbgLog("Loader confirmed dead (heartbeat=%llu, reqs=%d)",
                        heartbeat, reqCount);
                    break;
                }
            } else {
                deadCount = 0;
            }
        }

        __try {
            if (mapped->State == 1) {
                reqCount++;

                CALAMARI_CMD_BUF local;
                __try {
                    RtlCopyMemory(&local, mapped, sizeof(local));

                    __try {
                        CommandDispatcher(&local);
                    } __except (EXCEPTION_EXECUTE_HANDLER) {
                        DbgLog("Exception in CommandDispatcher (req #%d): 0x%X",
                            reqCount, GetExceptionCode());
                        local.Result = 0;
                    }

                    local.State = 2;
                    RtlCopyMemory(mapped, &local, sizeof(local));
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    DbgLog("Exception accessing shared buffer (req #%d): 0x%X",
                        reqCount, GetExceptionCode());
                }
            } else if ((UCHAR)heartbeat == 0) {
                mapped->Result = heartbeat;
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        for (int i = 0; i < 200; i++)
            _mm_pause();
    }

    MmUnmapLockedPages(mapped, mdl);
    MmUnlockPages(mdl);
    IoFreeMdl(mdl);

    if (g_TargetProcess) {
        ObfDereferenceObject(g_TargetProcess);
        g_TargetProcess = nullptr;
    }
    if (g_LoaderProcess) {
        ObfDereferenceObject(g_LoaderProcess);
        g_LoaderProcess = nullptr;
    }
    g_TargetPidAndAttached.Attached = FALSE;

    DbgLog("worker exit");
    PsTerminateSystemThread(exitStatus);
}

extern "C"
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING /*RegistryPath*/)
{
    DbgLog("init");

    g_LoaderProcess = nullptr;
    g_TargetProcess = nullptr;
    g_VestigialQword = 0;
    RtlZeroMemory(&g_TargetPidAndAttached, sizeof(g_TargetPidAndAttached));

    g_LoaderProcess = IoGetCurrentProcess();
    ObfReferenceObject(g_LoaderProcess);

    if (!DriverObject) {
        DbgLog("Shared buffer pointer is NULL");
        return STATUS_INVALID_PARAMETER;
    }

    auto sharedBuf = reinterpret_cast<PVOID>(DriverObject);
    if ((ULONG_PTR)sharedBuf > USERMODE_MAX) {
        DbgLog("Shared buffer 0x%llX is not a valid usermode address", sharedBuf);
        return STATUS_ACCESS_VIOLATION;
    }

    DbgLog("Shared buffer from loader: 0x%llX", sharedBuf);

    HANDLE threadHandle = nullptr;
    NTSTATUS status = PsCreateSystemThread(
        &threadHandle,
        THREAD_ALL_ACCESS,
        nullptr, nullptr, nullptr,
        (PKSTART_ROUTINE)WorkerThreadMain,
        sharedBuf
    );

    if (!NT_SUCCESS(status)) {
        DbgLog("Failed to create worker thread: 0x%X", status);
        return status;
    }

    ZwClose(threadHandle);
    DbgLog("worker spawned");
    return STATUS_SUCCESS;
}
