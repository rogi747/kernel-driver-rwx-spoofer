#include "globals.h"

NTSTATUS ResolveDriverObjectByName(PCWSTR DriverName, PDRIVER_OBJECT* OutDriverObject)
{
    if (!OutDriverObject)
        return STATUS_INVALID_PARAMETER;

    UNICODE_STRING name;
    RtlInitUnicodeString(&name, DriverName);

    PVOID object = nullptr;
    NTSTATUS status = ObReferenceObjectByName(
        &name,
        OBJ_CASE_INSENSITIVE,
        nullptr,
        0,
        *IoDriverObjectType,
        KernelMode,
        nullptr,
        &object
    );

    if (NT_SUCCESS(status))
        *OutDriverObject = static_cast<PDRIVER_OBJECT>(object);

    return status;
}

NTSTATUS AttachToTargetProcess(HANDLE ProcessId)
{
    ULONG pid = (ULONG)(ULONG_PTR)ProcessId;
    if (!pid)
        return STATUS_INVALID_PARAMETER;

    if (g_TargetProcess) {
        ObfDereferenceObject(g_TargetProcess);
        g_TargetProcess = nullptr;
    }
    g_TargetPidAndAttached.Attached = FALSE;

    PEPROCESS process = nullptr;
    NTSTATUS status = PsLookupProcessByProcessId(ProcessId, &process);
    if (!NT_SUCCESS(status)) {
        DbgLog("Failed to find process %d: 0x%X", pid, status);
        return status;
    }

    NTSTATUS exitStatus;
    __try {
        exitStatus = PsGetProcessExitStatus(process);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgLog("Exception checking process %d exit status", pid);
        ObfDereferenceObject(process);
        return GetExceptionCode();
    }

    if (exitStatus != STATUS_PENDING) {
        DbgLog("Process %d is terminating, refusing attach", pid);
        ObfDereferenceObject(process);
        return STATUS_PROCESS_IS_TERMINATING;
    }

    g_TargetProcess = process;
    g_TargetPidAndAttached.Pid = pid;
    g_TargetPidAndAttached.Attached = TRUE;
    DbgLog("Attached to process %d", pid);
    return STATUS_SUCCESS;
}

PVOID GetProcessImageBase(PEPROCESS Process)
{
    if (!Process)
        return nullptr;

    NTSTATUS exitStatus;
    __try {
        exitStatus = PsGetProcessExitStatus(Process);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return nullptr;
    }

    if (exitStatus != STATUS_PENDING)
        return nullptr;

    PVOID base = nullptr;

    // PsGetProcessSectionBaseAddress (fastest path)
    __try {
        base = PsGetProcessSectionBaseAddress(Process);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}
    if (base)
        return base;

    // PEB->ImageBaseAddress (offset 0x10)
    PPEB peb = nullptr;
    __try {
        peb = PsGetProcessPeb(Process);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (peb) {
        KAPC_STATE apcState;
        __try {
            KeStackAttachProcess(Process, &apcState);
            __try {
                base = *(PVOID*)((UCHAR*)peb + 0x10);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            KeUnstackDetachProcess(&apcState);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }
    if (base)
        return base;

    // PEB->Ldr->InLoadOrderModuleList first entry DllBase
    PPEB peb2 = nullptr;
    __try {
        peb2 = PsGetProcessPeb(Process);
    } __except (EXCEPTION_EXECUTE_HANDLER) {}

    if (peb2) {
        KAPC_STATE apcState;
        __try {
            KeStackAttachProcess(Process, &apcState);
            __try {
                ULONG_PTR ldr = *(ULONG_PTR*)((UCHAR*)peb2 + 0x18);
                if (ldr) {
                    PLIST_ENTRY head  = (PLIST_ENTRY)(ldr + 0x10);
                    PLIST_ENTRY first = head->Flink;
                    if (first && first != head)
                        base = *(PVOID*)((UCHAR*)first + 0x30);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
            KeUnstackDetachProcess(&apcState);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}
    }

    if (!base)
        DbgLog("All methods failed to resolve base address for EPROCESS %p", Process);

    return base;
}
