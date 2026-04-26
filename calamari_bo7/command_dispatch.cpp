#include "globals.h"

NTSTATUS CommandDispatcher(CALAMARI_CMD_BUF* Cmd)
{
    Cmd->Result = 1;

    switch (Cmd->Opcode) {

    case OP_GET_BASE: {
        if (!g_TargetPidAndAttached.Attached || g_TargetPidAndAttached.Pid != Cmd->Pid) {
            __try {
                AttachToTargetProcess((HANDLE)(ULONG_PTR)Cmd->Pid);
            } __except (EXCEPTION_EXECUTE_HANDLER) {}
        }

        if (!g_TargetPidAndAttached.Attached) {
            Cmd->Result = 0;
            return STATUS_UNSUCCESSFUL;
        }

        ULONG64 base = 0;
        __try {
            base = (ULONG64)GetProcessImageBase(g_TargetProcess);
        } __except (EXCEPTION_EXECUTE_HANDLER) {}

        *(ULONG64*)Cmd->Data = base;

        if (!base) {
            Cmd->Result = 0;
            return STATUS_UNSUCCESSFUL;
        }
        return STATUS_SUCCESS;
    }

    case OP_READ_MEMORY: {
        if (!g_TargetPidAndAttached.Attached || g_TargetPidAndAttached.Pid != Cmd->Pid)
            AttachToTargetProcess((HANDLE)(ULONG_PTR)Cmd->Pid);

        ULONG64 src  = *(ULONG64*)(Cmd->Data + 1);
        ULONG64 dst  = *(ULONG64*)(Cmd->Data + 9);
        ULONG64 size = *(ULONG64*)(Cmd->Data + 17);

        if (!g_TargetPidAndAttached.Attached || !src || !dst || !size) {
            Cmd->Result = 0;
            return STATUS_UNSUCCESSFUL;
        }

        if (g_TargetProcess && PsGetProcessExitStatus(g_TargetProcess) != STATUS_PENDING) {
            g_TargetPidAndAttached.Attached = FALSE;
            Cmd->Result = 0;
            return STATUS_PROCESS_IS_TERMINATING;
        }

        NTSTATUS st = InvokeReadProcessMemory(src, dst, (SIZE_T)size);
        if (!NT_SUCCESS(st)) {
            Cmd->Result = 0;
            if (g_RpmFailLogCount < 5) {
                DbgLog("ReadProcessMemory failed: addr=0x%llX size=%llu status=0x%X pid=%d",
                    src, size, st, g_TargetPidAndAttached.Pid);
                g_RpmFailLogCount++;
            }
        }
        return st;
    }

    case OP_PROBE_BYTE:
        Cmd->Data[0] = 1;
        return STATUS_SUCCESS;

    case OP_WRITE_MEMORY: {
        if (!g_TargetPidAndAttached.Attached || g_TargetPidAndAttached.Pid != Cmd->Pid)
            AttachToTargetProcess((HANDLE)(ULONG_PTR)Cmd->Pid);

        ULONG64 dstT = *(ULONG64*)(Cmd->Data + 1);
        ULONG64 srcL = *(ULONG64*)(Cmd->Data + 9);
        ULONG64 size = *(ULONG64*)(Cmd->Data + 17);

        if (!g_TargetPidAndAttached.Attached || !dstT || !srcL || !size) {
            Cmd->Result = 0;
            return STATUS_UNSUCCESSFUL;
        }

        if (g_TargetProcess && PsGetProcessExitStatus(g_TargetProcess) != STATUS_PENDING) {
            g_TargetPidAndAttached.Attached = FALSE;
            Cmd->Result = 0;
            return STATUS_PROCESS_IS_TERMINATING;
        }

        NTSTATUS st = InvokeWriteProcessMemory(dstT, srcL, (SIZE_T)size);
        if (!NT_SUCCESS(st))
            Cmd->Result = 0;
        return st;
    }

    case OP_PROBE_QWORD:
        *(ULONG64*)Cmd->Data = 1;
        return STATUS_SUCCESS;

    case OP_GET_PEB: {
        if (!g_TargetPidAndAttached.Attached || g_TargetPidAndAttached.Pid != Cmd->Pid)
            AttachToTargetProcess((HANDLE)(ULONG_PTR)Cmd->Pid);

        if (!g_TargetPidAndAttached.Attached) {
            Cmd->Result = 0;
            return STATUS_UNSUCCESSFUL;
        }

        ULONG64 peb = (ULONG64)PsGetProcessPeb(g_TargetProcess);
        *(ULONG64*)Cmd->Data = peb;
        if (!peb) {
            Cmd->Result = 0;
            return STATUS_UNSUCCESSFUL;
        }
        return STATUS_SUCCESS;
    }

    case OP_SPOOF_INIT: {
        NTSTATUS st = SpoofInit(Cmd->Data, 0x20);
        if (!NT_SUCCESS(st))
            Cmd->Result = 0;
        return st;
    }

    case OP_SPOOF_CLEANUP:
        SpoofCleanup();
        return STATUS_SUCCESS;

    default:
        Cmd->Result = 0;
        return STATUS_UNSUCCESSFUL;
    }
}
