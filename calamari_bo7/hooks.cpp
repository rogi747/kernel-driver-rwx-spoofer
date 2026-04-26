#include "globals.h"

constexpr ULONG POOL_TAG_DISK = 'DskS';
constexpr ULONG POOL_TAG_TPM  = 'TpmS';

extern "C"
NTSTATUS DiskHook_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (KeGetCurrentThread() == g_DiskHookThread)
        return g_OrigDiskDeviceControl(DeviceObject, Irp);

    if (!g_HooksActive)
        return g_OrigDiskDeviceControl(DeviceObject, Irp);

    auto stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_STORAGE_QUERY_PROPERTY)
        return g_OrigDiskDeviceControl(DeviceObject, Irp);

    ULONG inputLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen < 8)
        return g_OrigDiskDeviceControl(DeviceObject, Irp);

    auto userBuf = static_cast<UCHAR*>(Irp->AssociatedIrp.SystemBuffer);
    if (*(ULONG*)userBuf != 0)
        return g_OrigDiskDeviceControl(DeviceObject, Irp);

    ULONG allocSize = max(inputLen, outputLen) + 16;
    auto buf = static_cast<UCHAR*>(ExAllocatePoolWithTag(g_PoolType, allocSize, POOL_TAG_DISK));
    if (!buf)
        return g_OrigDiskDeviceControl(DeviceObject, Irp);

    RtlCopyMemory(buf, userBuf, inputLen);

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IO_STATUS_BLOCK iosb = {};
    g_DiskHookThread = KeGetCurrentThread();

    PIRP newIrp = IoBuildDeviceIoControlRequest(
        IOCTL_STORAGE_QUERY_PROPERTY,
        DeviceObject, buf, inputLen, buf, outputLen,
        FALSE, &event, &iosb
    );

    if (!newIrp) {
        g_DiskHookThread = nullptr;
        ExFreePoolWithTag(buf, POOL_TAG_DISK);
        return g_OrigDiskDeviceControl(DeviceObject, Irp);
    }

    NTSTATUS status = IoCallDriver(DeviceObject, newIrp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
        status = iosb.Status;
    }
    g_DiskHookThread = nullptr;

    ULONG_PTR info = 0;
    if (NT_SUCCESS(status) && iosb.Information) {
        ULONG returned = (ULONG)iosb.Information;

        if (returned >= 0x30) {
            ULONG serialOffset = *(ULONG*)(buf + 36);
            if (serialOffset && serialOffset < returned - 4) {
                ULONG xorLen = 20;
                if (returned - serialOffset < 20)
                    xorLen = returned - serialOffset;
                XorRangeWithSeed(buf, serialOffset, xorLen, returned);
            }
        }

        ULONG copyLen = min(returned, outputLen);
        info = copyLen;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, buf, copyLen);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    ExFreePoolWithTag(buf, POOL_TAG_DISK);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

static ULONG ReadBigEndian32(const UCHAR* p)
{
    return ((ULONG)p[0] << 24) | ((ULONG)p[1] << 16) | ((ULONG)p[2] << 8) | p[3];
}

extern "C"
NTSTATUS TpmHook_DeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (KeGetCurrentThread() == g_TpmHookThread)
        return g_OrigTpmDeviceControl(DeviceObject, Irp);

    if (!g_HooksActive)
        return g_OrigTpmDeviceControl(DeviceObject, Irp);

    auto stack = IoGetCurrentIrpStackLocation(Irp);
    if (stack->Parameters.DeviceIoControl.IoControlCode != IOCTL_TPM_SUBMIT_COMMAND)
        return g_OrigTpmDeviceControl(DeviceObject, Irp);

    ULONG inputLen  = stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG outputLen = stack->Parameters.DeviceIoControl.OutputBufferLength;

    if (inputLen < 10)
        return g_OrigTpmDeviceControl(DeviceObject, Irp);

    auto userBuf = static_cast<UCHAR*>(Irp->AssociatedIrp.SystemBuffer);

    ULONG cmdCode = ReadBigEndian32(userBuf + 6);
    if (cmdCode != 371 && cmdCode != 305 && cmdCode != 334)
        return g_OrigTpmDeviceControl(DeviceObject, Irp);

    ULONG allocSize = max(inputLen, outputLen) + 16;
    auto buf = static_cast<UCHAR*>(ExAllocatePoolWithTag(g_PoolType, allocSize, POOL_TAG_TPM));
    if (!buf)
        return g_OrigTpmDeviceControl(DeviceObject, Irp);

    RtlCopyMemory(buf, userBuf, inputLen);

    KEVENT event;
    KeInitializeEvent(&event, NotificationEvent, FALSE);

    IO_STATUS_BLOCK iosb = {};
    g_TpmHookThread = KeGetCurrentThread();

    PIRP newIrp = IoBuildDeviceIoControlRequest(
        IOCTL_TPM_SUBMIT_COMMAND,
        DeviceObject, buf, inputLen, buf, outputLen,
        FALSE, &event, &iosb
    );

    if (!newIrp) {
        g_TpmHookThread = nullptr;
        ExFreePoolWithTag(buf, POOL_TAG_TPM);
        return g_OrigTpmDeviceControl(DeviceObject, Irp);
    }

    NTSTATUS status = IoCallDriver(DeviceObject, newIrp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, nullptr);
        status = iosb.Status;
    }
    g_TpmHookThread = nullptr;

    ULONG_PTR info = 0;
    if (NT_SUCCESS(status) && iosb.Information) {
        ULONG returned = (ULONG)iosb.Information;

        if (returned >= 12) {
            ULONG respCode = ReadBigEndian32(buf + 6);
            if (respCode == 0) {
                if (returned > 0x34) {
                    for (int i = 0; i < 32; i++)
                        buf[20 + i] ^= g_SpoofSeed[i & 0x1F];
                }
                if (returned > 0x5C) {
                    for (int i = 0; i < 32; i++)
                        buf[60 + i] ^= g_SpoofSeed[i & 0x1F];
                }
            }
        }

        ULONG copyLen = min(returned, outputLen);
        info = copyLen;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, buf, copyLen);
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = info;
    ExFreePoolWithTag(buf, POOL_TAG_TPM);
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// Manual stack-location copy to match original codegen layout
extern "C"
NTSTATUS SmbiosHook_SystemControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (!g_HooksActive)
        return g_OrigSmbiosSystemControl(DeviceObject, Irp);

    PIO_STACK_LOCATION current = IoGetCurrentIrpStackLocation(Irp);
    PIO_STACK_LOCATION next    = IoGetNextIrpStackLocation(Irp);

    *(__m128i*)&next->MajorFunction       = *(__m128i*)&current->MajorFunction;
    *(__m128i*)&next->Parameters          = *(__m128i*)&current->Parameters;
    *(__m128i*)((UCHAR*)&next->Parameters + 16) = *(__m128i*)((UCHAR*)&current->Parameters + 16);
    next->FileObject = current->FileObject;
    next->Control    = 0;

    next->CompletionRoutine = SmbiosHook_CompletionRoutine;
    next->Context           = nullptr;
    next->Control           = 0x40;

    return IoCallDriver(DeviceObject, Irp);
}

NTSTATUS SmbiosHook_CompletionRoutine(PDEVICE_OBJECT /*DeviceObject*/, PIRP Irp, PVOID /*Context*/)
{
    if (Irp->IoStatus.Status == STATUS_SUCCESS && g_HooksActive) {
        PMDL mdl = Irp->MdlAddress;
        if (mdl) {
            PVOID mapped = (mdl->MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL))
                ? mdl->MappedSystemVa
                : MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, nullptr, FALSE, g_MdlMapFlags | 0x10);

            if (mapped) {
                ULONG byteCount = MmGetMdlByteCount(mdl);
                if (byteCount > 8)
                    SpoofSmbiosDmiStrings(mapped, byteCount);
            }
        }
    }

    if (Irp->PendingReturned)
        Irp->Tail.Overlay.CurrentStackLocation->Control |= 1;

    return STATUS_SUCCESS;
}
