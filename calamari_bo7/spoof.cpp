#include "globals.h"

void XorRangeWithSeed(void* Buf, ULONG Offset, ULONG Length, ULONG TotalLen)
{
    if (!Buf || Offset + Length > TotalLen)
        return;

    auto p = static_cast<UCHAR*>(Buf);
    for (ULONG i = 0; i < Length; i++)
        p[Offset + i] ^= g_SpoofSeed[i & 0x1F];
}

void SpoofSmbiosDmiStrings(void* DmiTable, ULONG Length)
{
    if (!DmiTable || Length < 8)
        return;

    auto base = static_cast<UCHAR*>(DmiTable);
    ULONG pos = 0;

    do {
        UCHAR structLen = base[pos + 1];
        if (structLen < 4)
            return;

        ULONG dataEnd = pos + structLen;
        if (dataEnd > Length)
            return;

        UCHAR type = base[pos];
        UCHAR targetStr1 = 0, targetStr2 = 0;

        if (type == 1 || type == 2 || type == 3) {
            if (structLen <= 7) goto next_struct;
            targetStr1 = base[pos + 7];
        } else if (type == 17) {
            if (structLen <= 0x1A) goto next_struct;
            targetStr1 = base[pos + 24];
            targetStr2 = base[pos + 26];
        }

        if (targetStr1 || targetStr2) {
            ULONG strPos = dataEnd;
            UCHAR strIdx = 1;

            while (strPos < Length && base[strPos]) {
                ULONG strStart = strPos;
                while (strPos < Length && base[strPos])
                    strPos++;

                ULONG strLen = strPos - strStart;

                if (strIdx == targetStr1 || strIdx == targetStr2) {
                    for (ULONG j = 0; j < strLen && j < 32; j++) {
                        UCHAR c = base[strStart + j] ^ g_SpoofSeed[j & 0x1F];
                        if ((UCHAR)(c - 33) > 0x5D)
                            c = (c % 26) + 'A';
                        base[strStart + j] = c;
                    }
                }

                strIdx++;
                strPos++;
            }
        }

    next_struct:
        {
            ULONG scan = dataEnd;
            while (scan + 1 < Length) {
                if (base[scan] == 0 && base[scan + 1] == 0) {
                    pos = scan + 2;
                    break;
                }
                scan++;
            }
            if (scan + 1 >= Length)
                break;
        }
    } while (pos + 4 < Length);
}

NTSTATUS SpoofInit(const void* Seed, ULONG SeedLen)
{
    __try {
        ULONG copyLen = (SeedLen <= 32) ? SeedLen : 32;
        RtlCopyMemory(g_SpoofSeed, Seed, copyLen);

        PCWSTR tpmNames[] = {
            L"\\Driver\\tpm",
            L"\\Driver\\TPM",
            L"\\Driver\\tpmpse",
        };

        for (int i = 0; i < 3; i++) {
            if (NT_SUCCESS(ResolveDriverObjectByName(tpmNames[i], &g_TpmDriverObject)))
                break;
        }

        if (g_TpmDriverObject) {
            g_OrigTpmDeviceControl = (PDRIVER_DISPATCH)_InterlockedExchange64(
                (volatile LONG64*)&g_TpmDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
                (LONG64)TpmHook_DeviceControl
            );
            DbgLog("TPM hooked");
        } else {
            DbgLog("TPM driver not found");
        }

        if (NT_SUCCESS(ResolveDriverObjectByName(L"\\Driver\\disk", &g_DiskDriverObject))) {
            g_OrigDiskDeviceControl = (PDRIVER_DISPATCH)_InterlockedExchange64(
                (volatile LONG64*)&g_DiskDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
                (LONG64)DiskHook_DeviceControl
            );
            DbgLog("Disk hooked");
        }

        if (NT_SUCCESS(ResolveDriverObjectByName(L"\\Driver\\mssmbios", &g_SmbiosDriverObject))) {
            g_OrigSmbiosSystemControl = (PDRIVER_DISPATCH)_InterlockedExchange64(
                (volatile LONG64*)&g_SmbiosDriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL],
                (LONG64)SmbiosHook_SystemControl
            );
            DbgLog("SMBIOS hooked");
        } else {
            DbgLog("mssmbios.sys not found");
        }

        g_HooksActive = TRUE;
        DbgLog("Spoof hooks active (seed: %02X%02X%02X%02X...)",
            g_SpoofSeed[0], g_SpoofSeed[1], g_SpoofSeed[2], g_SpoofSeed[3]);

        return STATUS_SUCCESS;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgLog("Exception in SpoofInit: 0x%X", GetExceptionCode());
        return GetExceptionCode();
    }
}

void SpoofCleanup()
{
    __try {
        g_HooksActive = FALSE;

        if (g_TpmDriverObject && g_OrigTpmDeviceControl) {
            _InterlockedExchange64(
                (volatile LONG64*)&g_TpmDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
                (LONG64)g_OrigTpmDeviceControl
            );
            ObfDereferenceObject(g_TpmDriverObject);
            g_TpmDriverObject = nullptr;
            DbgLog("TPM unhooked");
        }

        if (g_DiskDriverObject && g_OrigDiskDeviceControl) {
            _InterlockedExchange64(
                (volatile LONG64*)&g_DiskDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL],
                (LONG64)g_OrigDiskDeviceControl
            );
            ObfDereferenceObject(g_DiskDriverObject);
            g_DiskDriverObject = nullptr;
            DbgLog("Disk unhooked");
        }

        if (g_SmbiosDriverObject && g_OrigSmbiosSystemControl) {
            _InterlockedExchange64(
                (volatile LONG64*)&g_SmbiosDriverObject->MajorFunction[IRP_MJ_SYSTEM_CONTROL],
                (LONG64)g_OrigSmbiosSystemControl
            );
            ObfDereferenceObject(g_SmbiosDriverObject);
            g_SmbiosDriverObject = nullptr;
            DbgLog("SMBIOS unhooked");
        }
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        DbgLog("Exception in SpoofCleanup: 0x%X", GetExceptionCode());
    }
}
