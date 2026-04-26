#pragma once
#include "driver.h"

inline PEPROCESS  g_LoaderProcess       = nullptr;
inline PEPROCESS  g_TargetProcess       = nullptr;

#pragma pack(push, 1)
struct TARGET_STATE {
    ULONG    Pid;
    ULONG    _pad;
    BOOLEAN  Attached;
};
#pragma pack(pop)

inline TARGET_STATE g_TargetPidAndAttached = {};
inline ULONG64      g_VestigialQword       = 0;

inline UCHAR      g_SpoofSeed[32]        = {};

inline BOOLEAN          g_HooksActive             = FALSE;
inline PDRIVER_OBJECT   g_TpmDriverObject         = nullptr;
inline PDRIVER_DISPATCH g_OrigTpmDeviceControl    = nullptr;
inline PKTHREAD         g_TpmHookThread           = nullptr;
inline PDRIVER_OBJECT   g_DiskDriverObject        = nullptr;
inline PDRIVER_DISPATCH g_OrigDiskDeviceControl   = nullptr;
inline PKTHREAD         g_DiskHookThread          = nullptr;
inline PDRIVER_OBJECT   g_SmbiosDriverObject      = nullptr;
inline PDRIVER_DISPATCH g_OrigSmbiosSystemControl = nullptr;

inline POOL_TYPE g_PoolType     = NonPagedPool;
inline ULONG     g_MdlMapFlags  = 0;
inline LONG      g_RpmFailLogCount = 0;
