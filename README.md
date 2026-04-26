# calamari

Kernel-mode driver for cross-process memory operations and hardware identity spoofing on Windows 10/11 x64. Designed to be loaded via KDMapper (or any manual mapper that passes a usermode buffer as `DriverObject`).

## Features

- **Shared-memory command interface** — 52-byte packed buffer, MDL-mapped from usermode, polled in a spin loop with heartbeat monitoring
- **Cross-process R/W** — `MmCopyVirtualMemory`-based reads and writes with intermediate kernel buffering (stack for ≤4KB, pool for larger)
- **Process image base resolution** — three fallback methods: `PsGetProcessSectionBaseAddress` → `PEB->ImageBaseAddress` → `PEB->Ldr->InLoadOrderModuleList`
- **HWID spoofing** — seed-based XOR hooks on disk serial (`IOCTL_STORAGE_QUERY_PROPERTY`), TPM EK/SRK (`TPM_SUBMIT_COMMAND`), and SMBIOS DMI strings (types 1/2/3/17)
- **Atomic hook installation** — `InterlockedExchange64` on driver `MajorFunction` tables, re-entrant safe via thread-ID checks
- **BSOD hardened** — SEH wrapping on every user-facing path, process liveness checks before every memory operation

## Building

You need Visual Studio 2022 with the v143 toolset and WDK 10.0.26100.0 installed.

```
msbuild calamari_bo7.sln /p:Configuration=Release /p:Platform=x64
```

Output lands in `bin/Release/driver_bo7.sys`.

## Command protocol

Loader allocates a `CALAMARI_CMD_BUF` struct, passes its VA as `DriverObject` to KDMapper. The driver MDL-maps it into kernel space and spins:

```
State=1 (loader sets)  →  kernel reads, dispatches, writes result  →  State=2 (kernel sets)
```

Every 256 idle ticks the kernel writes its heartbeat counter to `Result` so the loader can detect a stuck driver.

| Opcode | Name | What it does |
|--------|------|-------------|
| 1 | `GET_BASE` | Attaches to PID, returns image base |
| 2 | `READ_MEMORY` | Copies `[src, src+size)` from target → loader VA |
| 3 | `PROBE_BYTE` | Writes 1 to `Data[0]`, used as a ping |
| 6 | `WRITE_MEMORY` | Copies `[src, src+size)` from loader → target VA |
| 7 | `PROBE_QWORD` | Writes 1 as QWORD to `Data`, used as a ping |
| 9 | `GET_PEB` | Returns target PEB address |
| 14 | `SPOOF_INIT` | Seeds the XOR key and installs disk/TPM/SMBIOS hooks |
| 15 | `SPOOF_CLEANUP` | Restores original dispatch functions, derefs driver objects |

## Spoofing details

All three hooks follow the same pattern: intercept the IRP, build a new one to forward downstream, wait for completion, XOR the relevant fields in the response buffer, then complete the original IRP with modified data.

**Disk** — targets `STORAGE_DEVICE_DESCRIPTOR.SerialNumberOffset`, XORs up to 20 bytes of the serial string.

**TPM** — targets response payloads for command codes 305 (TPM2_ReadPublic), 334 (TPM2_GetCapability), 371 (TPM2_CreatePrimary). XORs two 32-byte regions at offsets 0x14 and 0x3C.

**SMBIOS** — hooks `IRP_MJ_SYSTEM_CONTROL` on `mssmbios.sys` with a completion routine. Walks the raw DMI table and XORs serial-number string fields for System Information (type 1), Baseboard (type 2), Chassis (type 3), and Memory Device (type 17). XOR'd bytes that fall outside printable ASCII are folded back into `[A-Z]`.

## File layout

```
calamari_bo7/
├── driver.h              — ntoskrnl imports, command struct, opcodes
├── globals.h             — all mutable state
├── driver_entry.cpp      — DriverEntry + worker thread
├── command_dispatch.cpp  — opcode switch
├── memory.cpp            — MmCopyVirtualMemory wrappers
├── process.cpp           — PID attach, base address resolution
├── spoof.cpp             — hook install/teardown, XOR logic
├── hooks.cpp             — IRP dispatch hooks (disk, TPM, SMBIOS)
└── util.cpp              — DbgLog, SafeVsnprintf
```

## Notes

- The driver abuses `DriverObject` as a buffer pointer because KDMapper doesn't provide a clean param-passing mechanism. This is intentional.
- `g_VestigialQword` exists solely to preserve the `.data` section layout from the original binary. It's zeroed on init and never read.
- The SMBIOS hook copies stack locations with SSE moves (`__m128i`) instead of `IoCopyCurrentIrpStackLocationToNext` to match specific codegen requirements.
- Worker thread teardown is graceful: it detects loader death via `PsGetProcessExitStatus` polling and cleans up all references before exiting.

## License

MIT
