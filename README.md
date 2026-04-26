# kernel-driver

Windows x64 kernel driver for cross-process memory I/O and hardware identity spoofing. Loaded via KDMapper — communicates with usermode through a shared memory buffer mapped with MDL.

> Built for Windows 10/11 x64 · VS2022 v143 · WDK 10.0.26100.0

---

## What it does

**Memory** — read and write arbitrary process memory from kernel via `MmCopyVirtualMemory`. Uses a stack buffer for small copies (≤4KB) and pooled allocation for larger ones. Three fallback methods for resolving a process's image base.

**HWID Spoofing** — installs dispatch hooks on `disk.sys`, `tpm.sys`, and `mssmbios.sys` using atomic `InterlockedExchange64` on `MajorFunction` tables. Intercepts storage/TPM/SMBIOS queries and XORs serial fields in the response with a 32-byte user-supplied seed.

**Communication** — 52-byte packed struct shared between usermode and kernel. The loader writes a command, the driver picks it up in a spin loop, executes it, and writes back the result. Heartbeat counter lets the loader detect a stuck or dead driver.

---

## Opcodes

| # | Name | Description |
|---|------|-------------|
| 1 | `GET_BASE` | Attach to PID, return image base |
| 2 | `READ_MEMORY` | Copy from target process → loader |
| 3 | `PROBE_BYTE` | Ping (writes `1` to buffer) |
| 6 | `WRITE_MEMORY` | Copy from loader → target process |
| 7 | `PROBE_QWORD` | Ping (writes `1` as QWORD) |
| 9 | `GET_PEB` | Return target PEB address |
| 14 | `SPOOF_INIT` | Install HWID hooks with XOR seed |
| 15 | `SPOOF_CLEANUP` | Remove hooks, restore originals |

---

## Spoof targets

| Driver | IOCTL / IRP | What gets XOR'd |
|--------|-------------|-----------------|
| `disk.sys` | `STORAGE_QUERY_PROPERTY` | Serial number string (up to 20 bytes) |
| `tpm.sys` | `TPM_SUBMIT_COMMAND` (codes 305, 334, 371) | EK/SRK regions at offsets 0x14 and 0x3C (32 bytes each) |
| `mssmbios.sys` | `IRP_MJ_SYSTEM_CONTROL` | DMI strings for System (1), Baseboard (2), Chassis (3), Memory (17) |

---

## Project structure

```
├── driver.h               undocumented ntoskrnl imports, command struct, opcodes
├── globals.h              all mutable state in one place
├── driver_entry.cpp       DriverEntry + worker thread loop
├── command_dispatch.cpp   opcode switch
├── memory.cpp             MmCopyVirtualMemory wrappers + validation
├── process.cpp            PID attach, driver object resolution, base address lookup
├── spoof.cpp              hook install/teardown, XOR routines
├── hooks.cpp              disk, TPM, SMBIOS IRP dispatch hooks
└── util.cpp               debug logging
```

---

## Build

```
msbuild calamari_bo7.sln /p:Configuration=Release /p:Platform=x64
```

Output: `bin/Release/driver_bo7.sys`

---

## Implementation notes

- `DriverObject` param is reused as a shared buffer pointer — KDMapper doesn't provide a clean way to pass arguments, so this is the standard workaround
- All user-facing code paths are wrapped in SEH to prevent BSODs from bad pointers or dying processes
- Hook re-entrancy is handled by comparing `KeGetCurrentThread()` against a stored thread pointer — if the hook itself issues the forwarded IRP, it passes through to the original handler
- SMBIOS hook copies IRP stack locations with raw `__m128i` moves instead of `IoCopyCurrentIrpStackLocationToNext` to match specific codegen layout
- Worker thread monitors loader liveness via `PsGetProcessExitStatus` and tears down cleanly on loader exit

---

## License

[MIT](LICENSE)
