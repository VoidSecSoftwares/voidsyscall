# VoidSysCall

Zero-API Windows implant. Every syscall goes through a direct `syscall` instruction — no `ntdll.dll`, no imports, no hook surface.

## Features

- **Direct syscall** — resolved at runtime via the PEB, no `GetProcAddress`
- **PEB walker** — enumerates loaded modules and their exports by hash
- **In-memory injection** — NtCreateThreadEx, hollowing, module stomping, queued APC, **atom bombing**, **polymorphic rotation**
- **Anti-forensics** — event log nuke, prefetch wipe, USN journal clear, timestomping, ADS hide, VSS delete, memory stomp, registry scrub
- **Persistence** — WMI event sub, COM hijack, BCD bootkit, scheduled task, service DLL, AppInit, Winlogon, LSA notification
- **Lateral movement** — WMI exec, DCOM, PsExec, pass-the-hash, RDP session hijack
- **Evasion** — ETW block, WFP rule, AMSI HWBP patch, call stack spoof, cert strip, EDR DLL sideload
- **Exfiltration** — MFT parse, RDP clipboard steal, DNS-over-HTTPS, ICMP tunnel, HTTP chunked
- **Nuclear layer** — `FindSyscallGadgetAnyModule` scans every loaded DLL for `syscall;ret`, defeating ntdll-only hooks; `DirectSyscallByNumber` calls any syscall by number via a heap trampoline

## Nuclear Layer (v1.2.0)

The new weapons tier, purely additive — zero existing lines touched.

- **Atom Bombing** (`InjectAtomBombing`) — shellcode is smuggled into the process-global atom table. A 48-byte x64 stub in the target calls `GetAtomNameA`, which copies the bytes into a buffer and jumps into them. The payload never appears as an RWX allocation in the target's VAD. EDRs rarely trace atom lookups.
- **Polymorphic injection** (`InjectPolymorphic`) — round-robin rotation between `InjectSectionMapping`, `InjectAPCQueued`, and `InjectAtomBombing`. Each call uses a different technique so an EDR that blocks one still gets hit by the next. The cursor advances so successive injects never repeat.
- **FindSyscallGadgetAnyModule** — scans the PEB (`Ldr` / `InMemoryOrderModuleList`) for `syscall;ret` in **any** loaded DLL, not just ntdll. Defeats EDRs that only hook ntdll.
- **DirectSyscallByNumber** — allocates a 64-byte heap trampoline (`mov r10, rcx` / `mov eax, num` / `syscall` / `ret`), executes it, frees it. Call any syscall by number with no import.
- **EnumProcessThreads** — `NtGetNextThread` + `NtQueryInformationThread` to list all threads of a remote PID.
- **GetRemoteModuleBase** — reads the remote PEB, walks the Ldr, finds a DLL by hash.
- **NtQueryInformationProcess / NtQueryInformationThread** — new stubs, not in `stubs.go`.

## Build

```bash
go build ./...
```

Requires Windows + Go 1.22+.

## Test

```bash
go test ./syscallwin/ -v
```

Runs the full test suite: PEB walker, direct syscall, module export hash, injection into a suspended process.