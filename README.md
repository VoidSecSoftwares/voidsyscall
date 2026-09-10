# voidsyscall

[![go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?logo=linux)](#build)
[![c2](https://img.shields.io/badge/c2-https%20%7C%20dns%20%7C%20icmp-blueviolet)](channels/)
[![syscalls](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)

Zero WinAPI. Every NT primitive resolved at runtime from ntdll in memory —
`SYSCALL` instructions issued directly via Plan9 assembly stubs, no import table,
no ntdll usermode hooks touched. C2 over HTTPS / DNS / ICMP, AES-256-GCM per
message. Windows native. Linux builds. macOS builds.

This is not a syscall wrapper library. It's a full implant framework where
every operation — from injecting code to reading files to persisting in the
registry — goes through raw `Nt*` syscalls resolved at boot from the current
ntdll export table. No WinAPI calls exist in the binary. Nothing for an EDR
to hook at usermode.

---

## What's inside

### Syscall engine

- **Runtime SSN resolution**: PEB → LDR → ntdll base → PE export table →
  djb2 hash match → prologue scan for `B8 xx xx 00 00 0F 05` (direct) or
  `4C 8B D1 B8 xx xx 00 00 0F 05` (Hells Gate). Every function name is
  hashed at compile time — no plaintext strings in the binary.
- **Direct syscall**: Plan9 asm (`asm_amd64.s`) loads the SSN into EAX,
  sets 7 args by hand, executes `SYSCALL`. Return via `RAX`/`RDX`.
- **Indirect syscall**: Locates a `0F 05 C3` gadget (`syscall;ret`) inside
  ntdll, calls through it. The CPU trap lands inside ntdll — call stack
  shows ntdll frames, not implant frames. No usermode hook survives.
- **SSN fingerprint**: Dumps all resolved SSNs from the current ntdll build,
  generates a fingerprint hash. Export as hex, import on another machine.
  Detects build mismatches before they burn you.
- **Unhook**: Locks `.text` to RWX, copies original bytes from the disk-
  mapped ntdll, restores protection, flushes icache, nukes SSN cache.
  Every usermode hook placed by any EDR is gone.

### Injection — 4 methods, polymorphic rotation

The agent rotates through injection techniques automatically. Each call
uses a different method — no two injections look the same in forensics.

| Method | How it works | Why it's stealthy |
|--------|-------------|-------------------|
| **Section mapping** | `NtCreateSection` → `NtMapViewOfSection` (remote) → `NtCreateThreadEx` | No RWX allocation in VAD. Section is file-backed. Memory scanners see `PAGE_EXECUTE_READ`, not `PAGE_EXECUTE_READWRITE`. |
| **Process hollow** | `NtCreateUserProcess` (suspended) → `NtSuspendProcess` → zero image base → alloc + write shellcode → `NtSetContextThread` (RIP = shellcode) → `NtResumeProcess` | Process appears as legitimate svchost.exe in taskmgr. Only memory contents differ. |
| **APC queuing** | Enumerate threads via `NtQuerySystemInformation` → `NtOpenThread` → `NtQueueApcThread` | No new thread created. No new TEB. No new stack allocation. Fires when thread enters alertable wait. |
| **Module stomping** | Alloc in target → write minimal PE header + shellcode → `NtCreateThreadEx` at entry point | Module list shows a plausible DLL name. PE header is valid enough to fool module enumeration. |

### Anti-analysis — 13+ detection methods

Runs all checks, returns a scored threat report. Auto-destruct on Critical.

| Check | Method |
|-------|--------|
| **VM detection** | CPUID leaf `0x40000000` hypervisor signature scan (VMware, VirtualBox, Hyper-V, KVM, Xen, QEMU, Parallels) + leaf `0x40000001` fallback |
| **Sandbox detection** | CPU count, registry artifacts (VMware Tools, VBox Guest Additions, VMware/VBox services), sandbox process scan (30+ known names: wireshark, procmon, x64dbg, ida, etc.) |
| **Debugger detection** | `PEB.BeingDebugged`, `PEB.NtGlobalFlag`, heap debug flags, `ProcessDebugPort`, `ProcessDebugObjectHandle`, `ProcessDebugFlags`, hardware breakpoint DR0-7, timing single-step check |
| **Timing anomaly** | RDTSC-based: 50 samples of `NtQuerySystemInformation` latency, mean/stddev, flag if >10% of samples exceed 3σ variance. Catches instrumentation overhead. |
| **PEB evasion** | Patches `BeingDebugged`, `NtGlobalFlag`, `ProcessHeap` flags, `DebugPort`, `ThreadHideFromDebugger` — all via `GS` segment reads + `NtWriteVirtualMemory`. No API calls. |

### Token operations

All via `Nt*` syscalls, no WinAPI.

- `EnablePrivilege(index)` — set any privilege by LUID
- `EnableAllTokenPrivileges()` — 20 privileges at once (Debug, Impersonate, TCB, Backup, Restore, etc.)
- `GetProcessTokenIntegrityLevel()` — query mandatory integrity
- `StealProcessToken(pid)` — open + duplicate another process token
- `ImpersonateThread()` / `RevertToSelf()`

### VAD operations

- `EnumVirtualMemory()` — walk all virtual regions via `NtQueryVirtualMemory`
- `FindWritableExecRegions()` — find `PAGE_EXECUTE_READWRITE` committed regions
- `HideRegion()` — set `PAGE_NOACCESS` to hide memory from scanners
- `UnhideRegion()` — restore original protection

### File I/O — all Nt* syscalls

`NtCreateFile` → `NtReadFile` / `NtWriteFile` → `NtClose`. Zero `CreateFileA`,
`ReadFile`, `WriteFile`, or `DeleteFileW` calls. `ReadFileContents()`,
`WriteFileContents()`, `DeleteFileNt()`, `FileExists()`.

### Registry persistence — all Nt* syscalls

`NtCreateKey` → `NtSetValueKey`. `AddRunKeyPersistence()`, `RemoveRunKeyPersistence()`.
No `RegCreateKeyEx`, `RegSetValueEx`, or any Advapi32 calls.

### Handle operations

- `EnumerateSystemHandles()` — all open handles in the system via
  `NtQuerySystemInformation(SystemHandleInformation)`
- `FindEDRHandles()` — matches owner PIDs against 30+ known EDR process
  names (MsSense, CrowdStrike, Sentinel, Cylance, Carbon Black, etc.)
- `CloseEDRHandles()` — closes monitoring handles the EDR placed in your
  process
- `IsProcessMonitored()` — boolean check: are we being watched?

### Memory encryption

- **Vault**: In-memory XOR cipher with auto re-keying on a timer.
  Plaintext never stored raw. Re-key decrypts → generates new key →
  re-encrypts. Forensic heap dumps between re-key intervals get garbage.
- **SecureDelete**: 3-pass wipe (random → zeros → ones → zeros) before
  `NtFreeVirtualMemory`.
- **StackEncrypt**: Encrypt stack-allocated buffers before return.
  Stack frame reuse makes forensics unreliable.

### AMSI / ETW / evasion patches

- `PatchAMSI()` — `AmsiScanBuffer` → `MOV EAX, 0; RET`
- `PatchETW()` — `EtwEventWrite` → `RET`
- `PatchNtTraceEvent()` — `NtTraceEvent` → `RET`
- `PatchDbgUiRemoteBreakin()` — thread breakin → `RET`
- `PatchInstrumentationCallbacks()` — `ThreadHideFromDebugger`

### C2 channels

| Channel | Wire format | Prereqs |
|---------|-------------|---------|
| **HTTPS** | binary POST, custom framing, randomized UA/path | TLS cert |
| **DNS** | `<idx>-<total>-<base32>` subdomain, TXT response | DNS resolution |
| **ICMPv4** | payload in echo request/reply ID+seq | raw socket (root/Admin) |

All channels implement the `Channel` interface. Adding NTP, DoH, or TURN
means implementing the interface — zero agent changes.

### Crypto

AES-256-GCM per-message AEAD. Unique 12-byte nonce per message. Per-implant
keyring. Passphrase-based key derivation available. 3 tests, all passing.

---

## Layout

```
voidsyscall/
  syscallwin/          Direct/indirect NT syscalls + evasion
    asm_amd64.s        Syscall/IndirectSyscall/ReadGSBase/SetGSBase/asm_cpuid/asm_rdtsc
    resolve.go         PEB→LDR→ntdll walk, PE export parse, SSN cache, prologue scan
    stubs.go           ~25 Nt* wrappers, DirectSyscall, IndirectSyscallByHash
    hash.go            djb2 hash (string + UTF-16 pointer)
    constants.go       MEM_*, PAGE_*, THREAD_*, TOKEN_*, OBJ_*, REG_*, FILE_*, STATUS_*
    unhook.go          UnhookNtdll, SelfDel
    peb.go             PEB patching (BeingDebugged, NtGlobalFlag, Heap, DebugPort)
    token.go           Privilege escalation, token theft, impersonation
    vad.go             VAD enumeration, hide/unhide regions
    files.go           File I/O via Nt* syscalls
    registry.go        Registry persistence via Nt* syscalls
    fingerprint.go     SSN dump, build fingerprint, hex export/import
    inject_advanced.go 4 injection methods: section mapping, hollow, APC, module stomp
    antianalysis.go    VM/sandbox/debug/timing detection, scored threat report
    handles.go         System handle enumeration, EDR handle killer
    memcrypt.go        Vault (re-keying XOR), SecureDelete, StackEncrypt, WipeMemory
  syscallnix/          Linux/darwin raw syscalls
  patches/             AMSI, ETW, NtTraceEvent, DbgUiRemoteBreakin, InstrumentationCallbacks
  loader/              CreateThread/APC/module-stomp injection
  channels/            HTTP, DNS (TXT), ICMP — Channel interface
  crypto/              AES-256-GCM, envelope, passphrase variant (3 tests)
  server/              SessionManager, Task Queue, interactive REPL
  agent/               Config, beacon loop, 10 task handlers
  cmd/server/main.go   CLI with REPL
  cmd/agent/main.go    Windows-only entrypoint
```

---

## Build

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-agent.exe   ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server.exe  ./cmd/server
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux            ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin           ./cmd/server
```

Obfuscation with [garble](https://github.com/burrowers/garble):

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" \
    -o voidsyscall-agent.exe ./cmd/agent
```

---

## Usage

### Server

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443
```

### Agent

```bash
./voidsyscall-agent.exe -c agent/example-config.json
```

### Task protocol

| Task | Byte | Payload |
|------|------|---------|
| shell | `0x01` | UTF-8 command |
| inject | `0x02` | PID (4 bytes LE) + shellcode |
| patch | `0x03` | 0x01=AMSI, 0x02=ETW, 0x03=both |
| sleep | `0x04` | seconds (4 bytes LE) |
| evasion | `0x10` | 0x01=full, 0x02=VM, 0x03=sandbox, 0x04=debug, 0x05=timing, 0x06=report |
| handles | `0x11` | 0x01=count, 0x02=enum EDR, 0x03=close EDR, 0x04=monitored? |
| vault | `0x12` | encrypted storage operations |
| fingerprint | `0x13` | dump SSN build fingerprint |
| token | `0x14` | 0x01=enable all, 0x02=integrity, 0x03=debug priv, 0x04=impersonate |
| exit | `0xFF` | — |

---

## SSN resolution internals

1. `ReadGSBase` (asm) → `GS:[0x60]` → **TEB**
2. TEB+0x60 → **PEB**. PEB+0x18 → `Ldr`
3. Walk `InMemoryOrderModuleList` → match `ntdll.dll` via djb2 hash
4. Base → `IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS` → DataDirectory[0] = **Export Table**
5. Walk `AddressOfNames[]`, djb2 each, match target
6. Resolve ordinal → `AddressOfFunctions[ordinal]` → function address
7. Scan prologue for `B8 xx xx 00 00 0F 05` (direct), `B8 xx xx 00 00 C3` (early-ret), or `4C 8B D1 B8 xx xx 00 00 0F 05` (Hells Gate)
8. Extract 2-byte SSN → store in `map[uint32]uint16` cache

No function names in binary. Only djb2 hashes. The `syscall` instruction
bypasses every usermode hook.

---

## Agent task handlers

```go
TaskShell       // exec via cmd.exe
TaskInject      // polymorphic: section/hollow/APC/stomp
TaskPatch       // AMSI/ETW/both
TaskEvasion     // PEB patches + VM/sandbox/debug/timing detection
TaskHandles     // enumerate + kill EDR monitoring handles
TaskFingerprint // dump SSN build fingerprint
TaskToken       // privilege escalation + impersonation
TaskVault       // encrypted in-memory storage
TaskSleep       // jitter-aware sleep
TaskExit        // clean shutdown
```

---

## Status

**Shipped**: Beacon loop, task queue, 3 C2 channels, 4 injection methods,
10+ evasion checks, handle enumeration/closure, token manipulation, VAD ops,
file I/O, registry persistence, SSN fingerprinting, memory encryption,
AMSI/ETW patching, AES-GCM crypto, session management, interactive REPL.
3 crypto tests pass. `go build` clean on Windows.

**Not yet**: Linux autonomous agent (builds exist, no agent logic),
session key rotation, staged loader, NTP/DoH channels, persistence scheduling.

## Acknowledgments

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo)
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
- [f1zm0/acheron](https://github.com/f1zm0/acheron)
- [Sliver C2](https://github.com/BishopFox/sliver)

## License

MIT — [LICENSE](LICENSE)
