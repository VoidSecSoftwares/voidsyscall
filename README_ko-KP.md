# voidsyscall

[![go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?logo=linux)](#짓기)
[![c2](https://img.shields.io/badge/c2-https%20%7C%20dns%20%7C%20icmp-blueviolet)](channels/)
[![syscalls](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)

[English](./README.md) | [简体中文](./README_zh-CN.md) | **조선어** | [Русский](./README_ru-RU.md)

> 이 문서는 조선어(문화어) 버전입니다. 정화한 기술 술어는 원문(영문)을 기준으로 삼습니다.

WinAPI 셋 다리 없다. 모든 NT 원시 령(primitive)은 실행 시기에 기억장치에 적재된 ntdll에서 동적으로 해석되며——Plan9 어셈블리 루틴 조각을 통하여 `SYSCALL` 명령이 직접 나간다. 리입표(import table)가 없고 ntdll 사용자구역 이동수(钩子)에도 손을 대지 않는다. C2 통신은 HTTPS / DNS / ICMP 망을 돌며，매개 메시지는 AES-256-GCM AEAD로 봉하고 메시지마다 독립된 nonce를 쓴다. 삽입체(implant)는 Windows 고유로 만들고 Linux / macOS 서버 짓기는 그대로 보존한다.

이것은 syscall 포장자료실이 아니라 **온전한 삽입 골격(frame)**이다. 몸체 끼워넣기, 화일 읽기, 등록표(registry) 지속까지 모든 조작이 시동 때 현재 ntdll도출표에서 해석한 원시 `Nt*` syscall로만 진행된다. 바이너리 안에는 `kernel32`/`advapi32`/`user32`/`win32u` 리입이 하나도 없고，사용자구역 이동수(인라인 훅、IAT 훅、콜백)는 걸어볼 곳이 없다. 함수 이름은 일체 djb2 해시로만 존재하고，역어셈블리 관찰에서도 읽을 수 있는 문자열이 나타나지 않는다——32비트 해시와 `SYSCALL` 니모닉뿐이다.

---

## 내용

- [Syscall 기관（직접 / 간접 / 지문 / Unhook）](#syscall-기관)
- [끼워넣기——4가지 방법，多形輪轉](#끼워넣기)
- [반분석——13+ 검측 방법](#반분석)
- [Token 조작 / VAD 조작 / 화일 I-O / 등록표 / 수자(핸들) / 기억부 암호화 / 식불(补丁)](#token-조작)
- [C2 통로와 선형식](#c2-통로)
- [Crypto（AES-256-GCM）](#crypto)

---

## Syscall 기관

### 실행 시기 SSN 해석（시동 과정）

```
ReadGSBase ──GS:[0x60]──▶ TEB ──+0x60──▶ PEB ──+0x18──▶ PEB_LDR_DATA
                                                              │
                                          +0x10 InMemoryOrderModuleList ◀── 련결
                                                              │
                련결을 따라가며 DllBase에서 PE 머리를 읽고 djb2로 ntdll을 가른다
                                                              │
                     IMAGE_DOS_HEADER.e_lfanew ──▶ IMAGE_NT_HEADERS
                                                              │
                          DataDirectory[0].VirtualAddress ──▶ 도출표
                                                              │
          AddressOfNames[]을 하나씩 djb2 → 꼬리표 → AddressOfFunctions[]
                                                              │
                             함수 주소 ──▶ 머리글 단락 검사 ──▶ SSN 끄집어냄
```

- **djb2 해시**：`h = 5381; h = h*33 + c`。함수 이름 해시는 편집(compile) 시기에 끝나（`hash.go`，가락＋UTF-16 두 형），바이너리에는 `uint32` 상수만 남는다。
- **머리글 단락 검사**（`resolve.go`）：함수 앞 64바이트 창 안에서 아래 꼴을 맞추되 **jmp 밀대(跳板)를 참는다**（`EB xx` / `E9 xx xx xx xx`를 타고 이어서 검사）：
  - 직접 꼴：`B8 xx xx 00 00 0F 05`（`mov eax, SSN; syscall`）
  - 일찍 돌아가는 꼴：`B8 xx xx 00 00 C3`（`mov eax, SSN; ret`）
  - Hells Gate 변형：`4C 8B D1 B8 xx xx 00 00 0F 05`（`mov r10, rdx; mov eax, SSN; syscall`）
- **SSN 끄집어내기**：`B8` 뒤 4바이트 소단위，低16비트가 SSN。`map[uint32]uint16`（함수 해시 → SSN）에 보존。
- **Win32k 이름공간**：`NtUser*`/`NtGdi*` 계열은 `win32u.dll`로 해석하며，SSN 공간이 ntdll과 **따로**다——따로 해석，따로 보존。

### 직접 syscall（Plan9 어셈블리 루틴 조각）

`asm_amd64.s`：

| 단계 | 레지스터 동작 |
|------|-------------|
| 인자 배치 | 제1~3 인수는 `CX/R8/R9`，제4 인수는 `R10`（**필수**：`SYSCALL`이 `RCX/R11`을 망가뜨린다） |
| SSN 주입 | `movl $ssn, AX` |
| 발동 | `SYSCALL` → `KiSystemCall64`（`MSR_LSTAR`） |
| 복귀 | `NTSTATUS`는 RAX；`NtDeviceIoControlFile`류는 출력 가리키는 쪽을 RDX에 |

`Syscall`（≤7 인수）＋ 새 `Syscall9`（9 인수，틀 `$0-88`）가 `NtGdiBitBlt` 같은 큰 인수 syscall을 덮는다.

### 간접 syscall

직접 syscall의 호출갈림장에는 **삽입 자신의 틀만** 보인다——EDR은 갈림장만 되돌려도 곧장 발각한다. 간접 꼴은 ntdll `.text` 안에서 `0F 05 C3`（`syscall; ret`）가젯을 찾아 그곳으로 떨어뜨린다：

- CPU 트랩 주소가 ntdll 안에 박힌다——되돌릴 때 ntdll 틀이 보이고 삽입 틀은 감추어진다；
- `syscall`이 든 페이지는 EDR이 비실행으로 바꾸는 경우가 많다——검사는 첫바이트를 피해 옆 `0F 05` 끝을 이용한다。

### SSN 지문（건설 품종 사전 검사）

SSN은 불안정한 인터페이스: `10.0.19041`(20H1)→`10.0.26100`(24H2) 사이 함수 번호가 자주 뜬다. `fingerprint.go`가 현재 ntdll의 모든 해석된 SSN을 정렬＋해시하여 64비트 지문을 만든다：

- **내보냄**：十六진법 끈，분대/다른 콤퓨터와 견주기；
- **들여옴**：해석 전에 견주어 품종이 안 맞으면 동작을 포기한다——반쪽자리 번호 드리프트를 미리 걸러낸다。

### Unhook（디스크 그림 재적재）

EDR은 ntdll `.text`를 RWX로 바꿔 5~14바이트 밀대（`jmp r11`류）를 박는 수법을 쓴다. 흐름：

```
NtCreateFile(\SystemRoot\System32\ntdll.dll) → NtMapViewOfSection(SEC_IMAGE)
  → 새 .text 로 기억부의 .text 를 바이트 단위로 겨뤄봄
  → NtProtectVirtualMemory(.text → RWX) → memcpy(깨끗한 낱장) 
  → 보존(RX) → FlushInstructionCache → SSN 보존 없앰
```

매 신호(beacon) 앞머리에서 무조건 `CheckAndUnhook()`를 돈다——EDR이 다시 걸어도 다음 신호 전에 또 지워진다.

---

## 끼워넣기

신호 돌이 돌아가며 4가지 끼워넣기 방식을 엇갈아 쓴다. 두 번의 끼워넣기가 같은 기억부 배치、같은 떨어진 곳、같은 스레드 경로를 보여주지 않는다.

| 방법 | 원시어 연쇄 | 숨김 분석 |
|------|-----------|---------|
| **Section 사상** | `NtCreateSection` → `NtMapViewOfSection`（본지 쓰기→먼 곳 읽기）→ `NtCreateThreadEx` | Section이 디스크 화일에 붙었고 VAD에 `PAGE_EXECUTE_READWRITE`가 없다；먼 곳 개인 낱장은 `PAGE_EXECUTE_READ`로만 보인다 |
| **과정 알맹이(进程镂空)** | `NtCreateUserProcess`(걸어) → `NtSuspendProcess` → 그림 베이스를 비움 → `NtWriteVirtualMemory`(shellcode) → `NtSetContextThread`(RIP=짐) → `NtResumeProcess` | 과제 관리자에서 온당한 svchost.exe로 보인다——길，PID，PPID 다 참 |
| **APC 줄세우기** | `NtQuerySystemInformation`로 스레드 헤아림 → `NtOpenThread` → `NtQueueApcThread` | 새 스레드、새 TEB、새 쌓기 없음；목적 스레드가 일깨워질 기다림에 들면 발동 |
| **모듈 덮기** | 목적 과정에 나눠줌 → 최소 PE 머리＋shellcode → 입구점에서 `NtCreateThreadEx` | 모듈 목록에 타당하게 보이는 DLL 이름；PE 머리 벼리는 모듈 셈만 속이기에 족하다 |

---

## 반분석

모든 검측을 돌고 내는 것은 **점수 위협 보고서**。임계(Critical)일 때 자동소멸（`SelfDel`＋`NtTerminateProcess`）。

| 검측 | 메커니즘 세부 |
|------|-------------|
| **가상기계** | `CPUID(0x40000000)` 12바이트 초관리기 서명（`VMwareVMware`、`Microsoft Hv`、`KVMKVMKVM`、`XenVMM`、`QEMU`、`VBoxVBoxVBox`…）；`0x40000001`으로 되돌림 |
| **모래주머니(沙箱)** | 논리 처리기 수；등록표 자국（VMware Tools、VBoxGuestAdditions）；30+ 과정 이름（wireshark、procmon、x64dbg、idaq、dumpcap…） |
| **디버거** | `PEB.BeingDebugged`、`NtGlobalFlag`、쌓기 디버그 기、`ProcessDebugPort/ObjectHandle/Flags`、물리적 멈춤점 `DR0~DR7`、RDTSC 한 발 걸음 검사 |
| **시간수 이상** | `NtQuerySystemInformation` 지연 50샘플，평균 μ/표준차 σ；>10% 샘플이 μ±3σ 밖이면 계측기 분(EDR 훅 지연 특징) |
| **PEB 숨김** | `GS` 축 읽음＋`NtWriteVirtualMemory`로 `BeingDebugged`、`NtGlobalFlag`、`ProcessHeap`、`DebugPort`를 고치고，스레드 차례에 `NtSetInformationThread(ThreadHideFromDebugger=0x11)` |
| **KUSER_SHARED_DATA** | `0xFFFFF78000000000` 상수 구역의 온당한 구멍（TickCount、SystemTime、PhysicalPages…）만 읽어 evasion `0x09`로 보고 |

---

## Token 조작

- `EnablePrivilege(index)` — 아무 권한을 LUID로 올려놓기
- `EnableAllTokenPrivileges()` — 한 번에 20권한（SeDebug、SeImpersonate、SeTcb…）
- `GetProcessTokenIntegrityLevel()` — 강제 온전성 급
- `StealProcessToken(pid)` — `NtOpenProcessToken`→`NtDuplicateToken`
- `ImpersonateThread()` / `RevertToSelf()`

## VAD 조작

`EnumVirtualMemory()`、`FindWritableExecRegions()`（`PAGE_EXECUTE_READWRITE` 찾기）、`HideRegion()`/`UnhideRegion()`（`PAGE_NOACCESS`）。

## 화일 I-O / 등록표 —— 전부 Nt* syscall

- 화일：`NtCreateFile`→`NtReadFile`/`NtWriteFile`→`NtClose`。`CreateFileA` 등이 하나도 없다。
- 등록표：`NtCreateKey`→`NtSetValueKey`；`AddRunKeyPersistence()`（자기 경로는 `NtQueryInformationProcess(ProcessImageFileName=27)`）와 `RemoveRunKeyPersistence()`；Advapi32 없음。
- 지킴(monitor) 손잡이：`EnumerateSystemHandles()`、`FindEDRHandles()`、`CloseEDRHandles()`、`IsProcessMonitored()`。

## 기억부 암호화

- **Vault**：기억부 구간 XOR 흐름 암호，시간으로 자동 열쇠갈이（풀기→새 열쇠→도로 묶기）；열쇠갈이 사이의 힙 덤프는 밀문(密文) 쓰레기。
- **SecureDelete**：3+1 번 덮어씀（임의→0→1→0）후 `NtFreeVirtualMemory`。
- **StackEncrypt**：돌아가기 전 쌓기의 민감한 버퍼를 묶는다。

## 식불

`PatchAMSI()`（`AmsiScanBuffer`→`xor eax,eax; ret`）、`PatchETW()`（`EtwEventWrite`→`ret`）、`PatchNtTraceEvent()`、`PatchDbgUiRemoteBreakin()`、`PatchInstrumentationCallbacks()`。

---

## C2 통로

| 통로 | 선형식 | 앞조건 |
|------|--------|-------|
| **HTTPS** | 이진 POST，틀 머리：`16B 회기ID + 1B 종류 + 짐`；UA/길 임의화 | TLS 인증서 |
| **DNS** | `<idx>-<total>-<base32>` 子도메인 알맹이，TXT 회답 | 공식 NS |
| **ICMPv4** | 짐을 echo 요청/회답의 ID+seq에 나누어 심음 | 원막대소켓（root/Admin） |

모두 `Channel` 인터페이스 구현：NTP / DoH / TURN을 더하려면 인터페이스만 짜면 되고 agent는 가만。신호 돌이는 매 신호 앞에서 **통로를 엇바꿔** 돈다（round-robin）。

**틀 선형식**：

```
┌──────────────────────────┬────────┬───────────────┐
│ Message.ID [16]byte      │ Type   │ Data[]        │
│ —— 회기 암호화 문맥 열쇠표  │ 1B 임무 │ 임무 짐        │
└──────────────────────────┴────────┴───────────────┘
```

DoH는 이 틀을 또 한 겹 base32 알갱이로 싸고 `encodeDoHLabel/decodeDoHLabel`로 왕복 일치（label 최장 63B）。

---

## Crypto

AES-256-GCM per-message AEAD：메시지마다 독립 12B nonce，삽입마다 독립 열쇠고리，密文＋tag를 봉투에 덮는다。구령(口令) 유래 방식도 있다。

---

## 짓기

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'main.version=v1.1.0'" -o voidsyscall-agent.exe  ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'main.version=v1.1.0'" -o voidsyscall-server.exe ./cmd/server
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux          ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin         ./cmd/server
```

`-X main.version`은 편집기 버전을 박아 넣고 release절차가 꼬리표 따라 자동으로 쓴다。garble混淆：

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent
```

---

## 쓰는 법

### 서버

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443 \
    --web-addr 0.0.0.0:8181 --state session_state.json
```

- `--web-addr`：stdlib읽기전용 웹 화판（`/api/sessions`、5초 갱신）。
- `--state`：JSON 회기 지속——시작 때 도로 살리고，끝날 때 저장한다。

### Agent

```bash
./voidsyscall-agent.exe -c agent/example-config.json
```

### 임무 규약

| 임무 | 바이트 | 짐 |
|------|--------|-----|
| shell | `0x01` | UTF-8 명령 |
| inject | `0x02` | PID（4B LE）＋shellcode |
| patch | `0x03` | 0x01=AMSI 0x02=ETW 0x03=둘 |
| sleep | `0x04` | 초（4B LE） |
| evasion | `0x10` | 0x01=full 0x02=VM 0x03=모래 0x04=디버거 0x05=시간 0x06=보고서 0x09=KUSER |
| handles | `0x11` | 0x01=셈 0x02=EDR 목록 0x03=EDR 닫기 |
| vault | `0x12` | 암호화 보존 조작 |
| fingerprint | `0x13` | SSN 지문 |
| token | `0x14` | 0x01=모든 권한 0x02=온전성 0x04=흉내 |
| persist | `0x17` | RunKey 지속（`[이름]` 선택） |
| screenshot | `0x18` | BMP 그림（`NtGdiBitBlt`），`screenshots/`에 둠 |
| keylog | `0x19` | sub：0x01=시작 0x02=멈춤 0x03=털어냄 |
| clipboard | `0x1A` | `NtUserOpenClipboard/GetClipboardData(CF_UNICODETEXT)` |
| exit | `0xFF` | — |

---

## SSN 해석 일곱 걸음

1. `ReadGSBase` → `GS:[0x60]` → TEB
2. TEB+0x60 → PEB；PEB+0x18 → `Ldr`
3. `InMemoryOrderModuleList` → djb2로 ntdll 가름
4. `DllBase → e_lfanew → IMAGE_NT_HEADERS → DataDirectory[0]` = 도출표
5. `AddressOfNames[]` 하나씩 djb2
6. 꼬리표 → `AddressOfFunctions[]` → 함수 주소
7. 머리글 단락 검사로 SSN 끄집어냄；`win32u` 공간은 1~7 반복

---

## 상황

**낸 것**：신호 돌이、임무 줄、3 C2 통로＋DoH、4 끼워넣기、13+ 반검측、손잡이 목록/닫기、token 전부、VAD、Nt* 화일 I-O、RunKey 지속、SSN 지문、기억부 암호화、AMSI/ETW 식불、AES-GCM、web 화판、JSON 지속、버전 주입、CI、통로 엇바꿈。

**안 낸 것**：Linux 자주 agent（짓기만）、회기 열쇠갈이、단계별 loader、NTP/TURN 통로。

## 감사의 말

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo)
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
- [f1zm0/acheron](https://github.com/f1zm0/acheron)
- [Sliver C2](https://github.com/BishopFox/sliver)

## 표허(许可)증

MIT — [LICENSE](LICENSE)