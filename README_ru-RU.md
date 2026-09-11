# voidsyscall

[![go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?logo=linux)](#сборка)
[![c2](https://img.shields.io/badge/c2-https%20%7C%20dns%20%7C%20icmp-blueviolet)](channels/)
[![syscalls](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)

[English](./README.md) | [简体中文](./README_zh-CN.md) | [조선어](./README_ko-KP.md) | **Русский**

Ноль WinAPI. Каждый NT-примитив разрешается в рантайме из образа ntdll в памяти — инструкция `SYSCALL` выполняется напрямую через стубы на Plan9-ассемблере, без таблицы импорта и без касания пользовательских хуков ntdll. Канал C2 — HTTPS / DNS / ICMP, каждое сообщение зашифровано AES-256-GCM (AEAD) с собственным nonce. Нативная логика импланта для Windows, сборки под Linux/macOS сохранены.

Это не библиотека-обёртка над syscall-ами, а **полный каркас импланта**: от инжекта кода и чтения файлов до персистентности в реестре — всё идёт через сырые `Nt*`-сисколы, разрешённые при старте из таблицы экспорта текущего ntdll. В бинарнике нет ни одного импорта `kernel32`/`advapi32`/`user32`/`win32u` — пользовательским хукам (inline, IAT, callback'и) не за что зацепиться. Имена функций существуют только в виде констант djb2-хешей: на дизассемблере вы не найдёте строк, только 32-битные хеши и мнемонику `SYSCALL`.

---

## Содержание

- [Движок syscall (прямой / косвенный / отпечаток / unhook)](#движок-syscall)
- [Инжект — 4 метода, полиморфная ротация](#инжект)
- [Антианализ — 13+ методов детекта](#антианализ)
- [Токены / VAD / файлы / реестр / дескрипторы / шифрование памяти / патчи](#токены)
- [Каналы C2 и формат сообщений](#каналы-c2)
- [Crypto (AES-256-GCM)](#crypto)
- [Разрешение SSN — семь шагов](#разрешение-ssn--семь-шагов)

---

## Движок syscall

### Разрешение SSN в рантайме (стартовый конвейер)

```
ReadGSBase ──GS:[0x60]──▶ TEB ──+0x60──▶ PEB ──+0x18──▶ PEB_LDR_DATA
                                                              │
                                          +0x10 InMemoryOrderModuleList ◀── список
                                                              │
                обход по списку; DllBase → читаем PE → djb2 ищем ntdll
                                                              │
                     IMAGE_DOS_HEADER.e_lfanew ──▶ IMAGE_NT_HEADERS
                                                              │
                          DataDirectory[0].VirtualAddress ──▶ экспорт
                                                              │
          AddressOfNames[] по одному → djb2 → ordinal → AddressOfFunctions[]
                                                              │
                             адрес функции ──▶ пролог ──▶ извлекаем SSN
```

- **djb2**：`h = 5381; h = h*33 + c`. Хеши имён считаются на этапе компиляции (`hash.go`, строковый и UTF-16 варианты) — в бинарник попадают только `uint32`-константы.
- **Скан пролога** (`resolve.go`) — в окне 64 байт перед функцией, с **учётом jmp-трамплинов** (`EB xx`, `E9 xxxxxxxx` — следование по цепочке переходов):
  - прямой: `B8 xx xx 00 00 0F 05` (`mov eax, SSN; syscall`)
  - ранний ret: `B8 xx xx 00 00 C3` (`mov eax, SSN; ret`)
  - Hells Gate: `4C 8B D1 B8 xx xx 00 00 0F 05` (`mov r10, rdx; mov eax, SSN; syscall`)
- **Извлечение SSN**: 4 байта после `B8`, little-endian, младшие 16 бит — SSN. Кэш: `map[uint32]uint16` (хеш → SSN).
- **Пространство win32k**: GDI/User-примитивы (`NtUser*`/`NtGdi*`) идут через `win32u.dll` — их SSN-пространство **отдельно** от ntdll, разрешается и кэшируется независимо.

### Прямой syscall (студы на Plan9)

`asm_amd64.s`:

| Стадия | Регистры |
|--------|----------|
| Индексы | 1–3 в `CX/R8/R9`, 4-й в `R10` (**обязательно**: `SYSCALL` затирает `RCX/R11`) |
| SSN | `movl $ssn, AX` |
| Спуск | `SYSCALL` → `KiSystemCall64` (через `MSR_LSTAR`) |
| Возврат | `NTSTATUS` в RAX; у `NtDeviceIoControlFile` и подобных выходной буфер в RDX |

`Syscall` (≤7 арг.) + новый `Syscall9` (9 арг., фрейм `$0-88`) перекрывают «тяжёлые» виды вроде `NtGdiBitBlt`.

### Косвенный syscall

У прямого syscall в стеке виден только **фрейм самого импланта** — EDR со стековым трассировщиком замечает мгновенно. Косвенный режим ищет в `.text` ntdll гаджет `0F 05 C3` (`syscall; ret`) и прыгает через него:

- адрес трапа — внутри ntdll: размотка стека выдаёт ntdll-фреймы, а не фреймы импланта;
- страницы c `syscall` EDR часто делает неисполняемыми — скан пропускает первый байт и садится на соседний `0F 05`.

### Отпечаток SSN (пред-валидация сборки)

SSN — нестабильный интерфейс: между `10.0.19041` (20H1) и `10.0.26100` (24H2) номера плывут. `fingerprint.go` сортирует и хеширует все разрешённые SSN текущей сборки ntdll в 64-битный отпечаток:

- **экспорт**: hex-строка для сверки со второй машиной;
- **импорт**: сверка до разрешения — при несовпадении сборки поведение отменяется, чтобы полудрейф номеров не попал в чужой syscall.

### Unhook (перезаливка с дискового образа)

EDR обычно делает `.text` ntdll RWX и вшивает трамплин 5–14 байт (`jmp r11` и пр.). Процесс:

```
NtCreateFile(\SystemRoot\System32\ntdll.dll) → NtMapViewOfSection(SEC_IMAGE)
  → побайтовый diff нового .text и старого
  → NtProtectVirtualMemory(.text → RWX) → memcpy(чистые страницы)
  → защита(RX) → FlushInstructionCache → сброс кэша SSN
```

Каждый бикон безусловно вызывает `CheckAndUnhook()` в начале — даже повторный хукинг сносится до следующего beacon.

---

## Инжект

Ротация 4 методов на каждый бикон: два инжекта никогда не дают одинаковую раскладку памяти, точку входа и путь создания треда.

| Метод | Цепочка примитивов | Почему тихо |
|-------|-------------------|-------------|
| **Section mapping** | `NtCreateSection` → `NtMapViewOfSection` (запись локально → чтение удалённо) → `NtCreateThreadEx` | Section файло-подкреплён, в VAD нет `PAGE_EXECUTE_READWRITE`; удалённые приватные страницы видны как `PAGE_EXECUTE_READ` |
| **Process hollowing** | `NtCreateUserProcess` (suspend) → `NtSuspendProcess` → обнуление базы → `NtWriteVirtualMemory` (shellcode) → `NtSetContextThread` (RIP=payload) → `NtResumeProcess` | В диспетчере задач — легитимный svchost.exe: путь, PID, PPID настоящие |
| **APC queueing** | `NtQuerySystemInformation` (перечисление тредов) → `NtOpenThread` → `NtQueueApcThread` | Ноль новых тредов/TEB/стеков; срабатывание при alertable-ожидании |
| **Module stomping** | аллокация в цели → минимальный PE-заголовок + shellcode → `NtCreateThreadEx` на entry point | В списке модулей — правдоподобное имя DLL; геометрии PE-заголовка хватает, чтобы обмануть перечисление модулей |

---

## Антианализ

Прогон всех проверок выводит **балльный отчёт об угрозе**; при Critical — автодеструкция (`SelfDel` + `NtTerminateProcess`).

| Проверка | Механика |
|----------|----------|
| **VM** | `CPUID(0x40000000)`: 12 байт сигнатуры гипервизора (`VMwareVMware`, `Microsoft Hv`, `KVMKVMKVM`, `XenVMM…`, `VBoxVBoxVBox`…); фолбэк на `0x40000001` |
| **Песочница** | число логических ядер; артефакты реестра (VMware Tools, VBoxGuestAdditions); скан 30+ имён процессов (wireshark, procmon, x64dbg, idaq, dumpcap…) |
| **Отладчик** | `PEB.BeingDebugged`, `NtGlobalFlag`, флаги кучи, `ProcessDebugPort/ObjectHandle/Flags`, аппаратные `DR0–DR7`, RDTSC-тайминг |
| **Тайминг-аномалии** | 50 замеров `NtQuerySystemInformation`, μ/σ; >10% за пределами μ±3σ — инструментация (накладные расходы хищнических хуков) |
| **PEB-evasion** | чтение по `GS` + `NtWriteVirtualMemory`: правка `BeingDebugged`, `NtGlobalFlag`, `ProcessHeap`, `DebugPort`; на уровне треда `NtSetInformationThread(ThreadHideFromDebugger=0x11)` |
| **KUSER_SHARED_DATA** | только стабильные поля по `0xFFFFF78000000000` (TickCount, SystemTime, PhysicalPages…) — отчёт через evasion `0x09` |

---

## Токены

- `EnablePrivilege(index)` — любая привилегия по LUID
- `EnableAllTokenPrivileges()` — сразу 20 (SeDebug, SeImpersonate, SeTcb, SeBackup…)
- `GetProcessTokenIntegrityLevel()` — уровень целостности
- `StealProcessToken(pid)` — `NtOpenProcessToken` → `NtDuplicateToken`
- `ImpersonateThread()` / `RevertToSelf()`

## VAD-операции

`EnumVirtualMemory()`; `FindWritableExecRegions()` (`PAGE_EXECUTE_READWRITE`); `HideRegion()`/`UnhideRegion()` (`PAGE_NOACCESS`).

## Файлы / реестр — только Nt*

- Файлы: `NtCreateFile`→`NtReadFile`/`NtWriteFile`→`NtClose`. Ни одного `CreateFileA/ReadFile/WriteFile/DeleteFileW`.
- Реестр: `NtCreateKey`→`NtSetValueKey`; `AddRunKeyPersistence()` (свой путь через `NtQueryInformationProcess(ProcessImageFileName=27)`) / `RemoveRunKeyPersistence()`. Ни одного Advapi32.
- Дескрипторы: `EnumerateSystemHandles()`, `FindEDRHandles()`, `CloseEDRHandles()`, `IsProcessMonitored()`.

## Шифрование памяти

- **Vault**: XOR-шифр с автосменой ключа по таймеру (расшифровка→новый ключ→перешифровка); дамп кучи между сменами — мусор.
- **SecureDelete**: 3+1 прохода (случайное→0→1→0) перед `NtFreeVirtualMemory`.
- **StackEncrypt**: шифрование чувствительных буферов на стеке перед возвратом.

## Патчи

`PatchAMSI()` (`AmsiScanBuffer`→`xor eax,eax; ret`), `PatchETW()` (`EtwEventWrite`→`ret`), `PatchNtTraceEvent()`, `PatchDbgUiRemoteBreakin()`, `PatchInstrumentationCallbacks()`.

---

## Каналы C2

| Канал | Формат | Требования |
|-------|--------|-----------|
| **HTTPS** | бинарный POST, шапка: `16B ID сессии + 1B тип + данные`; рандомизированные UA/путь | TLS-сертификат |
| **DNS** | поддомены `<idx>-<total>-<base32>`, ответ в TXT | авторитетный NS |
| **ICMPv4** | payload в ID+seq echo-запросов/ответов | raw-socket (root/Admin) |

Все каналы реализуют интерфейс `Channel`: NTP/DoH/TURN добавляются только новой реализацией, агент не трогается. Цикл бикона **меняет канал** перед каждым beacon (round-robin).

**Формат сообщения**:

```
┌──────────────────────────┬────────┬───────────────┐
│ Message.ID [16]byte      │ Type   │ Data[]        │
│ —— ключ контекста сессии  │ 1B тип │ payload       │
└──────────────────────────┴────────┴───────────────┘
```

DoH дополнительно сегментирует это в base32-лейблы (`encodeDoHLabel/decodeDoHLabel`, лейбл ≤63B, склейка через `.`).

---

## Crypto

AES-256-GCM, per-message AEAD: независимый 12-байтовый nonce на сообщение, ключевой брелок на имплант, ciphertext+tag в конверте. Вариант с выводом ключа из пароля. Тесты кругового шифрования проходят.

---

## Сборка

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'main.version=v1.1.0'" -o voidsyscall-agent.exe  ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'main.version=v1.1.0'" -o voidsyscall-server.exe ./cmd/server
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux          ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin         ./cmd/server
```

`-X main.version` подставляет версию на этапе сборки; пайплайн release пишет её автоматически из тега. Обфускация через [garble](https://github.com/burrowers/garble):

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent
```

---

## Использование

### Сервер

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443 \
    --web-addr 0.0.0.0:8181 --state session_state.json
```

- `--web-addr`: read-only веб-панель на стандартной библиотеке (`/api/sessions`, автообновление 5 c).
- `--state`: JSON-персистентность сессий — восстановление при старте, сохранение при останове.

### Агент

```bash
./voidsyscall-agent.exe -c agent/example-config.json
```

### Протокол задач

| Задача | Байт | Payload |
|--------|------|---------|
| shell | `0x01` | UTF-8 команда |
| inject | `0x02` | PID (4B LE) + shellcode |
| patch | `0x03` | 0x01=AMSI 0x02=ETW 0x03=оба |
| sleep | `0x04` | секунды (4B LE) |
| evasion | `0x10` | 0x01=full 0x02=VM 0x03=песочница 0x04=отладчик 0x05=тайминг 0x06=отчёт 0x09=KUSER |
| handles | `0x11` | 0x01=count 0x02=EDR-список 0x03=закрыть EDR |
| vault | `0x12` | зашифрованное хранилище |
| fingerprint | `0x13` | отпечаток SSN |
| token | `0x14` | 0x01=все привилегии 0x02=целостность 0x04=имперсонация |
| persist | `0x17` | RunKey (опц. имя) |
| screenshot | `0x18` | BMP-скриншот (`NtGdiBitBlt`), в `screenshots/` |
| keylog | `0x19` | sub: 0x01=start 0x02=stop 0x03=dump |
| clipboard | `0x1A` | `NtUserOpenClipboard/GetClipboardData(CF_UNICODETEXT)` |
| exit | `0xFF` | — |

---

## Разрешение SSN — семь шагов

1. `ReadGSBase` → `GS:[0x60]` → TEB
2. TEB+0x60 → PEB; PEB+0x18 → `Ldr`
3. Обход `InMemoryOrderModuleList` → djb2 по ntdll
4. `DllBase → e_lfanew → IMAGE_NT_HEADERS → DataDirectory[0]` = экспорт
5. `AddressOfNames[]` по одному, djb2
6. ordinal → `AddressOfFunctions[]` → адрес
7. скан пролога → SSN; для `win32u` шаги 1–7 повторяются

В бинарнике нет строк с именами — только djb2-константы. `syscall` уходит из кольца через переключатель — пользовательскому хуку недостижим.

---

## Статус

**Готово**: цикл бикона, очередь задач, 3 канала + DoH, 4 метода инжекта, 13+ проверок антианализа, перечисление/закрытие дескрипторов, токены, VAD, Nt*-файлы, RunKey, отпечаток SSN, шифрование памяти, патчи AMSI/ETW, AES-GCM, web-панель, JSON-состояние, версия через `-X`, CI, ротация каналов. Проходят `go build`, `go vet` и юнит-тесты (channels, server, agent).

**Не готово**: автономный Linux-агент (только сборки), ротация ключей сессии, staged-loader, NTP/TURN-каналы.

## Благодарности

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo)
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
- [f1zm0/acheron](https://github.com/f1zm0/acheron)
- [Sliver C2](https://github.com/BishopFox/sliver)

## Лицензия

MIT — [LICENSE](LICENSE)