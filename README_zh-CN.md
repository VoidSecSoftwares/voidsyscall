# voidsyscall

[![go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?logo=linux)](#构建)
[![c2](https://img.shields.io/badge/c2-https%20%7C%20dns%20%7C%20icmp-blueviolet)](channels/)
[![syscalls](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)

[English](./README.md) | **简体中文** | [조선어](./README_ko-KP.md) | [Русский](./README_ru-RU.md)

零 WinAPI。所有 NT 原语在运行时从内存映像中的 ntdll 动态解析——通过 Plan9 汇编存根直接发出 `SYSCALL` 指令，无导入表（IAT 全零），不触碰 ntdll 用户态钩子。C2 走 HTTPS / DNS / ICMP 通道，每条消息 AES-256-GCM AEAD 封装并附带独立 nonce。原生 Windows 植入逻辑，同时保留 Linux / macOS 服务端构建。

这不是 syscall 封装库，而是**完整植入框架**：从代码注入、文件 I/O、注册表持久化到令牌冒名，所有操作一律走开机时从当前 ntdll 导出表解析出的原始 `Nt*` syscall。二进制内不存在任何 `kernel32`/`advapi32`/`user32`/`win32u` 导入，用户态钩子（inline hook、IAT hook、Callbacks）无处着力。每个函数名以 djb2 哈希常量存在，反汇编结果中检索不到明文字符串——只有 32 位哈希和 `SYSCALL` 助记符。

---

## 目录

- [Syscall 引擎（直接 / 间接 / 指纹 / Unhook）](#syscall-引擎)
- [注入——4 种方法，多态轮换](#注入)
- [反分析——13+ 检测方法](#反分析)
- [Token 操作 / VAD 操作 / 文件 I/O / 注册表 / 句柄 / 内存加密 / 补丁](#token-操作)
- [C2 通道与线格式](#c2-通道)
- [Crypto（AES-256-GCM）](#crypto)
- [目录结构与内部机制](#目录结构与内部机制)
- [SSN 解析七步走](#ssn-解析七步走)

---

## Syscall 引擎

### 运行时 SSN 解析（开机流程）

```
ReadGSBase ──GS:[0x60]──▶ TEB ──+0x60──▶ PEB ──+0x18──▶ PEB_LDR_DATA
                                                              │
                                          +0x10 InMemoryOrderModuleList ◀── 链表头
                                                              │
                      遍历节点，取 module->DllBase 上读 PE 头，djb2 匹配 ntdll" 基址
                                                              │
                     IMAGE_DOS_HEADER.e_lfanew ──▶ IMAGE_NT_HEADERS
                                                              │
                     OptionalHeader.DataDirectory[0].VirtualAddress ──▶ 导出表
                                                              │
          AddressOfNames[] 逐个 djb2 → 命中目标函数名 → 序号 → AddressOfFunctions[]
                                                              │
                              函数地址 ──▶ 前导序列扫描 ──▶ 提取 SSN
```

- **djb2 哈希**：`h = 5381; h = h*33 + c`。名称哈希在编译期完成（`hash.go` 以字符串 + UTF-16 双变体同构），二进制只有 `uint32` 常量。
- **前导扫描**（`resolve.go`）逐字节在目标函数前 64 字节窗口内匹配以下模式并**容忍 jmp 跳板**（`EB xx` 短跳 / `E9 xx xx xx xx` 近跳 → 沿跳转链继续扫描）：
  - 直接模式：`B8 xx xx 00 00 0F 05`（`mov eax, SSN; syscall`）
  - 提前返回模式：`B8 xx xx 00 00 C3`（`mov eax, SSN; ret`）
  - Hells Gate 变体：`4C 8B D1 B8 xx xx 00 00 0F 05`（`mov r10, rdx; mov eax, SSN; syscall`）
- **SSN 提取**：取 `B8` 之后 4 字节小端，低 16 位即 SSN，存入 `map[uint32]uint16` 缓存（函数哈希 → SSN）。
- **Win32k 命名空间**：GDI/User 原语（`NtUser*`/`NtGdi*`）走 `win32u.dll`，其 SSN 空间与 ntdll **分离**，单独解析、单独缓存。

### 直接 syscall（Plan9 汇编存根）

`asm_amd64.s` 手写 ABI，关键语义：

| 阶段 | 寄存器动作 |
|------|-----------|
| 参数入位 | 第 1~3 参依次送 `CX/R8/R9`（`syscallwin` 约定），第 4 参送 `R10`（**必须**，`SYSCALL` 会 clobber `RCX/R11`） |
| SSN 注入 | `movl $ssn, AX`（AX=RAX，Plan9 为长度无前缀命名） |
| 触发 | `SYSCALL` → 内核从 `MSR_LSTAR` 进入 `KiSystemCall64` |
| 返回 | `NTSTATUS` 在 RAX；`NtDeviceIoControlFile` 等会把输出缓冲指针放 RDX |

`Syscall`（≤7 参）与新加 `Syscall9`（9 参，栈帧 `$0-88`，`SUB $0x50` 为第 8/9 参预留）覆盖 `NtGdiBitBlt` 这类重参数量 syscall。零 Wi-Fi 调用：识别函数、系统调用、参数铺排全部在无库依赖的裸汇编里完成。

### 间接 syscall

直接 syscall 的调用栈里始终只有**植入自身的帧**——密集 EDR 靠栈回溯即可抓现行。间接模式在 ntdll `.text` 中搜索 `0F 05 C3`（`syscall; ret`）gadget，经其落地：

- CPU 陷阱地址落在 **ntdll 内部**，`KiUserExceptionDispatch`/栈回溯呈现 ntdll 帧；
- EDR 常把 `syscall` 指令所在页标记为非执行页（`NtProtectVirtualMemory` 至 `PAGE_PRESERVE`）——扫描时跳过首个字节偏移、改用相邻 `0F 05` 双字节序列落位，进一步绕开“页颗粒”防护。

### SSN 指纹（跨 Windows 构建预校验）

SSN 非稳定接口：`10.0.19041`（20H1）到 `10.0.26100`（24H2）间同一函数的编号漂移频繁。`fingerprint.go` 将当次 ntdll 构建的所有已解析 SSN 排序 + 哈希，生成 64 位指纹：

- **导出**：十六进制串，可与队友/第二台机器比对；
- **导入**：在解析前比对，构建不匹配 → 直接放弃该机器上的诱导行为，避免“半编号漂移”打到错误 syscall；
- **收益**：指纹在跑任务前就发现“这个 ntdll 我没见过”。

### Unhook（磁盘镜像重灌）

EDR 惯用手法：把 ntdll 的 `.text` 页做成 RWX 并注入 5~14 字节跳板（`jmp r11; push r11; mov r11, <handler>` 等）。Unhook 流程：

```
NtCreateFile(\SystemRoot\System32\ntdll.dll) → NtMapViewOfSection(SEC_IMAGE)
  → 新版 .text 与 in-memory .text 逐字节 diff
  → NtProtectVirtualMemory(.text → RWX) → memcpy(干净页) 
  → 恢复保护(RX) → FlushInstructionCache → 清空 SSN 缓存
```

之后每个信标前半段无条件执行 `CheckAndUnhook()`——即便 EDR 二次挂钩，也会在下一个 beacon 前被再次抹平。

---

## 注入

Agent 信标循环内轮换 4 种注入技术，两次注入的内存布局、落点、线程创建路径互不相同。

| 方法 | 原语链 | 隐蔽性分析 |
|------|--------|-----------|
| **Section 映射** | `NtCreateSection` → `NtMapViewOfSection`（本地写→远程读）→ `NtCreateThreadEx`（shellcode 地址） | Section 由磁盘文件背书，VAD 中无 `PAGE_EXECUTE_READWRITE`；远程私有页仅以 `PAGE_EXECUTE_READ` 呈现，内存扫描器按保护位白名单放行 |
| **进程镂空** | `NtCreateUserProcess`（挂起）→ `NtSuspendProcess` → 索引镜像基址 → 清零原 Base → 分配 + `NtWriteVirtualMemory`（shellcode）→ `NtSetContextThread`（RIP=载荷）→ `NtResumeProcess` | 任务管理器里是合法的 svchost.exe——路径、PID、PPID 全真，只有内存内容被替换 |
| **APC 排队** | `NtQuerySystemInformation(SystemHandleInformation)` 枚举线程 → `NtOpenThread` → `NtQueueApcThread` | 零新线程、零新 TEB、零新栈分配；等待目标线程进入可警醒等（`WaitForSingleObject`/I/O 完成）时插入内核 APC |
| **模块覆盖** | 目标进程内分配 → 写入最小合法 PE 头 + shellcode → `NtCreateThreadEx`（入口点） | 模块列表出现看似合理的 DLL 名；PE 头几何结构（节表、SizeOfHeaders）足矣骗过裸模块枚举 |

轮换顺序由 `agent` 内部取模推进——同一植入的不同次注入在不同宿主上无稳定指纹。

---

## 反分析

全量检查跑完后输出**评分威胁报告**；达到 Critical（OU）阈值触发自动销毁（`SelfDel` + `NtTerminateProcess`）。

| 检测项 | 机制细节 |
|--------|---------|
| **VM 检测** | `CPUID(0x40000000)` 读 12 字节超管理器签名（`VMwareVMware`、`Microsoft Hv`、`KVMKVMKVM`、`XenVMMXenVMM`、`QEMU`、`VBoxVBoxVBox`、`prl hyperv`…）；叶节点 `0x40000001` 的厂商字符串作回退 |
| **沙箱检测** | 逻辑处理器数量；注册表工件 `HKLM\SOFTWARE\VMware, Inc.\VMware Tools`、`VBoxGuestAdditions`、服务键检查；30+ 进程名扫描（`wireshark`、`procmon`、`x64dbg`、`idaq`、`dumpcap`、`ollydbg`…） |
| **调试器检测** | `PEB.BeingDebugged`(0x02)、`PEB.NtGlobalFlag`(0x68, 对照 `FLG_HEAP_ENABLE_TAIL_CHECK`…) 、堆调试标志、`ProcessDebugPort`、`ProcessDebugObjectHandle`、`ProcessDebugFlags`、硬件断点 `DR0~DR7`（经 `Context` 读 `Dr0..Dr7` 且校验 `DR7` 启用位）、RDTSC 单步计时|
| **计时异常** | 50 次 `NtQuerySystemInformation` 延迟采样，算均值 μ / 标准差 σ；>10% 样本超 μ±3σ 判为插桩开销（EDR 钩子加层的时延特征） |
| **PEB 规避** | 全程 `GS` 段偏移直读 + `NtWriteVirtualMemory` 就地修补 `BeingDebugged`、`NtGlobalFlag`、`ProcessHeap.Flags/ForceFlags`、`DebugPort` 清 0；线程级再补 `NtSetInformationThread(ThreadHideFromDebugger=0x11)` |
| **KUSER_SHARED_DATA 读取** | 只读 `0xFFFFF78000000000` 常量区的稳定洞（TickCountMultiplier、SystemTime/InterruptTime、NumberOfPhysicalPages 等），无非法解析风险，供 evasion 第 `0x09` 子命令上报 |

---

## Token 操作

全 `Nt*` 实现：

- `EnablePrivilege(index)` — 任意权限按 LUID/索引置位
- `EnableAllTokenPrivileges()` — 一次 20 项（SeDebug、SeImpersonate、SeTcb、SeBackup、SeRestore…）
- `GetProcessTokenIntegrityLevel()` — 强制完整性等级（Medium/High/System）
- `StealProcessToken(pid)` — `NtOpenProcessToken` → `NtDuplicateToken`，冒用 SYSTEM 等身份
- `ImpersonateThread()` / `RevertToSelf()`

## VAD 操作

- `EnumVirtualMemory()` — `NtQueryVirtualMemory` 全区域遍历
- `FindWritableExecRegions()` — 定位已提交 `PAGE_EXECUTE_READWRITE` 区（自 RX→RWX 切换考点）
- `HideRegion()` / `UnhideRegion()` — `PAGE_NOACCESS` 隐藏与恢复

## 文件 I/O / 注册表 —— 全 Nt* syscall

- 文件：`NtCreateFile` → `NtReadFile`/`NtWriteFile` → `NtClose`；零 `CreateFileA/ReadFile/WriteFile/DeleteFileW`。`ReadFileContents()`、`WriteFileContents()`、`DeleteFileNt()`、`FileExists()`。
- 注册表：`NtCreateKey` → `NtSetValueKey`；`AddRunKeyPersistence()`（`CurrentImagePath()` 经 `NtQueryInformationProcess(ProcessImageFileName=27)` 取自身路径后自引）与 `RemoveRunKeyPersistence()`；零 Advapi32。
- 监控句柄：`EnumerateSystemHandles()`、`FindEDRHandles()`（PID × 30+ 名单）、`CloseEDRHandles()`、`IsProcessMonitored()`。

## 内存加密

- **Vault**：内存段 XOR 流加密，定时自动换钥（解密→生成新钥→重加密）；两次换钥之间的堆转储拿到的是密文垃圾。
- **SecureDelete**：3+1 遍覆写（随机→0→1→0）后 `NtFreeVirtualMemory`。
- **StackEncrypt**：返回前加密栈上敏感缓冲，栈帧复用让取证失去可信度。

## 补丁

`PatchAMSI()`（`AmsiScanBuffer`→`xor eax,eax; ret`）、`PatchETW()`（`EtwEventWrite`→`ret`）、`PatchNtTraceEvent()`、`PatchDbgUiRemoteBreakin()`、`PatchInstrumentationCallbacks()`（线程躲藏）。

---

## C2 通道

| 通道 | 线格式 | 前置条件 |
|------|--------|---------|
| **HTTPS** | 二进制 POST，自定义帧头：`16B 会话ID + 1B type + N bytes payload`；UA/路径随机化 | TLS 证书（`-web-addr` 起管理 Web UI） |
| **DNS** | `<idx>-<total>-<base32>` 子域名分片，TXT RR 回包 | 权威 NS / 递归解析 |
| **ICMPv4** | 载荷散入 echo 请求/回复的 ID+seq 字段 | 原始套接字（root/Admin）：`ICMP_ECHO` 类型识别 |

全部实现 `Channel` 接口：新增 NTP / DoH / TURN 只需实现接口，agent 零改动。信标循环在每次 beacon 前**轮换传输通道**（round-robin）。

**帧格式**（`channels/`）：

```
┌──────────────────────────┬────────┬───────────────┬───────────┐
│  Message.ID [16]byte     │ Type   │  Data[]       │ (len)     │
│  —— 会话加密上下文密钥 ID   │ 1B 任务 │ 任务载荷        │ 由上层推导 │
└──────────────────────────┴────────┴───────────────┴───────────┘
```

DoH 变体将裸帧再包一层 base32 label 分段，经 `encodeDoHLabel/decodeDoHLabel` 双向一致，单 label 最长 63B、以 `.` 拼接。

---

## Crypto

AES-256-GCM per-message AEAD：每条消息独立 12B nonce（`NtGetTickCount` 熵混合），每植入独立 keyring，密文 + tag 后封装于信封。支持口令推导变体。单测覆盖加解密往返。

---

## 目录结构

```
voidsyscall/
  syscallwin/             直接/间接 syscall + 规避原语
    asm_amd64.s           Syscall/IndirectSyscall/ReadGSBase/SetGSBase/asm_cpuid/asm_rdtsc
    syscall9.a            Syscall9（9 参版，帧 $0-88）
    resolve.go            PEB→LDR→ntdll→导出表→前导扫描，SSN 缓存，jmp 容忍
    win32u.go             win32u SSN 解析 + Screenshot(BMP)/IsKeyDown/ClipboardText
    kshared.go            KUSER_SHARED_DATA 只读读取
    stubs.go              ~25 Nt* 封装 + DirectSyscall + IndirectSyscallByHash
    hash.go               djb2（字符串 + UTF-16）
    constants.go          MEM_*/PAGE_*/THREAD_*/TOKEN_*/OBJ_*/REG_*/FILE_*/STATUS_*
    unhook.go             UnhookNtdll、SelfDel
    peb.go                PEB 修补
    token.go              权限提升、token 窃取、冒名
    vad.go                VAD 枚举、hide/unhide
    files.go              Nt* 文件 I/O
    registry.go           Nt* 注册表 + RunKey 持久化
    fingerprint.go        SSN 指纹
    inject_advanced.go    section 映射/镂空/APC/模块覆盖
    antianalysis.go       VM/沙箱/调试/计时检测 + 评分报告
    handles.go            句柄枚举、EDR 句柄清除
    memcrypt.go           Vault/SecureDelete/StackEncrypt
  syscallnix/             Linux/darwin 原始 syscall
  patches/                AMSI/ETW/NtTraceEvent/DbgUiRemoteBreakin/InstrumentationCallbacks
  channels/               HTTP/DNS(TXT)/ICMP + httpcommon.go（HTTP/DoH mux 共构）
  crypto/                 AES-256-GCM + 信封 + 口令变体（3 测试通过）
  server/                 SessionManager、任务队列、REPL、web.go（stdlib web UI）、state.go（JSON 持久化）
  agent/                  配置、信标循环、通道轮换、14 任务处理器
  cmd/server/main.go      带 REPL 的 CLI（-web-addr/-state）
  cmd/agent/main.go       仅 Windows 入口
```

---

## 构建

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'main.version=v1.1.0'" -o voidsyscall-agent.exe  ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w -X 'main.version=v1.1.0'" -o voidsyscall-server.exe ./cmd/server
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux          ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin         ./cmd/server
```

`-X main.version` 注入编译期版本字符串，release 流程按 tag 自动写入。混淆（garble）：

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" -o voidsyscall-agent.exe ./cmd/agent
```

---

## 使用

### 服务端

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443 \
    --web-addr 0.0.0.0:8181 --state session_state.json
```

- `--web-addr`：stdlib 只读 Web UI（`/api/sessions`、`/api/sessions/{id}`，5s 自动刷新）。
- `--state`：JSON 会话持久化，重启自动恢复队列/结果/调度。

### Agent

```bash
./voidsyscall-agent.exe -c agent/example-config.json
```

### 任务协议

| 任务 | 字节 | 载荷 |
|------|------|------|
| shell | `0x01` | UTF-8 命令 |
| inject | `0x02` | PID（4B LE）+ shellcode |
| patch | `0x03` | 0x01=AMSI 0x02=ETW 0x03=both |
| sleep | `0x04` | 秒（4B LE） |
| evasion | `0x10` | 0x01=full 0x02=VM 0x03=sandbox 0x04=debug 0x05=timing 0x06=report 0x09=KUSER |
| handles | `0x11` | 0x01=count 0x02=enum EDR 0x03=close EDR 0x04=monitored? |
| vault | `0x12` | 加密存储操作 |
| fingerprint | `0x13` | dump SSN 指纹 |
| token | `0x14` | 0x01=all 0x02=integrity 0x03=debug priv 0x04=impersonate |
| persist | `0x17` | RunKey 持久化（`[name]` 可选） |
| screenshot | `0x18` | BMP 截图（NtGdiBitBlt → NtGdiGetBitmapBits），落 `screenshots/` |
| keylog | `0x19` | sub：0x01=start 0x02=stop 0x03=dump（30ms 轮询，256KiB 上限） |
| clipboard | `0x1A` | `NtUserOpenClipboard/GetClipboardData(CF_UNICODETEXT)/CloseClipboard` |
| exit | `0xFF` | — |

---

## SSN 解析七步走

1. `ReadGSBase`（asm）→ `GS:[0x60]` → TEB
2. TEB+0x60 → PEB；PEB+0x18 → `Ldr`
3. 遍历 `InMemoryOrderModuleList` → 节点内 16B 偏移 `DllBase`，`djb2("ntdll")` 匹配
4. `DllBase → e_lfanew → IMAGE_NT_HEADERS → DataDirectory[0]` = 导出表
5. `AddressOfNames[]` 逐项 djb2 对哈希
6. 序号 → `AddressOfFunctions[]` → 函数地址
7. 前导扫描提取 SSN；`win32u` 命名空间重复 1~7 步（基址取 `LoadLibrary("win32u.dll")` → 移除 IAT 痕迹）

二进制无函数名字符串，只有 djb2 常量。`syscall` 指令在除数保护环切换——用户态钩子永远不可达。

---

## 状态

**已交付**：信标循环、任务队列、3 C2 通道 + DoH 变体、4 注入方法、13+ 反检测、句柄枚举/清除、token 全套、VAD、Nt* 文件 I/O、RunKey 持久化、SSN 指纹、内存加密、AMSI/ETW 补丁、AES-GCM、无钩子 PEB 规避、web UI、JSON 状态持久化、可注入版本、CI 流水线、通道轮换。
**工程化**：`go build ./...` 干净；`go vet ./cmd/... ./server/... ./channels/... ./crypto/...` 通过；单元测试覆盖 channels（帧往返/DoH label）、server（会话/调度/状态往返）、agent（任务分发/keylog 映射）。

**待完成**：Linux 自主 agent（仅构建）、会话密钥轮换、分阶段 loader、NTP/TURN 通道、持久化调度。

## 致谢

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo)
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
- [f1zm0/acheron](https://github.com/f1zm0/acheron)
- [Sliver C2](https://github.com/BishopFox/sliver)

## 许可证

MIT — [LICENSE](LICENSE)