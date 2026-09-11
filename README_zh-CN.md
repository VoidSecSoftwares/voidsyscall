# voidsyscall

[![go](https://img.shields.io/badge/go-1.24-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey?logo=linux)](#构建)
[![c2](https://img.shields.io/badge/c2-https%20%7C%20dns%20%7C%20icmp-blueviolet)](channels/)
[![syscalls](https://img.shields.io/badge/implant-syscall%20only-critical?logo=intel)](syscallwin/)

零 WinAPI。所有 NT 原语在运行时从内存中的 ntdll 动态解析——通过 Plan9 汇编存根直接发出 `SYSCALL` 指令，不依赖导入表，不触碰 ntdll 用户态钩子。支持 HTTPS / DNS / ICMP C2 通道，每条消息使用 AES-256-GCM 加密。原生 Windows 实现，同时支持 Linux 和 macOS 构建。

这不是一个 syscall 封装库，而是一个完整的植入框架。从代码注入、文件读取到注册表持久化，所有操作均通过在启动时从当前 ntdll 导出表中解析的原始 `Nt*` syscall 完成。二进制文件中不存在任何 WinAPI 调用，用户态钩子无处着力。

---

## 内容概览

### Syscall 引擎

- **运行时 SSN 解析**：PEB → LDR → ntdll 基址 → PE 导出表 → djb2 哈希匹配 → 前导序列扫描（`B8 xx xx 00 00 0F 05` 直接模式，或 `4C 8B D1 B8 xx xx 00 00 0F 05` Hells Gate 模式）。所有函数名在编译时哈希化，二进制文件中不含明文字符串。
- **直接 syscall**：Plan9 汇编（`asm_amd64.s`）将 SSN 加载至 EAX，手动设置 7 个参数，执行 `SYSCALL`，通过 `RAX`/`RDX` 获取返回值。
- **间接 syscall**：在 ntdll 中定位 `0F 05 C3` gadget（`syscall;ret`），通过该 gadget 调用。CPU 陷阱落在 ntdll 内部——调用栈显示 ntdll 帧，而非植入帧。用户态钩子形同虚设。
- **SSN 指纹**：导出当前 ntdll 版本的所有已解析 SSN，生成指纹哈希。可导出为十六进制，在其他机器上导入。在构建不匹配导致问题之前即可检测。
- **Unhook**：将 `.text` 段锁定为 RWX，从磁盘映射的原始 ntdll 复制原始字节，恢复内存保护，刷新指令缓存，清除 SSN 缓存。任何 EDR 放置的用户态钩子全部失效。

### 注入——4 种方法，多态轮换

Agent 自动轮换注入技术。每次调用使用不同方法——取证分析中两次注入不会呈现相同特征。

| 方法 | 工作原理 | 隐蔽性 |
|------|---------|--------|
| **Section 映射** | `NtCreateSection` → `NtMapViewOfSection`（远程）→ `NtCreateThreadEx` | VAD 中不分配 RWX 内存。Section 由文件支撑。内存扫描器看到的是 `PAGE_EXECUTE_READ`，而非 `PAGE_EXECUTE_READWRITE`。 |
| **进程镂空** | `NtCreateUserProcess`（挂起）→ `NtSuspendProcess` → 清零镜像基址 → 分配 + 写入 shellcode → `NtSetContextThread`（RIP = shellcode）→ `NtResumeProcess` | 在任务管理器中显示为合法的 svchost.exe。仅内存内容不同。 |
| **APC 排队** | 通过 `NtQuerySystemInformation` 枚举线程 → `NtOpenThread` → `NtQueueApcThread` | 不创建新线程，不分配新 TEB 和新栈。在线程进入可警醒等待时触发。 |
| **模块覆盖** | 在目标中分配内存 → 写入最小 PE 头 + shellcode → `NtCreateThreadEx` 从入口点执行 | 模块列表显示为合理的 DLL 名称。PE 头足够有效以欺骗模块枚举。 |

### 反分析——13+ 检测方法

执行所有检查，返回评分威胁报告。Critical 级别时自动销毁。

| 检测项 | 方法 |
|--------|------|
| **虚拟机检测** | CPUID `0x40000000` 叶节点超管理器签名扫描（VMware、VirtualBox、Hyper-V、KVM、Xen、QEMU、Parallels）+ `0x40000001` 叶节点回退 |
| **沙箱检测** | CPU 核心数、注册表工件（VMware Tools、VBox Guest Additions、VMware/VBox 服务）、沙箱进程扫描（30+ 已知进程名：wireshark、procmon、x64dbg、ida 等） |
| **调试器检测** | `PEB.BeingDebugged`、`PEB.NtGlobalFlag`、堆调试标志、`ProcessDebugPort`、`ProcessDebugObjectHandle`、`ProcessDebugFlags`、硬件断点 DR0-7、计时单步检测 |
| **计时异常** | 基于 RDTSC：对 `NtQuerySystemInformation` 延迟采集 50 个样本，计算均值/标准差，若超过 10% 的样本超出 3σ 方差则标记。捕获检测工具引入的开销。 |
| **PEB 规避** | 修补 `BeingDebugged`、`NtGlobalFlag`、`ProcessHeap` 标志、`DebugPort`、`ThreadHideFromDebugger`——全部通过 `GS` 段读取 + `NtWriteVirtualMemory` 完成。无 API 调用。 |

### Token 操作

全部通过 `Nt*` syscall 实现，无 WinAPI。

- `EnablePrivilege(index)` — 按 LUID 设置任意权限
- `EnableAllTokenPrivileges()` — 一次启用 20 个权限（Debug、Impersonate、TCB、Backup、Restore 等）
- `GetProcessTokenIntegrityLevel()` — 查询强制完整性等级
- `StealProcessToken(pid)` — 打开并复制另一个进程的 Token
- `ImpersonateThread()` / `RevertToSelf()`

### VAD 操作

- `EnumVirtualMemory()` — 通过 `NtQueryVirtualMemory` 遍历所有虚拟内存区域
- `FindWritableExecRegions()` — 查找 `PAGE_EXECUTE_READWRITE` 已提交区域
- `HideRegion()` — 设置 `PAGE_NOACCESS` 从扫描器中隐藏内存
- `UnhideRegion()` — 恢复原始保护

### 文件 I/O——全部 Nt* syscall

`NtCreateFile` → `NtReadFile` / `NtWriteFile` → `NtClose`。零 `CreateFileA`、`ReadFile`、`WriteFile`、`DeleteFileW` 调用。提供 `ReadFileContents()`、`WriteFileContents()`、`DeleteFileNt()`、`FileExists()`。

### 注册表持久化——全部 Nt* syscall

`NtCreateKey` → `NtSetValueKey`。`AddRunKeyPersistence()`、`RemoveRunKeyPersistence()`。
无 `RegCreateKeyEx`、`RegSetValueEx` 或任何 Advapi32 调用。

### 句柄操作

- `EnumerateSystemHandles()` — 通过 `NtQuerySystemInformation(SystemHandleInformation)` 枚举系统所有打开的句柄
- `FindEDRHandles()` — 将所有者 PID 与 30+ 已知 EDR 进程名匹配（MsSense、CrowdStrike、Sentinel、Cylance、Carbon Black 等）
- `CloseEDRHandles()` — 关闭 EDR 在进程中放置的监控句柄
- `IsProcessMonitored()` — 布尔检查：是否正在被监控？

### 内存加密

- **Vault**：内存中的 XOR 密码，定时自动重新密钥化。明文从不以原始形式存储。重新密钥时先解密 → 生成新密钥 → 重新加密。密钥轮换间隔内的取证堆转储获取的是垃圾数据。
- **SecureDelete**：3 次覆写擦除（随机 → 全零 → 全一 → 全零），然后 `NtFreeVirtualMemory`。
- **StackEncrypt**：在函数返回前加密栈分配的缓冲区。栈帧复用使取证分析不可靠。

### AMSI / ETW / 规避补丁

- `PatchAMSI()` — `AmsiScanBuffer` → `MOV EAX, 0; RET`
- `PatchETW()` — `EtwEventWrite` → `RET`
- `PatchNtTraceEvent()` — `NtTraceEvent` → `RET`
- `PatchDbgUiRemoteBreakin()` — 线程 breakin → `RET`
- `PatchInstrumentationCallbacks()` — `ThreadHideFromDebugger`

### C2 通道

| 通道 | 线格式 | 前置条件 |
|------|--------|---------|
| **HTTPS** | 二进制 POST，自定义帧格式，随机化 UA/路径 | TLS 证书 |
| **DNS** | `<idx>-<total>-<base32>` 子域名，TXT 响应 | DNS 解析 |
| **ICMPv4** | 回显请求/回复中的 ID+seq 承载负载 | 原始套接字（需 root/Admin） |

所有通道实现 `Channel` 接口。添加 NTP、DoH 或 TURN 通道只需实现该接口——Agent 零修改。

### 加密

每条消息 AES-256-GCM AEAD 加密。每条消息使用唯一 12 字节 nonce。每植入实例独立密钥环。支持基于密码短语的密钥派生。3 个测试全部通过。

---

## 目录结构

```
voidsyscall/
  syscallwin/          直接/间接 NT syscall + 规避技术
    asm_amd64.s        Syscall/IndirectSyscall/ReadGSBase/SetGSBase/asm_cpuid/asm_rdtsc
    resolve.go         PEB→LDR→ntdll 遍历，PE 导出解析，SSN 缓存，前导序列扫描
    stubs.go           ~25 个 Nt* 封装，DirectSyscall，IndirectSyscallByHash
    hash.go            djb2 哈希（字符串 + UTF-16 指针）
    constants.go       MEM_*, PAGE_*, THREAD_*, TOKEN_*, OBJ_*, REG_*, FILE_*, STATUS_*
    unhook.go          UnhookNtdll，SelfDel
    peb.go             PEB 修补（BeingDebugged、NtGlobalFlag、Heap、DebugPort）
    token.go           权限提升，Token 窃取，身份模拟
    vad.go             VAD 枚举，隐藏/恢复区域
    files.go           通过 Nt* syscall 进行文件 I/O
    registry.go        通过 Nt* syscall 实现注册表持久化
    fingerprint.go     SSN 导出，构建指纹，十六进制导出/导入
    inject_advanced.go 4 种注入方法：Section 映射、进程镂空、APC、模块覆盖
    antianalysis.go    虚拟机/沙箱/调试器/计时检测，评分威胁报告
    handles.go         系统句柄枚举，EDR 句柄清除
    memcrypt.go        Vault（重密钥 XOR）、SecureDelete、StackEncrypt、WipeMemory
  syscallnix/          Linux/darwin 原始 syscall
  patches/             AMSI、ETW、NtTraceEvent、DbgUiRemoteBreakin、InstrumentationCallbacks
  channels/            HTTP、DNS（TXT）、ICMP — Channel 接口
  crypto/              AES-256-GCM，信封封装，密码短语变体（3 个测试）
  server/              SessionManager，任务队列，交互式 REPL
  agent/               配置，信标循环，10 个任务处理器
  cmd/server/main.go   带 REPL 的 CLI
  cmd/agent/main.go    仅 Windows 入口
```

---

## 构建

```bash
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-agent.exe   ./cmd/agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o voidsyscall-server.exe  ./cmd/server
GOOS=linux   GOARCH=amd64 go build -ldflags="-s -w" -o server-linux            ./cmd/server
GOOS=darwin  GOARCH=arm64 go build -ldflags="-s -w" -o server-darwin           ./cmd/server
```

使用 [garble](https://github.com/burrowers/garble) 进行混淆：

```bash
GOOS=windows GOARCH=amd64 garble -literals -tiny build -ldflags="-s -w" \
    -o voidsyscall-agent.exe ./cmd/agent
```

---

## 使用方法

### 服务端

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
./voidsyscall-server.exe --cert cert.pem --key key.pem --https-port 443
```

### Agent

```bash
./voidsyscall-agent.exe -c agent/example-config.json
```

### 任务协议

| 任务 | 字节 | 载荷 |
|------|------|------|
| shell | `0x01` | UTF-8 命令 |
| inject | `0x02` | PID（4 字节 LE）+ shellcode |
| patch | `0x03` | 0x01=AMSI，0x02=ETW，0x03=两者 |
| sleep | `0x04` | 秒数（4 字节 LE） |
| evasion | `0x10` | 0x01=完整，0x02=虚拟机，0x03=沙箱，0x04=调试器，0x05=计时，0x06=报告 |
| handles | `0x11` | 0x01=计数，0x02=枚举 EDR，0x03=关闭 EDR，0x04=是否被监控？ |
| vault | `0x12` | 加密存储操作 |
| fingerprint | `0x13` | 导出 SSN 构建指纹 |
| token | `0x14` | 0x01=启用全部权限，0x02=完整性等级，0x03=调试权限，0x04=身份模拟 |
| exit | `0xFF` | — |

---

## SSN 解析内部机制

1. `ReadGSBase`（汇编）→ `GS:[0x60]` → **TEB**
2. TEB+0x60 → **PEB**。PEB+0x18 → `Ldr`
3. 遍历 `InMemoryOrderModuleList` → 通过 djb2 哈希匹配 `ntdll.dll`
4. 基址 → `IMAGE_DOS_HEADER` → `e_lfanew` → `IMAGE_NT_HEADERS` → DataDirectory[0] = **导出表**
5. 遍历 `AddressOfNames[]`，逐项 djb2 哈希，匹配目标
6. 解析序号 → `AddressOfFunctions[序号]` → 函数地址
7. 扫描前导序列：`B8 xx xx 00 00 0F 05`（直接）、`B8 xx xx 00 00 C3`（提前返回）、`4C 8B D1 B8 xx xx 00 00 0F 05`（Hells Gate）
8. 提取 2 字节 SSN → 存入 `map[uint32]uint16` 缓存

二进制文件中无函数名，仅有 djb2 哈希。`syscall` 指令绕过所有用户态钩子。

---

## Agent 任务处理器

```go
TaskShell       // 通过 cmd.exe 执行
TaskInject      // 多态：section/hollow/APC/stomp
TaskPatch       // AMSI/ETW/两者
TaskEvasion     // PEB 修补 + 虚拟机/沙箱/调试器/计时检测
TaskHandles     // 枚举 + 清除 EDR 监控句柄
TaskFingerprint // 导出 SSN 构建指纹
TaskToken       // 权限提升 + 身份模拟
TaskVault       // 加密内存存储
TaskSleep       // 感知抖动的睡眠
TaskExit        // 干净退出
```

---

## 状态

**已完成**：信标循环、任务队列、3 个 C2 通道、4 种注入方法、10+ 反检测检查、句柄枚举/关闭、Token 操作、VAD 操作、文件 I/O、注册表持久化、SSN 指纹、内存加密、AMSI/ETW 修补、AES-GCM 加密、会话管理、交互式 REPL。3 个加密测试通过。`go build` 在 Windows 上编译通过。

**待完成**：Linux 自主 Agent（构建已存在，无 Agent 逻辑）、会话密钥轮换、分阶段加载器、NTP/DoH 通道、持久化调度。

## 致谢

- [carved4/go-native-syscall](https://github.com/carved4/go-native-syscall)
- [Enelg52/OffensiveGo](https://github.com/Enelg52/OffensiveGo)
- [am0nsec/HellsGate](https://github.com/am0nsec/HellsGate)
- [f1zm0/acheron](https://github.com/f1zm0/acheron)
- [Sliver C2](https://github.com/BishopFox/sliver)

## 许可证

MIT — [LICENSE](LICENSE)