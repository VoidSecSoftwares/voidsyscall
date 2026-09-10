//go:build windows

package patches

import (
	"fmt"
	"unsafe"

	"github.com/VoidSecSoftwares/voidsyscall/syscallwin"
)

const (
	ThreadHideFromDebugger = 0x11
)

func PatchInstrumentationCallbacks(threadHandle uintptr) error {
	// NtSetInformationThread(ThreadHideFromDebugger) — prevents debugger/instrumentation callbacks
	r1, err := syscallwin.DirectSyscall("NtSetInformationThread",
		threadHandle,
		uintptr(ThreadHideFromDebugger),
		0,
		0,
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtSetInformationThread(HideFromDebugger): NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func HideThreadFromDebugger() error {
	currentThread := syscallwin.GetCurrentProcHandle()
	return PatchInstrumentationCallbacks(currentThread)
}

func PatchNtSetSystemInformation() error {
	// Patch NtSetSystemInformation to return STATUS_SUCCESS without executing
	// This blocks certain system-debug control operations
	handle, err := syscallwin.DirectSyscall("NtSetSystemInformation", 0, 0, 0, 0)
	_ = handle
	_ = err

	addr, err := syscallwin.FindGadgetAddress("NtSetSystemInformation")
	if err != nil {
		return fmt.Errorf("find NtSetSystemInformation: %w", err)
	}

	baseAddr := addr
	var oldProtect uint32
	regionSize := uintptr(64)
	err = syscallwin.NtProtectVirtualMemory(
		uintptr(0xffffffffffffffff),
		(*uintptr)(unsafe.Pointer(&baseAddr)),
		&regionSize,
		syscallwin.PAGE_EXECUTE_READWRITE,
		&oldProtect,
	)
	if err != nil {
		return fmt.Errorf("unprotect NtSetSystemInformation: %w", err)
	}

	// MOV EAX, STATUS_SUCCESS; RET
	patch := []byte{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}
	var n uintptr
	err = syscallwin.NtWriteVirtualMemory(
		uintptr(0xffffffffffffffff),
		addr,
		patch,
		&n,
	)
	if err != nil {
		return fmt.Errorf("patch NtSetSystemInformation: %w", err)
	}

	var restore uint32
	_ = syscallwin.NtProtectVirtualMemory(
		uintptr(0xffffffffffffffff),
		(*uintptr)(unsafe.Pointer(&baseAddr)),
		&regionSize,
		oldProtect,
		&restore,
	)

	_ = syscallwin.NtFlushInstructionCache(
		uintptr(0xffffffffffffffff),
		addr,
		64,
	)

	return nil
}
