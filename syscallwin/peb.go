//go:build windows

package syscallwin

import (
	"unsafe"
)

const (
	x64BeingDebuggedOffset = 0x2
	x64NtGlobalFlagOffset  = 0xBC
	x64HeapFlagsOffset     = 0x70
	x64ProcessHeapOffset   = 0x30
	x64MinimumStackCommit  = 0x10

	FLG_HEAP_ENABLE_TAIL_CHECK   = 0x00000010
	FLG_HEAP_ENABLE_FREE_CHECK   = 0x00000020
	FLG_HEAP_VALIDATE_PARAMETERS = 0x00000040
	FLG_HEAP_VALIDATE_ALL        = 0x00000080

	HeapDebugFlags = 0x00000002
	HeapTailCheck  = 0x00000010
	HeapFreeCheck  = 0x00000020
	HeapValidate   = 0x00000040
)

type PEB struct {
	_                [2]byte
	BeingDebugged    byte
	_                [1]byte
	_                [4]byte
	ImageBaseAddress uintptr
	Ldr              uintptr
	FastPebLock      uintptr
	ProcessHeap      uintptr
	_                [16]byte
	NtGlobalFlag     uint32
}

func GetPEBAddress() uintptr {
	return ReadGSBase()
}

func GetPEB() *PEB {
	return (*PEB)(unsafe.Pointer(GetPEBAddress()))
}

func patchByteAt(addr uintptr, val byte) {
	var oldProtect uint32
	regionSize := uintptr(1)
	_ = NtProtectVirtualMemory(0xffffffffffffffff, &addr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect)
	var n uintptr
	_ = NtWriteVirtualMemory(0xffffffffffffffff, addr, []byte{val}, &n)
	_ = NtProtectVirtualMemory(0xffffffffffffffff, &addr, &regionSize, oldProtect, &oldProtect)
}

func patchUint32At(addr uintptr, val uint32) {
	var oldProtect uint32
	regionSize := uintptr(4)
	_ = NtProtectVirtualMemory(0xffffffffffffffff, &addr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect)
	buf := []byte{byte(val), byte(val >> 8), byte(val >> 16), byte(val >> 24)}
	var n uintptr
	_ = NtWriteVirtualMemory(0xffffffffffffffff, addr, buf, &n)
	_ = NtProtectVirtualMemory(0xffffffffffffffff, &addr, &regionSize, oldProtect, &oldProtect)
}

func PatchBeingDebugged() {
	patchByteAt(GetPEBAddress()+x64BeingDebuggedOffset, 0)
}

func PatchNtGlobalFlag() {
	patchUint32At(GetPEBAddress()+x64NtGlobalFlagOffset, 0)
}

func PatchHeapFlags() {
	peb := GetPEB()
	if peb.ProcessHeap == 0 {
		return
	}
	patchUint32At(peb.ProcessHeap+x64HeapFlagsOffset, 0x02)
}

func PatchDebugPort() {
	handle := GetCurrentProcHandle()
	r1, _ := DirectSyscall("NtSetInformationProcess", handle, 7, 0, unsafe.Sizeof(uintptr(0)))
	_ = r1
}

func PatchAll() {
	PatchBeingDebugged()
	PatchNtGlobalFlag()
	PatchHeapFlags()
	PatchDebugPort()
}

func IsDebuggerAttached() bool {
	return GetPEB().BeingDebugged != 0
}

func GetNtGlobalFlag() uint32 {
	return GetPEB().NtGlobalFlag
}

func GetImageBase() uintptr {
	return GetPEB().ImageBaseAddress
}

func PatchThreadHideDebugger() {
	threadHandle := uintptr(0xffffffffffffffff)
	r1, _ := DirectSyscall("NtSetInformationThread",
		threadHandle,
		0x11, // ThreadHideFromDebugger
		0, 0,
	)
	_ = r1
}

func GetProcessHeapFlags() uint32 {
	peb := GetPEB()
	if peb.ProcessHeap == 0 {
		return 0
	}
	return *(*uint32)(unsafe.Pointer(peb.ProcessHeap + x64HeapFlagsOffset))
}

func PatchMinimumStackCommit() {
	patchUint32At(GetPEBAddress()+x64MinimumStackCommit, 0)
}
