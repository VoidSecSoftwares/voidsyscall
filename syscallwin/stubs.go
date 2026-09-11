//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

//go:noescape
func Syscall(funcId uint32, arg1, arg2, arg3, arg4, arg5, arg6, arg7 uintptr) (uintptr, uintptr)

//go:noescape
func Syscall9(funcId uint32, arg1, arg2, arg3, arg4, arg5, arg6, arg7, arg8, arg9 uintptr) (uintptr, uintptr)

//go:noescape
func IndirectSyscall(stubAddr uintptr, funcId uint32, arg1, arg2, arg3, arg4, arg5, arg6 uintptr) (uintptr, uintptr)

//go:noescape
func GetCurrentProcHandle() uintptr

//go:noescape
func GetCurrentThreadId() uintptr

//go:noescape
func SetGSBase(newbase uintptr)

//go:noescape
func ReadGSBase() uintptr

//go:noescape
func asm_cpuid(leaf uintptr, a *uintptr, b *uintptr, c *uintptr, d *uintptr)

//go:noescape
func asm_rdtsc(lo *uint32, hi *uint32)

// GetCurrentProcessId reads the PID from the PEB (PEB+0x40, GS[0x60] -> PEB).
func GetCurrentProcessId() (uint32, error) {
	tebBase := ReadGSBase()
	if tebBase == 0 {
		return 0, fmt.Errorf("TEb base is nil")
	}
	pebBase := *(*uintptr)(unsafe.Pointer(tebBase + 0x60))
	pid := *(*uint32)(unsafe.Pointer(pebBase + 0x40))
	return pid, nil
}

func DirectSyscall(funcName string, args ...uintptr) (uintptr, error) {
	hash := DJB2Hash(funcName)
	ssn, err := GetSSN(hash)
	if err != nil {
		return 0, fmt.Errorf("GetSSN(%s): %w", funcName, err)
	}
	var a [7]uintptr
	for i, arg := range args {
		if i < 7 {
			a[i] = arg
		}
	}
	r1, _ := Syscall(uint32(ssn), a[0], a[1], a[2], a[3], a[4], a[5], a[6])
	return r1, nil
}

func DirectSyscallByHash(funcHash uint32, args ...uintptr) (uintptr, error) {
	ssn, err := GetSSN(funcHash)
	if err != nil {
		return 0, fmt.Errorf("GetSSN(0x%x): %w", funcHash, err)
	}
	var a [7]uintptr
	for i, arg := range args {
		if i < 7 {
			a[i] = arg
		}
	}
	r1, _ := Syscall(uint32(ssn), a[0], a[1], a[2], a[3], a[4], a[5], a[6])
	return r1, nil
}

func IndirectSyscallByHash(funcHash uint32, args ...uintptr) (uintptr, error) {
	ssn, err := GetSSN(funcHash)
	if err != nil {
		return 0, fmt.Errorf("GetSSN(0x%x): %w", funcHash, err)
	}
	gadget, err := findSyscallGadget(ntdllMod, ntdllSize)
	if err != nil {
		return 0, fmt.Errorf("find syscall gadget: %w", err)
	}
	var a [6]uintptr
	for i, arg := range args {
		if i < 6 {
			a[i] = arg
		}
	}
	r1, _ := IndirectSyscall(gadget, uint32(ssn), a[0], a[1], a[2], a[3], a[4], a[5])
	return r1, nil
}

func FindGadgetAddress(funcName string) (uintptr, error) {
	hash := DJB2Hash(funcName)
	return findGadget(ntdllMod, ntdllSize, hash)
}

func NtAllocateVirtualMemory(processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, regionSize *uintptr, allocationType uint32, protectType uint32) error {
	r1, err := DirectSyscall("NtAllocateVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(allocationType),
		uintptr(protectType),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtAllocateVirtualMemory failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtWriteVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer []byte, numberOfBytesWritten *uintptr) error {
	r1, err := DirectSyscall("NtWriteVirtualMemory",
		processHandle,
		baseAddress,
		uintptr(unsafe.Pointer(unsafe.SliceData(buffer))),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(numberOfBytesWritten)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtWriteVirtualMemory failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtReadVirtualMemory(processHandle uintptr, baseAddress uintptr, buffer []byte, numberOfBytesRead *uintptr) error {
	r1, err := DirectSyscall("NtReadVirtualMemory",
		processHandle,
		baseAddress,
		uintptr(unsafe.Pointer(unsafe.SliceData(buffer))),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(numberOfBytesRead)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtReadVirtualMemory failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtProtectVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, newProtect uint32, oldProtect *uint32) error {
	r1, err := DirectSyscall("NtProtectVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(newProtect),
		uintptr(unsafe.Pointer(oldProtect)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtProtectVirtualMemory failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtFreeVirtualMemory(processHandle uintptr, baseAddress *uintptr, regionSize *uintptr, freeType uint32) error {
	r1, err := DirectSyscall("NtFreeVirtualMemory",
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(regionSize)),
		uintptr(freeType),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtFreeVirtualMemory failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtCreateThreadEx(threadHandle *uintptr, desiredAccess uint32, objAttrs uintptr, processHandle uintptr, startRoutine uintptr, argument uintptr, createFlags uintptr, zeroBits uintptr, stackSize uintptr, maxStackSize uintptr, attribList uintptr) error {
	r1, err := DirectSyscall("NtCreateThreadEx",
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess),
		objAttrs,
		processHandle,
		startRoutine,
		argument,
		createFlags,
		zeroBits,
		stackSize,
		maxStackSize,
		attribList,
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateThreadEx failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtOpenProcess(processHandle *uintptr, desiredAccess uint32, objAttrs uintptr, clientId *ClientId) error {
	r1, err := DirectSyscall("NtOpenProcess",
		uintptr(unsafe.Pointer(processHandle)),
		uintptr(desiredAccess),
		objAttrs,
		uintptr(unsafe.Pointer(clientId)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtOpenProcess failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtOpenThread(threadHandle *uintptr, desiredAccess uint32, objAttrs uintptr, clientId *ClientId) error {
	r1, err := DirectSyscall("NtOpenThread",
		uintptr(unsafe.Pointer(threadHandle)),
		uintptr(desiredAccess),
		objAttrs,
		uintptr(unsafe.Pointer(clientId)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtOpenThread failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtSuspendProcess(processHandle uintptr) error {
	r1, err := DirectSyscall("NtSuspendProcess", processHandle)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtSuspendProcess failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtResumeProcess(processHandle uintptr) error {
	r1, err := DirectSyscall("NtResumeProcess", processHandle)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtResumeProcess failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtTerminateProcess(processHandle uintptr, exitCode uintptr) error {
	r1, err := DirectSyscall("NtTerminateProcess", processHandle, exitCode)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtTerminateProcess failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtClose(handle uintptr) error {
	r1, err := DirectSyscall("NtClose", handle)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtClose failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtDuplicateObject(sourceProcessHandle uintptr, sourceHandle uintptr, targetProcessHandle uintptr, targetHandle *uintptr, desiredAccess uint32, handleAttributes uint32, options uint32) error {
	r1, err := DirectSyscall("NtDuplicateObject",
		sourceProcessHandle,
		sourceHandle,
		targetProcessHandle,
		uintptr(unsafe.Pointer(targetHandle)),
		uintptr(desiredAccess),
		uintptr(handleAttributes),
		uintptr(options),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtDuplicateObject failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtOpenProcessToken(processHandle uintptr, desiredAccess uint32, tokenHandle *uintptr) error {
	r1, err := DirectSyscall("NtOpenProcessToken",
		processHandle,
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(tokenHandle)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtOpenProcessToken failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtQueryInformationToken(tokenHandle uintptr, tokenInformationClass uint32, tokenInformation uintptr, tokenInformationLength uint32, returnLength *uint32) error {
	r1, err := DirectSyscall("NtQueryInformationToken",
		tokenHandle,
		uintptr(tokenInformationClass),
		tokenInformation,
		uintptr(tokenInformationLength),
		uintptr(unsafe.Pointer(returnLength)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtQueryInformationToken failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtAdjustPrivilegesToken(tokenHandle uintptr, disableAllPrivileges bool, state uintptr, bufferSize uint32, previousState uintptr, returnLength *uint32) error {
	var disable uint32
	if disableAllPrivileges {
		disable = 1
	}
	r1, err := DirectSyscall("NtAdjustPrivilegesToken",
		tokenHandle,
		uintptr(disable),
		state,
		uintptr(bufferSize),
		previousState,
		uintptr(unsafe.Pointer(returnLength)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtAdjustPrivilegesToken failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtCreateKey(keyHandle *uintptr, desiredAccess uint32, objectAttributes uintptr, titleIndex uint32, class uintptr, createOptions uint32, disposition *uint32) error {
	r1, err := DirectSyscall("NtCreateKey",
		uintptr(unsafe.Pointer(keyHandle)),
		uintptr(desiredAccess),
		objectAttributes,
		uintptr(titleIndex),
		class,
		uintptr(createOptions),
		uintptr(unsafe.Pointer(disposition)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateKey failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtSetValueKey(keyHandle uintptr, valueName uintptr, titleIndex uint32, dataType uint32, data uintptr, dataSize uint32) error {
	r1, err := DirectSyscall("NtSetValueKey",
		keyHandle,
		valueName,
		uintptr(titleIndex),
		uintptr(dataType),
		data,
		uintptr(dataSize),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtSetValueKey failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtCreateFile(fileHandle *uintptr, desiredAccess uint32, objectAttributes uintptr, ioStatusBlock *IOStatusBlock, allocationSize *int64, fileAttributes uint32, shareAccess uint32, createDisposition uint32, createOptions uint32, eaBuffer uintptr, eaLength uint32) error {
	r1, err := DirectSyscall("NtCreateFile",
		uintptr(unsafe.Pointer(fileHandle)),
		uintptr(desiredAccess),
		objectAttributes,
		uintptr(unsafe.Pointer(ioStatusBlock)),
		uintptr(unsafe.Pointer(allocationSize)),
		uintptr(fileAttributes),
		uintptr(shareAccess),
		uintptr(createDisposition),
		uintptr(createOptions),
		eaBuffer,
		uintptr(eaLength),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateFile failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtQuerySystemInformation(systemInformationClass uint32, systemInformation uintptr, systemInformationLength uint32, returnLength *uint32) error {
	r1, err := DirectSyscall("NtQuerySystemInformation",
		uintptr(systemInformationClass),
		systemInformation,
		uintptr(systemInformationLength),
		uintptr(unsafe.Pointer(returnLength)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtQuerySystemInformation failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtSetInformationThread(threadHandle uintptr, threadInformationClass uint32, threadInformation uintptr, threadInformationLength uint32) error {
	r1, err := DirectSyscall("NtSetInformationThread",
		threadHandle,
		uintptr(threadInformationClass),
		threadInformation,
		uintptr(threadInformationLength),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtSetInformationThread failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtFlushInstructionCache(processHandle uintptr, baseAddress uintptr, size uintptr) error {
	r1, err := DirectSyscall("NtFlushInstructionCache",
		processHandle,
		baseAddress,
		size,
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtFlushInstructionCache failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtCreateSection(sectionHandle *uintptr, desiredAccess uint32, objectAttributes uintptr, maximumSize *int64, sectionPageProtection uint32, allocationAttributes uint32, fileHandle uintptr) error {
	r1, err := DirectSyscall("NtCreateSection",
		uintptr(unsafe.Pointer(sectionHandle)),
		uintptr(desiredAccess),
		objectAttributes,
		uintptr(unsafe.Pointer(maximumSize)),
		uintptr(sectionPageProtection),
		uintptr(allocationAttributes),
		fileHandle,
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateSection failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtMapViewOfSection(sectionHandle uintptr, processHandle uintptr, baseAddress *uintptr, zeroBits uintptr, commitSize uintptr, sectionOffset *int64, viewSize *uintptr, inheritDisposition uint32, allocationType uint32, win32Protect uint32) error {
	r1, err := DirectSyscall("NtMapViewOfSection",
		sectionHandle,
		processHandle,
		uintptr(unsafe.Pointer(baseAddress)),
		zeroBits,
		commitSize,
		uintptr(unsafe.Pointer(sectionOffset)),
		uintptr(unsafe.Pointer(viewSize)),
		uintptr(allocationType),
		uintptr(win32Protect),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtMapViewOfSection failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}

func NtQueryVirtualMemory(processHandle uintptr, baseAddress uintptr, memoryInformationClass uint32, memoryInformation uintptr, memoryInformationLength uintptr, returnLength *uintptr) error {
	r1, err := DirectSyscall("NtQueryVirtualMemory",
		processHandle,
		baseAddress,
		uintptr(memoryInformationClass),
		memoryInformation,
		memoryInformationLength,
		uintptr(unsafe.Pointer(returnLength)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtQueryVirtualMemory failed: NTSTATUS 0x%x err: %v", r1, err)
	}
	return nil
}
