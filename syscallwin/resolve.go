//go:build windows

package syscallwin

import (
	"fmt"
	"os"
	"unsafe"
)

var (
	ntdllMod     uintptr
	ntdllSize    uintptr
	ntdllDiskBuf []byte
	ssnCache     map[uint32]uint16
)

func GetModuleBase(moduleName string) (uintptr, error) {
	peb := (*[64]byte)(unsafe.Pointer(ReadGSBase()))
	ldrOffset := uint64(0x18)
	ldr := *(**byte)(unsafe.Pointer(uintptr(unsafe.Pointer(peb)) + uintptr(ldrOffset)))
	inMemoryOrderOffset := uint64(0x20)
	flinkOffset := uint64(0x00)

	moduleHash := DJB2Hash(moduleName)

	current := *(*uintptr)(unsafe.Pointer(uintptr(unsafe.Pointer(ldr)) + uintptr(flinkOffset)))

	for i := 0; i < 500; i++ {
		entry := uintptr(unsafe.Pointer(ldr)) + uintptr(flinkOffset)
		_ = entry

		moduleEntry := current
		fl := *(*uintptr)(unsafe.Pointer(moduleEntry + uintptr(flinkOffset)))
		if fl == 0 {
			return 0, fmt.Errorf("module %s not found", moduleName)
		}

		_unicodeStr := moduleEntry + uintptr(inMemoryOrderOffset) - 0x10
		unicodeStr := (*UnicodeString)(unsafe.Pointer(_unicodeStr))

		if unicodeStr.Length > 0 && unicodeStr.Buffer != nil {
			hash := DJB2HashW(unicodeStr.Buffer)
			if hash == moduleHash {
				dosHeader := *(*uintptr)(unsafe.Pointer(moduleEntry + uintptr(inMemoryOrderOffset) + 0x10))
				ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
				ntHeaders := dosHeader + uintptr(ntHeadersOffset)
				imageBase := *(*uintptr)(unsafe.Pointer(ntHeaders + 0x30))
				return imageBase, nil
			}
		}
		current = fl
	}
	return 0, fmt.Errorf("module %s not found after 500 iterations", moduleName)
}

func findGadget(base uintptr, size uintptr, fnHash uint32) (uintptr, error) {
	for i := uintptr(0); i < size-4; i++ {
		// RET: C3
		// Check for: 4C 8B D1 B8 XX XX 00 00 0F 05 C3 (direct syscall pattern)
		if *(*byte)(unsafe.Pointer(base + i)) == 0xC3 {
			retOffset := i
			if i >= 10 {
				pattern := *(*[4]byte)(unsafe.Pointer(base + i - 4))
				if pattern[0] == 0x0F && pattern[1] == 0x05 { // SYSCALL
					_ = retOffset
				}
			}
		}
	}

	dosHeader := *(*uintptr)(unsafe.Pointer(base))
	if *(*uint16)(unsafe.Pointer(dosHeader)) != 0x5A4D {
		return 0, fmt.Errorf("invalid PE header")
	}
	ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
	ntHeaders := dosHeader + uintptr(ntHeadersOffset)
	NumberOfRvaAndSizes := *(*uint32)(unsafe.Pointer(ntHeaders + 0x74))
	optionalHeader := ntHeaders + 0x18

	exportDirRVA := *(*uint32)(unsafe.Pointer(optionalHeader + 0x70))
	exportDirSize := *(*uint32)(unsafe.Pointer(optionalHeader + 0x74))
	if exportDirRVA == 0 || NumberOfRvaAndSizes < 1 {
		return 0, fmt.Errorf("no export directory")
	}

	exportDir := base + uintptr(exportDirRVA)
	numberOfNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	namesRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x20))
	functionsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x1C))
	ordinalsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x24))
	_ = exportDirSize

	names := base + uintptr(namesRVA)
	functions := base + uintptr(functionsRVA)
	ordinals := base + uintptr(ordinalsRVA)

	for i := uint32(0); i < numberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(names + uintptr(i*4)))
		name := base + uintptr(nameAddr)
		nameHash := DJB2Hash(goStringAt(name))
		if nameHash == fnHash {
			ordinalIdx := *(*uint16)(unsafe.Pointer(ordinals + uintptr(i*2)))
			funcRVA := *(*uint32)(unsafe.Pointer(functions + uintptr(uint32(ordinalIdx)*4)))
			funcAddr := base + uintptr(funcRVA)
			return funcAddr, nil
		}
	}
	return 0, fmt.Errorf("function with hash 0x%x not found", fnHash)
}

func goStringAt(addr uintptr) string {
	var buf []byte
	for i := uintptr(0); i < 256; i++ {
		b := *(*byte)(unsafe.Pointer(addr + i))
		if b == 0 {
			break
		}
		buf = append(buf, b)
	}
	return string(buf)
}

// findSyscallGadget locates the SysWhispers-style syscall;ret gadget (0F 05 C3) inside ntdll.
func findSyscallGadget(base uintptr, size uintptr) (uintptr, error) {
	for i := uintptr(0); i < size-3; i++ {
		b0 := *(*byte)(unsafe.Pointer(base + i))
		b1 := *(*byte)(unsafe.Pointer(base + i + 1))
		b2 := *(*byte)(unsafe.Pointer(base + i + 2))
		if b0 == 0x0F && b1 == 0x05 && b2 == 0xC3 {
			return base + i, nil
		}
	}
	return 0, fmt.Errorf("syscall gadget not found")
}

// scanSSN walks the exported stub in search of the SSN immediate. The window
// is widened to 64 bytes and tolerant of EDR trampolines: a jmp-hook only
// displaces the mov immediate, it does not remove it.
func scanSSN(addr uintptr) (uint16, error) {
	for i := uintptr(0); i < 64; i++ {
		b0 := *(*byte)(unsafe.Pointer(addr + i))
		if b0 == 0xB8 {
			b5 := *(*byte)(unsafe.Pointer(addr + i + 5))
			b6 := *(*byte)(unsafe.Pointer(addr + i + 6))
			if b5 == 0x0F && b6 == 0x05 {
				// B8 XX XX 00 00 0F 05 — MOV EAX, SSN; SYSCALL
				return uint16(*(*byte)(unsafe.Pointer(addr + i + 1))) | uint16(*(*byte)(unsafe.Pointer(addr + i + 2)))<<8, nil
			}
			if b5 == 0xC3 {
				// B8 XX XX 00 00 C3 — MOV EAX, SSN; RET
				return uint16(*(*byte)(unsafe.Pointer(addr + i + 1))) | uint16(*(*byte)(unsafe.Pointer(addr + i + 2)))<<8, nil
			}
		}
		if b0 == 0x4C && *(*byte)(unsafe.Pointer(addr + i + 1)) == 0x8B &&
			*(*byte)(unsafe.Pointer(addr + i + 2)) == 0xD1 && *(*byte)(unsafe.Pointer(addr + i + 3)) == 0xB8 {
			// 4C 8B D1 B8 XX XX 00 00 0F 05 — Hells Gate direct
			return uint16(*(*byte)(unsafe.Pointer(addr + i + 4))) | uint16(*(*byte)(unsafe.Pointer(addr + i + 5)))<<8, nil
		}
	}

	// Last resort: any MOV EAX, imm32 inside the stub.
	for i := uintptr(0); i < 64; i++ {
		b0 := *(*byte)(unsafe.Pointer(addr + i))
		if b0 == 0xB8 {
			return uint16(*(*byte)(unsafe.Pointer(addr + i + 1))) | uint16(*(*byte)(unsafe.Pointer(addr + i + 2)))<<8, nil
		}
	}

	return 0, fmt.Errorf("could not determine SSN")
}

func resolveSSNIn(base uintptr, size uintptr, fnHash uint32) (uint16, error) {
	addr, err := findGadget(base, size, fnHash)
	if err != nil {
		return 0, err
	}
	return scanSSN(addr)
}

func resolveSSN(base uintptr, fnHash uint32) (uint16, error) {
	return resolveSSNIn(base, ntdllSize, fnHash)
}

func ResolveFromDisk(dllPath string) error {
	data, err := os.ReadFile(dllPath)
	if err != nil {
		return fmt.Errorf("read ntdll from disk: %w", err)
	}
	ntdllDiskBuf = data
	return nil
}

func InitNtdll() error {
	mod, err := GetModuleBase("ntdll.dll")
	if err != nil {
		return fmt.Errorf("get ntdll base: %w", err)
	}
	ntdllMod = mod

	dosHeader := *(*uintptr)(unsafe.Pointer(mod))
	ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
	ntHeaders := mod + uintptr(ntHeadersOffset)
	optionalHeader := ntHeaders + 0x18
	imageSize := *(*uint32)(unsafe.Pointer(optionalHeader + 0x38))
	ntdllSize = uintptr(imageSize)

	ssnCache = make(map[uint32]uint16, 2048)

	// Best-effort: keep a disk copy handy so DetectNtdllHooks can diff
	// against a clean image without depending on tool-supplied files.
	_ = loadNtdllDiskCopy()
	return nil
}

func GetSSN(funcHash uint32) (uint16, error) {
	if ssnCache == nil {
		if err := InitNtdll(); err != nil {
			return 0, err
		}
	}
	if ssn, ok := ssnCache[funcHash]; ok {
		return ssn, nil
	}
	ssn, err := resolveSSN(ntdllMod, funcHash)
	if err != nil {
		return 0, err
	}
	ssnCache[funcHash] = ssn
	return ssn, nil
}

func GetSSNByName(funcName string) (uint16, error) {
	hash := DJB2Hash(funcName)
	return GetSSN(hash)
}

func PrewarmCache(hashes []uint32) error {
	for _, h := range hashes {
		if _, err := GetSSN(h); err != nil {
			return fmt.Errorf("prewarm hash 0x%x: %w", h, err)
		}
	}
	return nil
}

func CacheSize() int {
	return len(ssnCache)
}
