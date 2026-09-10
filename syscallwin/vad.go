//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	PartitionId       uint16
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
}

type VADRegion struct {
	BaseAddress uintptr
	RegionSize  uintptr
	Protect     uint32
	State       uint32
	Type        uint32
	IsExec      bool
	IsGuard     bool
}

func EnumVirtualMemory(processHandle uintptr) ([]VADRegion, error) {
	var regions []VADRegion
	var baseAddr uintptr

	for {
		var mbi MemoryBasicInformation
		var returnLen uintptr
		r1, err := DirectSyscall("NtQueryVirtualMemory",
			processHandle, baseAddr, 0,
			uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if r1 != 0 || err != nil {
			break
		}
		if mbi.BaseAddress == 0 && mbi.RegionSize == 0 {
			break
		}
		regions = append(regions, VADRegion{
			BaseAddress: mbi.BaseAddress,
			RegionSize:  mbi.RegionSize,
			Protect:     mbi.Protect,
			State:       mbi.State,
			Type:        mbi.Type,
			IsExec:      mbi.Protect == PAGE_EXECUTE_READ || mbi.Protect == PAGE_EXECUTE_READWRITE,
			IsGuard:     mbi.Protect&0x100 != 0,
		})
		baseAddr = mbi.BaseAddress + mbi.RegionSize
		if baseAddr < mbi.BaseAddress {
			break
		}
	}
	return regions, nil
}

func FindWritableExecRegions(processHandle uintptr) ([]VADRegion, error) {
	regions, err := EnumVirtualMemory(processHandle)
	if err != nil {
		return nil, err
	}
	var result []VADRegion
	for _, r := range regions {
		if r.IsExec && r.State == MEM_COMMIT {
			result = append(result, r)
		}
	}
	return result, nil
}

func FindUnmappedRegions(processHandle uintptr) ([]VADRegion, error) {
	regions, err := EnumVirtualMemory(processHandle)
	if err != nil {
		return nil, err
	}
	var result []VADRegion
	for _, r := range regions {
		if r.State == MEM_RESERVE {
			result = append(result, r)
		}
	}
	return result, nil
}

func HideRegion(processHandle uintptr, baseAddr uintptr, size uintptr) error {
	var oldProtect uint32
	base := baseAddr
	regionSize := size
	return NtProtectVirtualMemory(processHandle, &base, &regionSize, PAGE_NOACCESS, &oldProtect)
}

func UnhideRegion(processHandle uintptr, baseAddr uintptr, size uintptr, originalProtect uint32) error {
	var oldProtect uint32
	base := baseAddr
	regionSize := size
	return NtProtectVirtualMemory(processHandle, &base, &regionSize, originalProtect, &oldProtect)
}

func GetRegionInfo(processHandle uintptr, addr uintptr) (*VADRegion, error) {
	var mbi MemoryBasicInformation
	var returnLen uintptr
	r1, err := DirectSyscall("NtQueryVirtualMemory",
		processHandle, addr, 0,
		uintptr(unsafe.Pointer(&mbi)), unsafe.Sizeof(mbi),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r1 != 0 || err != nil {
		return nil, fmt.Errorf("NtQueryVirtualMemory at 0x%x: NTSTATUS 0x%x", addr, r1)
	}
	return &VADRegion{
		BaseAddress: mbi.BaseAddress,
		RegionSize:  mbi.RegionSize,
		Protect:     mbi.Protect,
		State:       mbi.State,
		Type:        mbi.Type,
	}, nil
}
