//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

// kUserSharedData is the user-half of the KUSER_SHARED_DATA page on x64.
// Only fields whose offsets are stable across Windows 10/11 are read here.
const kUserSharedData = 0xFFFFF78000000000

type KUserInfo struct {
	TickCountMicros     uint32
	TickCountMultiplier uint32
	InterruptTime100ns  uint64
	SystemTime100ns     uint64 // since 1601-01-01
	NumberPhysicalPages uint32
	ActiveConsoleId     uint32
	TimeZoneId          int32
}

// ReadKUserShared reads timings and system counters straight from the
// kernel-mapped shared page. Nothing here touches a syscall API, so EDR
// that instruments ntdll/win32k never sees the read.
func ReadKUserShared() (KUserInfo, error) {
	var info KUserInfo
	if !isSharedPageReadable() {
		return info, fmt.Errorf("shared data page not readable")
	}
	info.TickCountMicros = *(*uint32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0000)))
	info.TickCountMultiplier = *(*uint32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0014)))
	info.InterruptTime100ns = *(*uint64)(unsafe.Pointer(uintptr(kUserSharedData + 0x0020)))
	info.SystemTime100ns = *(*uint64)(unsafe.Pointer(uintptr(kUserSharedData + 0x0340)))
	info.NumberPhysicalPages = *(*uint32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0374)))
	info.ActiveConsoleId = *(*uint32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0640)))
	info.TimeZoneId = *(*int32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0644)))
	return info, nil
}

func isSharedPageReadable() (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	// TickCount is microseconds since boot: read twice and require monotonic
	// progress to reject sandboxes that zero or alias the page.
	a := *(*uint32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0000)))
	b := *(*uint32)(unsafe.Pointer(uintptr(kUserSharedData + 0x0000)))
	return a == b
}

// BootedMinutes approximates uptime from the KUSER tick counters.
func (k KUserInfo) BootedMinutes() uint64 {
	raw := uint64(k.TickCountMicros) * uint64(k.TickCountMultiplier)
	return raw / 10000 / 1000 / 60
}
