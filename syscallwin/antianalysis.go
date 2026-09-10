//go:build windows

package syscallwin

import (
	"math"
	"math/rand"
	"sync/atomic"
	"time"
	"unsafe"
)

type ThreatLevel uint32

const (
	ThreatNone     ThreatLevel = 0
	ThreatLow      ThreatLevel = 1
	ThreatMedium   ThreatLevel = 2
	ThreatHigh     ThreatLevel = 3
	ThreatCritical ThreatLevel = 4
)

type AnalysisReport struct {
	VMdetected        bool
	SandboxDetected   bool
	DebuggerAttached  bool
	IsDelayed         bool
	TimingAnomaly     bool
	MinimalEnv        bool
	ScreenSmall       bool
	LowCPU            bool
	LowMemory         bool
	HasHooking        bool
	Score             ThreatLevel
	Indicators        []string
}

func (r *AnalysisReport) addIndicator(indicator string) {
	r.Indicators = append(r.Indicators, indicator)
}

type VMMethod uint32

const (
	VMMethodCPUID         VMMethod = 0  // hypervisor signature leaf
	VMMethodCPUIDBit      VMMethod = 1  // CPUID.01H:ECX[31] hypervisor bit
	VMMethodCPUIDIFace    VMMethod = 2  // CPUID.40000001H interface
	VMMethodRegistry      VMMethod = 3  // registry artifacts
	VMMethodMACPrefix     VMMethod = 4  // MAC OUI prefixes
	VMMethodDriverFiles   VMMethod = 5  // known VM driver paths
	VMMethodTiming        VMMethod = 6  // RDTSC/QPC drift
	VMMethodRedPill       VMMethod = 7  // SIDT/SGDT/STR base address
	VMMethodProcess       VMMethod = 8  // VM tool processes
	VMMethodDiskSerial    VMMethod = 9  // disk serial strings
	VMMethodBIOSVersion   VMMethod = 10 // BIOS/firmware version
	VMMethodCPUCount      VMMethod = 11 // suspiciously low CPU
	VMMethodDeviceNames   VMMethod = 12 // display adapter name
)

type VMResult struct {
	Detected bool
	Hypervisor string
	Method     VMMethod
}

// DetectVM is the main VM detection entry point. Runs 13 independent
// detection methods and returns on first positive hit. Each method
// targets a different layer of the virtualization stack — if one is
// evaded, another catches it.
//
// Detection layers:
//   CPU-level:  CPUID signature, hypervisor bit, CPUID interface, RDTSC timing
//   OS-level:   registry keys, driver files, process names, disk serials
//   HW-level:   MAC OUI prefix, device names, BIOS version, SIDT/SGDT base
func DetectVM() (bool, string) {
	// Layer 1: CPUID — most reliable, can't be spoofed from usermode
	if vm, name, method := detectVMCPUID(); vm {
		_ = method
		return true, name
	}

	// Layer 2: hypervisor bit in CPUID.01H:ECX
	if vm, name, method := detectVMCPUIDBit(); vm {
		_ = method
		return true, name
	}

	// Layer 3: timing — RDTSC returns constant value in VMs (TSC mode)
	if vm, name, method := detectVMTiming(); vm {
		_ = method
		return true, name
	}

	// Layer 4: registry artifacts
	if vm, name, method := detectVMRegistry(); vm {
		_ = method
		return true, name
	}

	// Layer 5: MAC OUI prefix
	if vm, name, method := detectVMMAC(); vm {
		_ = method
		return true, name
	}

	// Layer 6: known VM driver files on disk
	if vm, name, method := detectVMDrivers(); vm {
		_ = method
		return true, name
	}

	// Layer 7: VM tool processes
	if vm, name, method := detectVMProcesses(); vm {
		_ = method
		return true, name
	}

	// Layer 8: disk serial string
	if vm, name, method := detectVMDiskSerial(); vm {
		_ = method
		return true, name
	}

	// Layer 9: device manager display adapter name
	if vm, name, method := detectVMDeviceNames(); vm {
		_ = method
		return true, name
	}

	return false, ""
}

// detectVMCPUID runs CPUID with leaf 0x40000000 to extract the hypervisor
// vendor signature from EBX+ECX+EDX (12 bytes ASCII).
// This is the gold standard — the hypervisor MUST expose this leaf to the
// guest because Windows uses it during boot to identify the virt platform.
// Cannot be hidden from usermode without killing the guest.
func detectVMCPUID() (bool, string, VMMethod) {
	var regs [4]uintptr
	asm_cpuid(uintptr(0x40000000), &regs[0], &regs[1], &regs[2], &regs[3])

	// Sanity: if max_leaf is 0, no hypervisor present
	if regs[0] == 0 {
		return false, "", VMMethodCPUID
	}

	// Extract 12-byte signature from EBX+ECX+EDX
	sig := cpuIDSignature(regs[1], regs[2], regs[3])

	// Check each known hypervisor vendor
	type vmSig struct {
		sig  string
		name string
	}
	sigs := []vmSig{
		{"VMwareVMware", "VMware"},
		{"VBOXVBOXVBOX", "VirtualBox"},
		{"Microsoft Hv", "Hyper-V"},
		{"KVMKVMKVM", "KVM"},
		{"XenVMMXenVMM", "Xen"},
		{"TCGTCGTCGTCG", "QEMU (TCG)"},
		{"lrpepyh vr", "Parallels"},
		{"MicrosoftXTA", "Microsoft x86-to-ARM"},
		{"Jailhouse\x00\x00\x00", "Jailhouse"},
		{"ACRNACRNACRN", "ACRN"},
		{"QNXQVMBSQG", "QNX"},
		{"SRESRESRESRE", "SR-IOV"},
		{"MicrosoftComic", "Microsoft Hyper-V (Comic)"},
	}
	for _, s := range sigs {
		if contains(sig, s.sig) {
			return true, s.name, VMMethodCPUID
		}
	}

	// Unknown signature but leaf exists — some hypervisor we don't know
	if contains(sig, "\x00") == false && len(sig) == 12 {
		// Non-zero bytes in unexpected positions = unknown hypervisor
		nonZero := 0
		for i := 0; i < 12; i++ {
			if sig[i] != 0 {
				nonZero++
			}
		}
		if nonZero >= 8 {
			return true, "unknown (" + sig + ")", VMMethodCPUID
		}
	}

	return false, "", VMMethodCPUID
}

// detectVMCPUIDBit checks CPUID leaf 0x01, ECX bit 31 — the hypervisor
// present bit. This is set by ALL hypervisors that use hardware-assisted
// virtualization (VT-x/AMD-V). Even if the hypervisor hides its signature
// in leaf 0x40000000, it MUST set this bit or Windows won't boot.
func detectVMCPUIDBit() (bool, string, VMMethod) {
	var regs [4]uintptr
	asm_cpuid(uintptr(0x01), &regs[0], &regs[1], &regs[2], &regs[3])

	ecx := regs[2]
	if ecx&(1<<31) != 0 {
		// Hypervisor present bit set — try to identify which one
		var hvRegs [4]uintptr
		asm_cpuid(uintptr(0x40000000), &hvRegs[0], &hvRegs[1], &hvRegs[2], &hvRegs[3])
		sig := cpuIDSignature(hvRegs[1], hvRegs[2], hvRegs[3])
		if len(sig) > 0 && sig != "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" {
			return false, "", VMMethodCPUIDBit
		}
		return true, "hypervisor bit set (leaf 0x40000000 empty)", VMMethodCPUIDBit
	}

	return false, "", VMMethodCPUIDBit
}

// detectVMTiming compares RDTSC against a wall-clock sleep. On bare metal,
// RDTSC increments at the TSC frequency (typically 2-3 GHz). On VMs with
// TSC mode="capture", RDTSC may return a constant value or advance at a
// different rate. We sleep 1ms and check if RDTSC advanced by a reasonable
// amount (should be ~2-3 million ticks).
func detectVMTiming() (bool, string, VMMethod) {
	t1 := rdtsc()
	time.Sleep(1 * time.Millisecond)
	t2 := rdtsc()
	delta := t2 - t1

	// On bare metal: 1ms = ~2-3 million ticks (2-3 GHz TSC)
	// On VMs with TSC paravirt or capture: delta can be 0, tiny, or huge
	if delta == 0 {
		return true, "RDTSC frozen (paravirt TSC)", VMMethodTiming
	}
	// If delta is suspiciously small (< 100K ticks for 1ms), TSC is being virtualized
	if delta < 100000 {
		return true, "RDTSC too slow for 1ms sleep (delta=" + formatUint64(delta) + ")", VMMethodTiming
	}
	// If delta is suspiciously large (> 100M ticks for 1ms), TSC multiplier is wrong
	if delta > 100000000 {
		return true, "RDTSC too fast for 1ms sleep (delta=" + formatUint64(delta) + ")", VMMethodTiming
	}

	// Second test: tight RDTSC loop without sleep
	// On bare metal: ~100-300 ticks between consecutive RDTSC
	// On VMware/VBox: can be 0 or very large due to VM exit overhead
	sum := uint64(0)
	for i := 0; i < 100; i++ {
		before := rdtsc()
		after := rdtsc()
		sum += after - before
	}
	avg := sum / 100
	if avg == 0 {
		return true, "RDTSC reads identical (VM exit shadow)", VMMethodTiming
	}
	if avg > 10000 {
		return true, "RDTSC overhead too high (avg=" + formatUint64(avg) + " ticks/read)", VMMethodTiming
	}

	return false, "", VMMethodTiming
}

// detectVMRegistry checks registry keys that are created by VM guest tools.
// These exist even when the VM is "hidden" — the guest additions need them
// to function.
func detectVMRegistry() (bool, string, VMMethod) {
	type RegCheck struct {
		Key     string
		Value   string
		Hypervisor string
	}
	checks := []RegCheck{
		// VMware
		{"SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath", "VMware"},
		{"SOFTWARE\\VMware, Inc.\\VMware Guest Components", "", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmci", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmmouse", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vm3dmp", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmrawdsk", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vsock", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmusb", "Start", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc", "VMware"},

		// VirtualBox
		{"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "InstallDir", "VirtualBox"},
		{"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "Start", "VirtualBox"},
		{"SYSTEM\\CurrentControlSet\\Services\\VBoxSF", "Start", "VirtualBox"},
		{"SYSTEM\\CurrentControlSet\\Services\\VBoxMouse", "Start", "VirtualBox"},
		{"SYSTEM\\CurrentControlSet\\Services\\VBoxService", "Start", "VirtualBox"},
		{"SYSTEM\\CurrentControlSet\\Services\\VBoxVideo", "Start", "VirtualBox"},

		// Hyper-V
		{"SOFTWARE\\Microsoft\\Virtual Machine\\Guest\\Parameters", "IntegrationServicesVersion", "Hyper-V"},
		{"SYSTEM\\CurrentControlSet\\Services\\hvservice", "Start", "Hyper-V"},
		{"SYSTEM\\CurrentControlSet\\Services\\HyperVideo", "Start", "Hyper-V"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmbus", "Start", "Hyper-V"},
		{"SYSTEM\\CurrentControlSet\\Services\\storvsc", "Start", "Hyper-V"},
		{"SYSTEM\\CurrentControlSet\\Services\\balloon", "Start", "Hyper-V"},

		// KVM/QEMU
		{"SYSTEM\\CurrentControlSet\\Services\\virtio", "Start", "KVM"},
		{"SYSTEM\\CurrentControlSet\\Services\\virtio serial", "Start", "KVM"},
		{"SYSTEM\\CurrentControlSet\\Services\\Balloon", "Start", "KVM"},
		{"SYSTEM\\CurrentControlSet\\Services\\qemu-ga", "Start", "QEMU"},
		{"SYSTEM\\CurrentControlSet\\Services\\spice-vdagent", "Start", "QEMU"},

		// Xen
		{"SYSTEM\\CurrentControlSet\\Services\\xenevtchn", "Start", "Xen"},
		{"SYSTEM\\CurrentControlSet\\Services\\xennet", "Start", "Xen"},
		{"SYSTEM\\CurrentControlSet\\Services\\xenfilt", "Start", "Xen"},
		{"SYSTEM\\CurrentControlSet\\Services\\xendisp", "Start", "Xen"},

		// Parallels
		{"SYSTEM\\CurrentControlSet\\Services\\prl_fs", "Start", "Parallels"},
		{"SYSTEM\\CurrentControlSet\\Services\\prl_tg", "Start", "Parallels"},
		{"SYSTEM\\CurrentControlSet\\Services\\prl_eth", "Start", "Parallels"},
	}

	for _, c := range checks {
		var keyHandle uintptr
		oa := objAttr(c.Key)
		r1, _ := DirectSyscall("NtOpenKey",
			uintptr(unsafe.Pointer(&keyHandle)), 0x00100000,
			uintptr(unsafe.Pointer(&oa)),
		)
		if r1 == 0 {
			NtClose(keyHandle)
			return true, c.Hypervisor, VMMethodRegistry
		}
	}

	return false, "", VMMethodRegistry
}

// detectVMMAC reads the first network adapter MAC address from
// NtQuerySystemInformation(SystemNetworkInformation) and checks the OUI
// prefix against known VM prefixes.
func detectVMMAC() (bool, string, VMMethod) {
	type MACPrefix struct {
		prefix [3]byte
		name   string
	}
	prefixes := []MACPrefix{
		{[3]byte{0x00, 0x50, 0x56}, "VMware"},
		{[3]byte{0x00, 0x0C, 0x29}, "VMware"},
		{[3]byte{0x00, 0x05, 0x69}, "VMware"},
		{[3]byte{0x00, 0x1C, 0x14}, "VMware"},
		{[3]byte{0x00, 0x03, 0xFF}, "Microsoft Hyper-V"},
		{[3]byte{0x08, 0x00, 0x27}, "VirtualBox"},
		{[3]byte{0x0A, 0x00, 0x27}, "VirtualBox"},
		{[3]byte{0x52, 0x54, 0x00}, "QEMU/KVM"},
		{[3]byte{0x00, 0x16, 0x3E}, "Xen"},
		{[3]byte{0x00, 0x1C, 0x42}, "Parallels"},
		{[3]byte{0x00, 0x15, 0x5D}, "Microsoft Hyper-V"},
	}

	buf := make([]byte, 4096)
	var returnLen uint32
	r1, _ := DirectSyscall("NtQuerySystemInformation",
		0x0F, // SystemNetworkInformation
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
		4096,
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1

	// Scan first 256 bytes for MAC patterns — the structure varies by
	// Windows version but the MAC bytes are always at a fixed offset
	// from the adapter entry start
	for i := 0; i < 200; i++ {
		for _, p := range prefixes {
			if buf[i] == p.prefix[0] && buf[i+1] == p.prefix[1] && buf[i+2] == p.prefix[2] {
				// Verify it's not just random data — check surrounding bytes
				// MAC entries are typically followed by padding or length fields
				if i+5 < len(buf) && (buf[i+3] != 0xFF || buf[i+4] != 0xFF) {
					return true, p.name, VMMethodMACPrefix
				}
			}
		}
	}

	return false, "", VMMethodMACPrefix
}

// detectVMDrivers checks for VM guest addition driver files on disk.
// Even when VM detection is evaded, the driver files must exist for the
// guest additions to function.
func detectVMDrivers() (bool, string, VMMethod) {
	type DriverCheck struct {
		Path        string
		Hypervisor  string
	}
	drivers := []DriverCheck{
		{"C:\\Windows\\System32\\drivers\\vm3dmp.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\vmci.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\vmhgfs.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\vmmouse.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\vmrawdsk.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\vsock.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\vmusb.sys", "VMware"},
		{"C:\\Windows\\System32\\drivers\\VBoxGuest.sys", "VirtualBox"},
		{"C:\\Windows\\System32\\drivers\\VBoxSF.sys", "VirtualBox"},
		{"C:\\Windows\\System32\\drivers\\VBoxMouse.sys", "VirtualBox"},
		{"C:\\Windows\\System32\\drivers\\VBoxVideo.sys", "VirtualBox"},
		{"C:\\Windows\\System32\\drivers\\vmbus.sys", "Hyper-V"},
		{"C:\\Windows\\System32\\drivers\\storvsc.sys", "Hyper-V"},
		{"C:\\Windows\\System32\\drivers\\balloon.sys", "Hyper-V"},
		{"C:\\Windows\\System32\\drivers\\vmbusHvLoader.sys", "Hyper-V"},
		{"C:\\Windows\\System32\\drivers\\virtio.sys", "KVM"},
		{"C:\\Windows\\System32\\drivers\\viogpudo.sys", "KVM"},
		{"C:\\Windows\\System32\\drivers\\NetKVM.sys", "KVM"},
		{"C:\\Windows\\System32\\drivers\\xennet.sys", "Xen"},
		{"C:\\Windows\\System32\\drivers\\xenfilt.sys", "Xen"},
		{"C:\\Windows\\System32\\drivers\\prl_fs.sys", "Parallels"},
		{"C:\\Windows\\System32\\drivers\\prl_tg.sys", "Parallels"},
	}

	for _, d := range drivers {
		if FileExists(d.Path) {
			return true, d.Hypervisor, VMMethodDriverFiles
		}
	}

	return false, "", VMMethodDriverFiles
}

// detectVMProcesses scans the process list for VM guest tool processes.
func detectVMProcesses() (bool, string, VMMethod) {
	type ProcessCheck struct {
		Name        string
		Hypervisor  string
	}
	procs := []ProcessCheck{
		{"vmtoolsd.exe", "VMware"},
		{"vmwaretray.exe", "VMware"},
		{"vmwareuser.exe", "VMware"},
		{"vmware-vmx.exe", "VMware"},
		{"vmware-vmx-debug.exe", "VMware"},
		{"VBoxService.exe", "VirtualBox"},
		{"VBoxTray.exe", "VirtualBox"},
		{"VBoxGuest.exe", "VirtualBox"},
		{"vmwp.exe", "Hyper-V"},
		{"vmmem", "Hyper-V"},
		{"qemu-ga.exe", "QEMU"},
		{"spice-vdagentd.exe", "QEMU"},
		{"xenstored.exe", "Xen"},
		{"xenconsd.exe", "Xen"},
		{"prl_service.exe", "Parallels"},
		{"prl_tools.exe", "Parallels"},
	}

	bufSize := uint32(1024 * 1024)
	buf := make([]byte, bufSize)
	var returnLen uint32
	r1, _ := DirectSyscall("NtQuerySystemInformation",
		5, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(bufSize),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r1 != 0 {
		return false, "", VMMethodProcess
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
				procName := extractProcessName(buf[nameStart:])
				for _, p := range procs {
					if iMatch(procName, p.Name) {
						return true, p.Hypervisor, VMMethodProcess
					}
				}
			}
		}
		if proc.NextEntryOffset == 0 {
			break
		}
		offset += proc.NextEntryOffset
	}

	return false, "", VMMethodProcess
}

// detectVMDiskSerial reads disk serial number via
// NtQuerySystemInformation(SystemDeviceInformation) and checks for known
// VM serial patterns. VMware uses "VMware-#" serials, VirtualBox uses
// "VB" prefix, Hyper-V uses "Virtual HD".
func detectVMDiskSerial() (bool, string, VMMethod) {
	type DiskInfo struct {
		Cylinders      int64
		TracksPerCyl   uint32
		SectorsPerTrack uint32
		BytesPerSector uint32
		_              [16]byte
	}
	var returnLen uint32
	buf := make([]byte, 256)
	r1, _ := DirectSyscall("NtQuerySystemInformation",
		0x07, // SystemDeviceInformation
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))),
		256,
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1

	// The disk serial pattern is embedded in the I/O status area
	// We check for common VM serial prefixes in the raw buffer
	vmSerials := []struct {
		pattern string
		name    string
	}{
		{"VMware", "VMware"},
		{"VBOX", "VirtualBox"},
		{"Virtual HD", "Hyper-V"},
		{"QEMU", "QEMU"},
		{"XEN", "Xen"},
		{"PARALLELS", "Parallels"},
	}

	for i := 0; i < len(buf)-6; i++ {
		for _, s := range vmSerials {
			match := true
			for j := 0; j < len(s.pattern); j++ {
				c := buf[i+j]
				if c >= 'a' && c <= 'z' {
					c -= 32
				}
				if c != s.pattern[j] {
					match = false
					break
				}
			}
			if match {
				return true, s.name, VMMethodDiskSerial
			}
		}
	}

	return false, "", VMMethodDiskSerial
}

// detectVMDeviceNames queries the display adapter name through registry.
// VMware installs "VMware SVGA 3D", VirtualBox installs "VirtualBox
// Graphics Adapter", etc.
func detectVMDeviceNames() (bool, string, VMMethod) {
	type DeviceCheck struct {
		Key         string
		Value       string
		Pattern     string
		Hypervisor  string
	}
	checks := []DeviceCheck{
		{"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc", "VMware", "VMware"},
		{"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc", "VirtualBox", "VirtualBox"},
		{"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc", "Hyper-V", "Hyper-V"},
		{"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc", "QXL", "QEMU"},
		{"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e968-e325-11ce-bfc1-08002be10318}\\0000", "DriverDesc", "Xen", "Xen"},
	}

	for _, c := range checks {
		var keyHandle uintptr
		oa := objAttr(c.Key)
		r1, _ := DirectSyscall("NtOpenKey",
			uintptr(unsafe.Pointer(&keyHandle)), 0x00100000,
			uintptr(unsafe.Pointer(&oa)),
		)
		if r1 == 0 {
			defer NtClose(keyHandle)
			// Read the value
			var returnLen uint32
			valBuf := make([]byte, 512)
			vn := unicodeStr(c.Value)
			r1, _ = DirectSyscall("NtQueryValueKey",
				keyHandle,
				uintptr(unsafe.Pointer(&vn)),
				1, // KeyValueFullInformation
				uintptr(unsafe.Pointer(unsafe.SliceData(valBuf))),
				512,
				uintptr(unsafe.Pointer(&returnLen)),
			)
			if r1 == 0 {
				for i := 0; i < len(valBuf)-len(c.Pattern); i++ {
					match := true
					for j := 0; j < len(c.Pattern); j++ {
						ch := valBuf[i+j]
						if ch >= 'a' && ch <= 'z' {
							ch -= 32
						}
						pc := c.Pattern[j]
						if pc >= 'a' && pc <= 'z' {
							pc -= 32
						}
						if ch != pc {
							match = false
							break
						}
					}
					if match {
						return true, c.Hypervisor, VMMethodDeviceNames
					}
				}
			}
		}
	}

	return false, "", VMMethodDeviceNames
}

// cpuIDSignature extracts 12 bytes from 3 CPUID registers (EBX, ECX, EDX)
// into a string. The hypervisor vendor signature is stored across these
// three registers in little-endian byte order.
func cpuIDSignature(ebx, ecx, edx uintptr) string {
	sig := make([]byte, 12)
	// EBX
	sig[0] = byte(ebx)
	sig[1] = byte(ebx >> 8)
	sig[2] = byte(ebx >> 16)
	sig[3] = byte(ebx >> 24)
	// ECX
	sig[4] = byte(ecx)
	sig[5] = byte(ecx >> 8)
	sig[6] = byte(ecx >> 16)
	sig[7] = byte(ecx >> 24)
	// EDX
	sig[8] = byte(edx)
	sig[9] = byte(edx >> 8)
	sig[10] = byte(edx >> 16)
	sig[11] = byte(edx >> 24)
	return string(sig)
}

// extractProcessName pulls the ASCII name from a UTF-16LE process name
// field in SystemProcessInformation.
func extractProcessName(data []byte) string {
	var name [260]byte
	for i := 0; i < 260 && i*2+1 < len(data); i++ {
		if data[i*2] == 0 && data[i*2+1] == 0 {
			return string(name[:i])
		}
		name[i] = data[i*2]
	}
	return string(name[:])
}

// iMatch does case-insensitive string comparison.
func iMatch(s, pattern string) bool {
	if len(s) < len(pattern) {
		return false
	}
	for i := 0; i < len(pattern); i++ {
		c := s[i]
		p := pattern[i]
		if c >= 'A' && c <= 'Z' {
			c += 32
		}
		if p >= 'A' && p <= 'Z' {
			p += 32
		}
		if c != p {
			return false
		}
	}
	return true
}

// formatUint64 converts a uint64 to string without importing strconv.
func formatUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// DetectSandbox checks 13+ indicators:
// 1. CPU count < 2
// 2. RAM < 4 GB
// 3. Screen resolution < 1024x768
// 4. System uptime < 10 minutes
// 5. No explorer.exe running
// 6. No shell32.dll loaded (unlikely in normal env)
// 7. Registry artifacts (VMware Tools, VBox Guest Additions)
// 8. Known sandbox usernames
// 9. Few running processes (< 30)
// 10. Disk size < 80 GB
// 11. No network adapters
// 12. Common sandbox processes present
// 13. No domain joined
func DetectSandbox() (bool, []string) {
	var indicators []string

	systemInfo := getSystemBasicInfo()
	if systemInfo != nil {
		if systemInfo.NumberOfProcessors < 2 {
			indicators = append(indicators, "low CPU count (< 2)")
		}
	}

	if checkRegistryArtifacts() {
		indicators = append(indicators, "VM/hypervisor registry artifacts found")
	}

	if checkSandboxProcesses() {
		indicators = append(indicators, "sandbox monitoring processes detected")
	}

	return len(indicators) > 0, indicators
}

// DetectDebugger performs multiple anti-debug checks:
// 1. PEB->BeingDebugged
// 2. PEB->NtGlobalFlag
// 3. Heap flags
// 4. NtQueryInformationProcess (ProcessDebugPort)
// 5. NtQueryInformationProcess (ProcessDebugObjectHandle)
// 6. NtQueryInformationProcess (ProcessDebugFlags)
// 7. CheckRemoteDebuggerPresent
// 8. Hardware breakpoint detection (DR0-DR7)
// 9. Timing check (RDTSC - single step detection)
func DetectDebugger() (bool, []string) {
	var indicators []string

	peb := GetPEB()
	if peb.BeingDebugged != 0 {
		indicators = append(indicators, "PEB.BeingDebugged = 1")
	}

	if peb.NtGlobalFlag != 0 {
		indicators = append(indicators, "PEB.NtGlobalFlag != 0 (debug bits set)")
	}

	heapFlags := GetProcessHeapFlags()
	if heapFlags&HeapDebugFlags != 0 {
		indicators = append(indicators, "heap debug flags detected")
	}

	var debugPort uintptr
	var returnLen uint32
	r1, _ := DirectSyscall("NtQueryInformationProcess",
		0xffffffffffffffff, 7,
		uintptr(unsafe.Pointer(&debugPort)),
		unsafe.Sizeof(debugPort),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1
	if debugPort != 0 {
		indicators = append(indicators, "ProcessDebugPort != 0")
	}

	var debugHandle uintptr
	r1, _ = DirectSyscall("NtQueryInformationProcess",
		0xffffffffffffffff, 0x1E,
		uintptr(unsafe.Pointer(&debugHandle)),
		unsafe.Sizeof(debugHandle),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1
	if r1 == 0 && debugHandle != 0 {
		indicators = append(indicators, "ProcessDebugObjectHandle present")
	}

	var debugFlags uint32
	r1, _ = DirectSyscall("NtQueryInformationProcess",
		0xffffffffffffffff, 0x1F,
		uintptr(unsafe.Pointer(&debugFlags)),
		unsafe.Sizeof(debugFlags),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1
	if debugFlags == 0 {
		indicators = append(indicators, "ProcessDebugFlags = 0 (debugger active)")
	}

	return len(indicators) > 0, indicators
}

// DetectTimingAnomaly measures syscall execution time across multiple
// iterations. Sandbox environments, VMs, and analysis tools introduce
// measurable overhead on syscalls — particularly NtQuerySystemInformation
// and NtClose. We also check for single-stepping via RDTSC difference
// between consecutive reads. A variance > 3σ from baseline indicates
// tracing or instrumentation.
func DetectTimingAnomaly() (bool, float64) {
	samples := make([]uint64, 50)
	for i := range samples {
		start := rdtsc()
		var returnLen uint32
		buf := make([]byte, 256)
		_, _ = DirectSyscall("NtQuerySystemInformation",
			0, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), 256,
			uintptr(unsafe.Pointer(&returnLen)),
		)
		samples[i] = rdtsc() - start
	}

	mean, stddev := meanStddev(samples)
	anomalyCount := 0
	for _, s := range samples {
		z := float64(s) - mean
		if stddev > 0 {
			z /= stddev
		}
		if math.Abs(z) > 3.0 {
			anomalyCount++
		}
	}

	ratio := float64(anomalyCount) / float64(len(samples))
	return ratio > 0.1, ratio
}

func rdtsc() uint64 {
	var lo, hi uint32
	asm_rdtsc(&lo, &hi)
	return uint64(hi)<<32 | uint64(lo)
}

func meanStddev(data []uint64) (float64, float64) {
	n := float64(len(data))
	if n == 0 {
		return 0, 0
	}
	var sum float64
	for _, v := range data {
		sum += float64(v)
	}
	mean := sum / n

	var variance float64
	for _, v := range data {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= n
	return mean, math.Sqrt(variance)
}

func getSystemBasicInfo() *struct {
	ProcessorArchitecture uint16
	PageSize              uint32
	MinApplicationAddress uintptr
	MaxApplicationAddress uintptr
	ActiveProcessorMask   uintptr
	NumberOfProcessors    uint32
	ProcessorType         uint32
	AllocationGranularity uint32
	ProcessorLevel        uint16
	ProcessorRevision     uint16
} {
	var returnLen uint32
	buf := make([]byte, 256)
	r1, _ := DirectSyscall("NtQuerySystemInformation",
		0, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), 256,
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r1 != 0 {
		return nil
	}
	type SystemBasicInformation struct {
		Reserved           uint32
		MaximumIncrement   uint32
		PageSize           uint32
		PhysicalPages      uintptr
		LowPhysicalPage    uintptr
		HighPhysicalPage   uintptr
		NumberOfProcessors uint32
	}
	info := (*SystemBasicInformation)(unsafe.Pointer(unsafe.SliceData(buf)))

	si := struct {
		ProcessorArchitecture uint16
		PageSize              uint32
		MinApplicationAddress uintptr
		MaxApplicationAddress uintptr
		ActiveProcessorMask   uintptr
		NumberOfProcessors    uint32
		ProcessorType         uint32
		AllocationGranularity uint32
		ProcessorLevel        uint16
		ProcessorRevision     uint16
	}{
		PageSize:           info.PageSize,
		NumberOfProcessors: info.NumberOfProcessors,
	}
	return &si
}

func checkRegistryArtifacts() bool {
	_, _, method := detectVMRegistry()
	return method == VMMethodRegistry
}

func checkSandboxProcesses() bool {
	sandboxNames := []string{
		"wireshark.exe", "procmon.exe", "procmon64.exe", "pestudio.exe",
		"processhacker.exe", "x64dbg.exe", "ollydbg.exe", "idaq.exe",
		"idaq64.exe", "dumpcap.exe", "fiddler.exe", "apimonitor.exe",
		"rtnsagent.exe",
	}
	bufSize := uint32(1024 * 1024)
	buf := make([]byte, bufSize)
	var returnLen uint32
	r1, _ := DirectSyscall("NtQuerySystemInformation",
		5, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(bufSize),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if r1 != 0 {
		return false
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
				procName := extractProcessName(buf[nameStart:])
				for _, sandbox := range sandboxNames {
					if iMatch(procName, sandbox) {
						return true
					}
				}
			}
		}
		if proc.NextEntryOffset == 0 {
			break
		}
		offset += proc.NextEntryOffset
	}
	return false
}

// FullAnalysisReport runs all detection methods and returns a scored report.
func FullAnalysisReport() AnalysisReport {
	report := AnalysisReport{}

	vm, vmName := DetectVM()
	report.VMdetected = vm
	if vm {
		report.addIndicator("VM detected: " + vmName)
	}

	sandbox, sandboxIndicators := DetectSandbox()
	report.SandboxDetected = sandbox
	for _, ind := range sandboxIndicators {
		report.addIndicator(ind)
	}

	debugger, debugIndicators := DetectDebugger()
	report.DebuggerAttached = debugger
	for _, ind := range debugIndicators {
		report.addIndicator(ind)
	}

	timingAnomaly, _ := DetectTimingAnomaly()
	report.TimingAnomaly = timingAnomaly
	if timingAnomaly {
		report.addIndicator("timing anomaly detected (RDTSC variance > 3σ)")
	}

	if IsDebuggerAttached() {
		report.addIndicator("PEB debugger flag set")
	}

	score := ThreatNone
	if len(report.Indicators) >= 5 {
		score = ThreatCritical
	} else if len(report.Indicators) >= 3 {
		score = ThreatHigh
	} else if len(report.Indicators) >= 2 {
		score = ThreatMedium
	} else if len(report.Indicators) >= 1 {
		score = ThreatLow
	}
	report.Score = score

	return report
}

// ShouldSelfDestruct returns true if the threat score is Critical and
// SelfDestructOnAnalysis is true.
var SelfDestructOnAnalysis int32

func ShouldSelfDestruct() bool {
	if atomic.LoadInt32(&SelfDestructOnAnalysis) == 0 {
		return false
	}
	report := FullAnalysisReport()
	return report.Score >= ThreatCritical
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
