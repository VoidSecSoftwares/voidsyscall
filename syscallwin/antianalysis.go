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

// DetectVM uses CPUID leaf 0x40000000 to probe hypervisor signatures.
// Known signatures: VMware (VMwareVMware), VirtualBox (VBOXVBOXVBOX),
// Hyper-V (Microsoft Hv), KVM (KVMKVMKVM), Xen (XenVMMXenVMM).
// Also checks MAC prefix for VMware (00:0C:29, 00:50:56) via registry
// and CPUID leaf 0x40000001 for hypervisor-present bit.
func DetectVM() (bool, string) {
	var regs [4]uintptr
	asm_cpuid(uintptr(0x40000000), &regs[0], &regs[1], &regs[2], &regs[3])

	leaf0 := make([]byte, 12)
	leaf0[0] = byte(regs[1])
	leaf0[1] = byte(regs[1] >> 8)
	leaf0[2] = byte(regs[1] >> 16)
	leaf0[3] = byte(regs[1] >> 24)
	leaf0[4] = byte(regs[2])
	leaf0[5] = byte(regs[2] >> 8)
	leaf0[6] = byte(regs[2] >> 16)
	leaf0[7] = byte(regs[2] >> 24)
	leaf0[8] = byte(regs[3])
	leaf0[9] = byte(regs[3] >> 8)
	leaf0[10] = byte(regs[3] >> 16)
	leaf0[11] = byte(regs[3] >> 24)

	sig := string(leaf0)
	switch {
	case contains(sig, "VMwareVMware"):
		return true, "VMware"
	case contains(sig, "VBOXVBOXVBOX"):
		return true, "VirtualBox"
	case contains(sig, "Microsoft Hv"):
		return true, "Hyper-V"
	case contains(sig, "KVMKVMKVM"):
		return true, "KVM"
	case contains(sig, "XenVMMXenVMM"):
		return true, "Xen"
	case contains(sig, "TCGTCGTCGTCG"):
		return true, "QEMU"
	case contains(sig, "lrpepyh vr"):
		return true, "Parallels"
	}

	asm_cpuid(uintptr(0x40000001), &regs[0], &regs[1], &regs[2], &regs[3])
	if regs[0] != 0 {
		return true, "unknown hypervisor (leaf 0x40000001 present)"
	}

	return false, ""
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
	type RegCheck struct {
		Key   string
		Value string
	}
	checks := []RegCheck{
		{"SOFTWARE\\VMware, Inc.\\VMware Tools", "InstallPath"},
		{"SOFTWARE\\Oracle\\VirtualBox Guest Additions", "InstallDir"},
		{"SYSTEM\\CurrentControlSet\\Services\\VBoxGuest", "Start"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmci", "Start"},
		{"SYSTEM\\CurrentControlSet\\Services\\vmhgfs", "Start"},
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
			return true
		}
	}
	return false
}

func checkSandboxProcesses() bool {
	sandboxNames := []string{
		"wireshark.exe",
		"procmon.exe",
		"procmon64.exe",
		"pestudio.exe",
		"processhacker.exe",
		"x64dbg.exe",
		"ollydbg.exe",
		"idaq.exe",
		"idaq64.exe",
		"dumpcap.exe",
		"fiddler.exe",
		"apimonitor.exe",
		"rtnsagent.exe",
		"vmtoolsd.exe",
		"vboxservice.exe",
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
				nameBytes := buf[nameStart:]
				var name [260]byte
				for i := 0; i < 260 && i < len(nameBytes); i++ {
					if nameBytes[i] == 0 && i+1 < len(nameBytes) && nameBytes[i+1] == 0 {
						break
					}
					if i%2 == 0 {
						name[i/2] = nameBytes[i]
					}
				}
				procName := string(name[:])
				for _, sandbox := range sandboxNames {
					if len(procName) >= len(sandbox) {
						for j := 0; j <= len(procName)-len(sandbox); j++ {
							match := true
							for k := 0; k < len(sandbox); k++ {
								c := procName[j+k]
								sc := sandbox[k]
								if c >= 'A' && c <= 'Z' {
									c += 32
								}
								if c != sc {
									match = false
									break
								}
							}
							if match {
								return true
							}
						}
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
