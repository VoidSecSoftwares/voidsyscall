//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

func CreateFileNt(path string, desiredAccess uint32, shareAccess uint32, disposition uint32, options uint32) (uintptr, error) {
	pathUTF16, err := stringToUTF16(path)
	if err != nil {
		return 0, err
	}
	us := UnicodeString{
		Length:        uint16(len(path) * 2),
		MaximumLength: uint16(len(path)*2 + 2),
		Buffer:        pathUTF16,
	}
	objAttr := ObjectAttributes{
		Length:     uint32(unsafe.Sizeof(ObjectAttributes{})),
		ObjectName: &us,
		Attributes: OBJ_CASE_INSENSITIVE,
	}
	var fileHandle uintptr
	var ioStatus IOStatusBlock
	r1, err := DirectSyscall("NtCreateFile",
		uintptr(unsafe.Pointer(&fileHandle)),
		uintptr(desiredAccess),
		uintptr(unsafe.Pointer(&objAttr)),
		uintptr(unsafe.Pointer(&ioStatus)),
		0, uintptr(FILE_ATTRIBUTE_NORMAL), uintptr(shareAccess),
		uintptr(disposition), uintptr(options), 0, 0,
	)
	if r1 != 0 || err != nil {
		return 0, fmt.Errorf("NtCreateFile %s: NTSTATUS 0x%x", path, r1)
	}
	return fileHandle, nil
}

func ReadFileNt(fileHandle uintptr, size uint32) ([]byte, error) {
	buf := make([]byte, size)
	var ioStatus IOStatusBlock
	r1, err := DirectSyscall("NtReadFile",
		fileHandle, 0, 0, 0,
		uintptr(unsafe.Pointer(&ioStatus)),
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))), uintptr(size),
		0, 0,
	)
	if r1 != 0 || err != nil {
		return nil, fmt.Errorf("NtReadFile: NTSTATUS 0x%x", r1)
	}
	return buf[:ioStatus.Information], nil
}

func WriteFileNt(fileHandle uintptr, data []byte) (uintptr, error) {
	var ioStatus IOStatusBlock
	r1, err := DirectSyscall("NtWriteFile",
		fileHandle, 0, 0, 0,
		uintptr(unsafe.Pointer(&ioStatus)),
		uintptr(unsafe.Pointer(unsafe.SliceData(data))), uintptr(len(data)),
		0, 0,
	)
	if r1 != 0 || err != nil {
		return 0, fmt.Errorf("NtWriteFile: NTSTATUS 0x%x", r1)
	}
	return ioStatus.Information, nil
}

func ReadFileContents(path string) ([]byte, error) {
	handle, err := CreateFileNt(path, FILE_GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return nil, err
	}
	defer NtClose(handle)

	var fileSize int64
	var returnLen uint32
	r1, _ := DirectSyscall("NtQueryInformationFile", handle, 0,
		uintptr(unsafe.Pointer(&fileSize)), 8, 5,
		uintptr(unsafe.Pointer(&returnLen)),
	)
	_ = r1
	if fileSize <= 0 || fileSize > 10*1024*1024 {
		fileSize = 10 * 1024 * 1024
	}
	return ReadFileNt(handle, uint32(fileSize))
}

func WriteFileContents(path string, data []byte) error {
	handle, err := CreateFileNt(path, FILE_GENERIC_WRITE, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return err
	}
	defer NtClose(handle)
	_, err = WriteFileNt(handle, data)
	return err
}

func DeleteFileNt(path string) error {
	pathUTF16, err := stringToUTF16(path)
	if err != nil {
		return err
	}
	us := UnicodeString{
		Length:        uint16(len(path) * 2),
		MaximumLength: uint16(len(path)*2 + 2),
		Buffer:        pathUTF16,
	}
	objAttr := ObjectAttributes{
		Length:     uint32(unsafe.Sizeof(ObjectAttributes{})),
		ObjectName: &us,
		Attributes: OBJ_CASE_INSENSITIVE,
	}
	r1, _ := DirectSyscall("NtDeleteFile", uintptr(unsafe.Pointer(&objAttr)))
	_ = r1
	return nil
}

func FileExists(path string) bool {
	handle, err := CreateFileNt(path, FILE_GENERIC_READ,
		FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, FILE_OPEN,
		FILE_SYNCHRONOUS_IO_NONALERT|FILE_NON_DIRECTORY_FILE)
	if err != nil {
		return false
	}
	NtClose(handle)
	return true
}

func stringToUTF16(s string) (*uint16, error) {
	encoded := make([]uint16, len(s)+1)
	for i, c := range s {
		if c > 0xFFFF {
			continue
		}
		encoded[i] = uint16(c)
	}
	encoded[len(s)] = 0
	return &encoded[0], nil
}
