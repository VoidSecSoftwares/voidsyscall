//go:build darwin

package syscallnix

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	_PROT_READ  = 0x01
	_PROT_WRITE = 0x02
	_PROT_EXEC  = 0x04

	_MAP_PRIVATE = 0x0002
	_MAP_ANON    = 0x1000
	_MAP_JIT     = 0x0800
)

func Mmap(length uintptr, prot int, fd int, offset int) (uintptr, error) {
	r1, _, errno := syscall.RawSyscall6(syscall.SYS_MMAP,
		0,
		length,
		uintptr(prot),
		uintptr(_MAP_PRIVATE|_MAP_ANON),
		uintptr(fd),
		uintptr(offset),
	)
	if errno != 0 {
		return 0, fmt.Errorf("mmap: %w", errno)
	}
	return r1, nil
}

func Mprotect(addr, length uintptr, prot int) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_MPROTECT,
		addr,
		length,
		uintptr(prot),
	)
	if errno != 0 {
		return fmt.Errorf("mprotect: %w", errno)
	}
	return nil
}

func Munmap(addr, length uintptr) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_MUNMAP, addr, length, 0)
	if errno != 0 {
		return fmt.Errorf("munmap: %w", errno)
	}
	return nil
}

func Write(fd int, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	n, _, errno := syscall.RawSyscall(syscall.SYS_WRITE,
		uintptr(fd),
		uintptr(unsafe.Pointer(unsafe.SliceData(data))),
		uintptr(len(data)),
	)
	if errno != 0 {
		return int(n), fmt.Errorf("write: %w", errno)
	}
	return int(n), nil
}

func Read(fd int, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	n, _, errno := syscall.RawSyscall(syscall.SYS_READ,
		uintptr(fd),
		uintptr(unsafe.Pointer(unsafe.SliceData(data))),
		uintptr(len(data)),
	)
	if errno != 0 {
		return int(n), fmt.Errorf("read: %w", errno)
	}
	return int(n), nil
}

func Exit(code int) {
	syscall.RawSyscall(syscall.SYS_EXIT, uintptr(code), 0, 0)
}

func SelfDelete(path string) error {
	return syscall.Unlink(path)
}
