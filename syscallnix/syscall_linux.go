//go:build linux

package syscallnix

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	_SYS_READ   = 0
	_SYS_WRITE  = 1
	_SYS_OPEN   = 2
	_SYS_CLOSE  = 3
	_SYS_MMAP   = 9
	_SYS_MPROTECT = 10
	_SYS_MUNMAP = 11
	_SYS_GETPID = 39
	_SYS_KILL   = 62
	_SYS_CLONE  = 56
	_SYS_EXECVE = 59
	_SYS_EXIT   = 60
	_SYS_RT_SIGACTION = 13

	PROT_READ  = 0x1
	PROT_WRITE = 0x2
	PROT_EXEC  = 0x4

	MAP_PRIVATE = 0x02
	MAP_ANONYMOUS = 0x20
	MAP_JIT     = 0x0800

	MADV_DONTNEED = 4
)

func RawSyscall(num, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.RawSyscall(num, a1, a2, a3)
}

func Syscall(num, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.Syscall(num, a1, a2, a3)
}

func Mmap(length uintptr, prot int, fd int, offset int) (uintptr, error) {
	r1, _, errno := syscall.RawSyscall6(_SYS_MMAP,
		0,
		length,
		uintptr(prot),
		uintptr(MAP_PRIVATE|MAP_ANONYMOUS),
		uintptr(fd),
		uintptr(offset),
	)
	if errno != 0 {
		return 0, fmt.Errorf("mmap: %w", errno)
	}
	return r1, nil
}

func Mprotect(addr, length uintptr, prot int) error {
	_, _, errno := syscall.RawSyscall(_SYS_MPROTECT,
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
	_, _, errno := syscall.RawSyscall(_SYS_MUNMAP, addr, length, 0)
	if errno != 0 {
		return fmt.Errorf("munmap: %w", errno)
	}
	return nil
}

func Write(fd int, data []byte) (int, error) {
	if len(data) == 0 {
		return 0, nil
	}
	n, _, errno := syscall.RawSyscall(_SYS_WRITE,
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
	n, _, errno := syscall.RawSyscall(_SYS_READ,
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
	syscall.RawSyscall(_SYS_EXIT, uintptr(code), 0, 0)
}

func Getpid() int {
	pid, _, _ := syscall.RawSyscall(_SYS_GETPID, 0, 0, 0)
	return int(pid)
}

func Execve(path string, argv []string, envp []string) error {
	_ = path
	_ = argv
	_ = envp
	return fmt.Errorf("execve: not implemented in v1")
}

func SelfDelete(path string) error {
	return syscall.Unlink(path)
}
