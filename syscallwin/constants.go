//go:build windows

package syscallwin

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	MEM_RELEASE            = 0x8000
	MEM_DECOMMIT           = 0x4000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
	PAGE_READWRITE         = 0x04
	PAGE_NOACCESS          = 0x01

	THREAD_ALL_ACCESS                 = 0x001FFFFF
	THREAD_CREATE                     = 0x0002
	PROCESS_ALL_ACCESS                = 0x001FFFFF
	PROCESS_CREATE                    = 0x0200
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_SUSPEND                   = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

	TOKEN_ADJUST_PRIVILEGES = 0x0020
	TOKEN_QUERY             = 0x0008
	TOKEN_IMPERSONATE       = 0x0004
	TOKEN_DUPLICATE         = 0x0002

	SECTION_ALL_ACCESS  = 0x001FFFFF
	SECTION_MAP_READ    = 0x0004
	SECTION_MAP_WRITE   = 0x0002
	SECTION_MAP_EXECUTE = 0x0008

	FILE_GENERIC_READ            = 0x00120089
	FILE_GENERIC_WRITE           = 0x00120116
	FILE_SHARE_READ              = 0x00000001
	FILE_SHARE_WRITE             = 0x00000002
	FILE_SHARE_DELETE            = 0x00000004
	FILE_ATTRIBUTE_NORMAL        = 0x00000080
	FILE_OPEN                    = 0x00000001
	FILE_SUPERSEDE               = 0x00000000
	FILE_SYNCHRONOUS_IO_NONALERT = 0x00000020
	FILE_NON_DIRECTORY_FILE      = 0x00000040

	OBJ_CASE_INSENSITIVE = 0x00000040
	OBJ_KERNEL_HANDLE    = 0x00000200
	OBJ_DONT_REPARSE     = 0x00000800

	REG_OPTION_NON_VOLATILE = 0x00000000
	REG_CREATED_NEW_KEY     = 0x00000001
	REG_OPENED_EXISTING_KEY = 0x00000002
	REG_SZ                  = 1

	KEY_READ       = 0x00020019
	KEY_WRITE      = 0x00020006
	KEY_ALL_ACCESS = 0x000F003F

	SystemHandleInformation   = 0x10
	ObjectTypeInformation     = 3
	ObjectInformationAllTypes = 3

	STATUS_SUCCESS              = 0x00000000
	STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
	STATUS_BUFFER_TOO_SMALL     = 0xC0000023

	SeDebugPrivilege = 20
	SeTcbPrivilege   = 7

	ThreadHideFromDebugger = 0x11

	ImageInfoProcess = 0
)

type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	_             [4]byte // padding on amd64
	Buffer        *uint16
}

type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *UnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type ClientId struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type IOStatusBlock struct {
	Status      uintptr
	Information uintptr
}

type PartialOverlap struct {
	Offset     int64
	OffsetHigh int32
	_          [4]byte // padding
}

type ASEnterpriseUpdateInfoRequestBuffer struct {
	EnterpriseID uint64
	CallCount    uint32
}
