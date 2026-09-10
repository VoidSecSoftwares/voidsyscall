//go:build windows

package syscallwin

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unsafe"
)

type SSNEntry struct {
	NameHash uint32
	SSN      uint16
}

type SSNFingerprint struct {
	ntdllBase  uintptr
	ssnMap     map[uint32]uint16
	gadgetAddr uintptr
}

var globalFingerprint *SSNFingerprint

func GetSSNFingerprint() (*SSNFingerprint, error) {
	if globalFingerprint != nil {
		return globalFingerprint, nil
	}

	base, err := GetModuleBase("ntdll.dll")
	if err != nil {
		return nil, fmt.Errorf("find ntdll: %w", err)
	}

	ssnMap := make(map[uint32]uint16)

	dosHeader := *(*uintptr)(unsafe.Pointer(base))
	ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
	ntHeaders := base + uintptr(ntHeadersOffset)
	optionalHeader := ntHeaders + 0x18
	exportDirRVA := *(*uint32)(unsafe.Pointer(optionalHeader + 0x70))
	if exportDirRVA == 0 {
		return nil, fmt.Errorf("no export directory")
	}

	exportDir := base + uintptr(exportDirRVA)
	numberOfNames := *(*uint32)(unsafe.Pointer(exportDir + 0x18))
	namesRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x20))
	functionsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x1C))
	ordinalsRVA := *(*uint32)(unsafe.Pointer(exportDir + 0x24))

	names := base + uintptr(namesRVA)
	functions := base + uintptr(functionsRVA)
	ordinals := base + uintptr(ordinalsRVA)

	for i := uint32(0); i < numberOfNames; i++ {
		nameAddr := *(*uint32)(unsafe.Pointer(names + uintptr(i*4)))
		name := goStringAt(base + uintptr(nameAddr))
		hash := DJB2Hash(name)

		ordinalIdx := *(*uint16)(unsafe.Pointer(ordinals + uintptr(i*2)))
		funcRVA := *(*uint32)(unsafe.Pointer(functions + uintptr(uint32(ordinalIdx)*4)))
		funcAddr := base + uintptr(funcRVA)

		ssn, err := resolveSSN(base, hash)
		if err == nil && ssn > 0 {
			ssnMap[hash] = ssn
		}
		_ = funcAddr
	}

	gadget, _ := findSyscallGadget(base, ntdllSize)

	globalFingerprint = &SSNFingerprint{
		ntdllBase:  base,
		ssnMap:     ssnMap,
		gadgetAddr: gadget,
	}
	return globalFingerprint, nil
}

func (fp *SSNFingerprint) GetSSN(funcHash uint32) (uint16, bool) {
	ssn, ok := fp.ssnMap[funcHash]
	return ssn, ok
}

func (fp *SSNFingerprint) GetGadget() uintptr       { return fp.gadgetAddr }
func (fp *SSNFingerprint) GetSSNCount() int          { return len(fp.ssnMap) }
func (fp *SSNFingerprint) GetNtdllBase() uintptr     { return fp.ntdllBase }
func (fp *SSNFingerprint) ExportMap() map[uint32]uint16 {
	out := make(map[uint32]uint16, len(fp.ssnMap))
	for k, v := range fp.ssnMap {
		out[k] = v
	}
	return out
}

func (fp *SSNFingerprint) ToFingerprintHash() string {
	hashes := make([]string, 0, len(fp.ssnMap))
	for k, v := range fp.ssnMap {
		hashes = append(hashes, fmt.Sprintf("%08x:%04x", k, v))
	}
	sort.Strings(hashes)
	return fmt.Sprintf("%08x", DJB2Hash(strings.Join(hashes, "|")))
}

func GenerateBuildFingerprint() (string, int, uintptr, error) {
	fp, err := GetSSNFingerprint()
	if err != nil {
		return "", 0, 0, err
	}
	return fp.ToFingerprintHash(), fp.GetSSNCount(), fp.GetGadget(), nil
}

func FingerprintToBytes() ([]byte, error) {
	fp, err := GetSSNFingerprint()
	if err != nil {
		return nil, err
	}
	entries := make([]SSNEntry, 0, len(fp.ssnMap))
	for hash, ssn := range fp.ssnMap {
		entries = append(entries, SSNEntry{NameHash: hash, SSN: ssn})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].NameHash < entries[j].NameHash })

	buf := make([]byte, 0, len(entries)*6+8)
	gadgetBytes := uintptrToBytes(fp.gadgetAddr)
	buf = append(buf, gadgetBytes...)
	for _, e := range entries {
		buf = append(buf, byte(e.NameHash), byte(e.NameHash>>8), byte(e.NameHash>>16), byte(e.NameHash>>24))
		buf = append(buf, byte(e.SSN), byte(e.SSN>>8))
	}
	return buf, nil
}

func FingerprintToHex() (string, error) {
	data, err := FingerprintToBytes()
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

func FingerprintFromHex(hexStr string) (*SSNFingerprint, error) {
	data, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, err
	}
	return FingerprintFromBytes(data)
}

func FingerprintFromBytes(data []byte) (*SSNFingerprint, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("fingerprint data too short: %d bytes", len(data))
	}
	gadget := bytesToUintptr(data[:8])
	ssnMap := make(map[uint32]uint16)
	offset := 8
	for offset+6 <= len(data) {
		hash := uint32(data[offset]) | uint32(data[offset+1])<<8 | uint32(data[offset+2])<<16 | uint32(data[offset+3])<<24
		ssn := uint16(data[offset+4]) | uint16(data[offset+5])<<8
		ssnMap[hash] = ssn
		offset += 6
	}
	return &SSNFingerprint{ssnMap: ssnMap, gadgetAddr: gadget}, nil
}

func VerifySSNConsistency() (bool, int, int) {
	fp, err := GetSSNFingerprint()
	if err != nil {
		return false, 0, 0
	}
	total, resolved := 0, 0
	for _, ssn := range fp.ssnMap {
		total++
		if ssn > 0 {
			resolved++
		}
	}
	return total == resolved, total, resolved
}

func GetExportCount() int {
	fp, err := GetSSNFingerprint()
	if err != nil {
		return 0
	}
	return fp.GetSSNCount()
}

func uintptrToBytes(v uintptr) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24),
		byte(v >> 32), byte(v >> 40), byte(v >> 48), byte(v >> 56)}
}

func bytesToUintptr(b []byte) uintptr {
	return uintptr(b[0]) | uintptr(b[1])<<8 | uintptr(b[2])<<16 | uintptr(b[3])<<24 |
		uintptr(b[4])<<32 | uintptr(b[5])<<40 | uintptr(b[6])<<48 | uintptr(b[7])<<56
}
