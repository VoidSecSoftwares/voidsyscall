//go:build windows

package syscallwin

import "unsafe"


func DJB2Hash(input string) uint32 {
	var h uint32 = 5381
	for i := 0; i < len(input); i++ {
		h = h*33 + uint32(input[i])
	}
	return h | 1
}

func DJB2HashW(input *uint16) uint32 {
	var h uint32 = 5381
	for i := 0; ; i++ {
		c := *(*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(input)) + uintptr(i*2)))
		if c == 0 {
			break
		}
		h = h*33 + uint32(c)
	}
	return h | 1
}
