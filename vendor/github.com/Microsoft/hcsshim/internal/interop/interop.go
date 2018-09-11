package interop

import (
	"syscall"
	"unsafe"
)

//go:generate go run $GOROOT/src/syscall/mksyscall_windows.go -output zsyscall_windows.go interop.go

//sys coTaskMemFree(buffer unsafe.Pointer) = ole32.CoTaskMemFree

func ConvertAndFreeCoTaskMemString(buffer *uint16) string {
	str := syscall.UTF16ToString((*[1 << 29]uint16)(unsafe.Pointer(buffer))[:])
	coTaskMemFree(unsafe.Pointer(buffer))
	return str
}

func ConvertAndFreeCoTaskMemBytes(buffer *uint16) []byte {
	return []byte(ConvertAndFreeCoTaskMemString(buffer))
}

func Win32FromHresult(hr uintptr) syscall.Errno {
	if hr&0x1fff0000 == 0x00070000 {
		return syscall.Errno(hr & 0xffff)
	}
	return syscall.Errno(hr)
}
