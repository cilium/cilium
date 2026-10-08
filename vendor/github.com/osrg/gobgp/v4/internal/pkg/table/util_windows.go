//go:build windows

package table

/*
#include <windows.h>
*/
import "C"

import "unsafe"

func SystemMemoryAvailableMiB() uint64 {
	var status C.MEMORYSTATUSEX
	status.dwLength = C.DWORD(unsafe.Sizeof(status))
	C.GlobalMemoryStatusEx(&status)
	return uint64(status.ullAvailPhys) / (1024 * 1024)
}
