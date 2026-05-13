//go:build linux

package table

// #include <unistd.h>
import "C"

func SystemMemoryAvailableMiB() uint64 {
	return uint64(C.sysconf(C._SC_AVPHYS_PAGES) * C.sysconf(C._SC_PAGE_SIZE) / (1024 * 1024))
}
