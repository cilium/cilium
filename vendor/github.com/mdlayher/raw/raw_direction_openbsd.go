// +build openbsd

package raw

import (
	"syscall"
	"unsafe"
)

// setBPFDirection enables filtering traffic traveling in a specific direction
// using BPF, so that traffic sent by this package is not captured when reading
// using this package.
func setBPFDirection(fd int, direction int) error {
	var dirfilt uint

	switch direction {
	case 0:
		// filter outbound
		dirfilt = syscall.BPF_DIRECTION_OUT
	default:
		// no filter
	}

	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		syscall.BIOCSDIRFILT,
		uintptr(unsafe.Pointer(&dirfilt)),
	)
	if err != 0 {
		return syscall.Errno(err)
	}

	return nil
}
