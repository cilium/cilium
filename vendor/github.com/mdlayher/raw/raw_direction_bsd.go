// +build darwin dragonfly freebsd netbsd

package raw

import (
	"syscall"
	"unsafe"
)

// setBPFDirection enables filtering traffic traveling in a specific direction
// using BPF, so that traffic sent by this package is not captured when reading
// using this package.
func setBPFDirection(fd int, direction int) error {
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		// Even though BIOCSDIRECTION is preferred on FreeBSD, BIOCSSEESENT continues
		// to work, and is required for other BSD platforms
		syscall.BIOCSSEESENT,
		uintptr(unsafe.Pointer(&direction)),
	)
	if err != 0 {
		return syscall.Errno(err)
	}

	return nil
}
