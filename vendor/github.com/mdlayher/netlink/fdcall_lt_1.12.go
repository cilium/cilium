//+build !go1.12,linux

package netlink

import "os"

// setBlockingMode exists for compatibility reasons: prior to Go 1.12,
// package netlink used blocking file descriptors, and did not support
// deadlines. This variant of setBlockingMode, which does nothing (i.e.
// it leaves the file descriptor in blocking mode), maintains compatibility
// for users up to and including Go 1.11.
func setBlockingMode(sysfd int) error {
	return nil
}

func fdread(fd *os.File, f func(int) (done bool)) error {
	f(int(fd.Fd()))
	return nil
}

func fdwrite(fd *os.File, f func(int) (done bool)) error {
	f(int(fd.Fd()))
	return nil
}

func fdcontrol(fd *os.File, f func(int)) error {
	f(int(fd.Fd()))
	return nil
}
