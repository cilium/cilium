//+build go1.12,linux

package netlink

import (
	"os"

	"golang.org/x/sys/unix"
)

// setBlockingMode puts the file descriptor into non-blocking mode.
func setBlockingMode(sysfd int) error {
	return unix.SetNonblock(sysfd, true)
}

func fdread(fd *os.File, f func(int) (done bool)) error {
	rc, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Read(func(sysfd uintptr) bool {
		return f(int(sysfd))
	})
}

func fdwrite(fd *os.File, f func(int) (done bool)) error {
	rc, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Write(func(sysfd uintptr) bool {
		return f(int(sysfd))
	})
}

func fdcontrol(fd *os.File, f func(int)) error {
	rc, err := fd.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(sysfd uintptr) {
		f(int(sysfd))
	})
}
