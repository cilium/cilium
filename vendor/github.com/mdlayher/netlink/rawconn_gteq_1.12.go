//+build go1.12

package netlink

import (
	"os"
	"syscall"
)

func newRawConn(fd *os.File) (syscall.RawConn, error) {
	return fd.SyscallConn()
}
