//+build !go1.12

package netlink

import (
	"os"
	"syscall"
)

func newRawConn(fd *os.File) (syscall.RawConn, error) {
	return &rawConn{fd: fd.Fd()}, nil
}

var _ syscall.RawConn = &rawConn{}

// A rawConn is a syscall.RawConn.
type rawConn struct {
	fd uintptr
}

func (rc *rawConn) Control(f func(fd uintptr)) error {
	f(rc.fd)
	return nil
}

func (rc *rawConn) Read(_ func(fd uintptr) (done bool)) error {
	return notSupported("syscall-conn-read")
}

func (rc *rawConn) Write(_ func(fd uintptr) (done bool)) error {
	return notSupported("syscall-conn-write")
}
