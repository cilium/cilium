package socket

import (
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// A Conn is a low-level network connection which integrates with Go's runtime
// network poller to provide asynchronous I/O and deadline support.
type Conn struct {
	// Indicates whether or not Conn.Close has been called. Must be accessed
	// atomically. Atomics definitions must come first in the Conn struct.
	closed uint32

	// A unique name for the Conn which is also associated with derived file
	// descriptors such as those created by accept(2).
	name string

	// Provides access to the underlying file registered with the runtime
	// network poller, and arbitrary raw I/O calls.
	fd *os.File
	rc syscall.RawConn
}

// A Config contains options for a Conn.
type Config struct {
	// NetNS specifies the Linux network namespace the Conn will operate in.
	// This option is unsupported on other operating systems.
	//
	// If set (non-zero), Conn will enter the specified network namespace and an
	// error will occur in Socket if the operation fails.
	//
	// If not set (zero), a best-effort attempt will be made to enter the
	// network namespace of the calling thread: this means that any changes made
	// to the calling thread's network namespace will also be reflected in Conn.
	// If this operation fails (due to lack of permissions or because network
	// namespaces are disabled by kernel configuration), Socket will not return
	// an error, and the Conn will operate in the default network namespace of
	// the process. This enables non-privileged use of Conn in applications
	// which do not require elevated privileges.
	//
	// Entering a network namespace is a privileged operation (root or
	// CAP_SYS_ADMIN are required), and most applications should leave this set
	// to 0.
	NetNS int
}

// High-level methods which provide convenience over raw system calls.

// Close closes the underlying file descriptor for the Conn, which also causes
// all in-flight I/O operations to immediately unblock and return errors. Any
// subsequent uses of Conn will result in EBADF.
func (c *Conn) Close() error {
	// The caller has expressed an intent to close the socket, so immediately
	// increment s.closed to force further calls to result in EBADF before also
	// closing the file descriptor to unblock any outstanding operations.
	//
	// Because other operations simply check for s.closed != 0, we will permit
	// double Close, which would increment s.closed beyond 1.
	if atomic.AddUint32(&c.closed, 1) != 1 {
		// Multiple Close calls.
		return nil
	}

	return os.NewSyscallError("close", c.fd.Close())
}

// CloseRead shuts down the reading side of the Conn. Most callers should just
// use Close.
func (c *Conn) CloseRead() error { return c.Shutdown(unix.SHUT_RD) }

// CloseWrite shuts down the writing side of the Conn. Most callers should just
// use Close.
func (c *Conn) CloseWrite() error { return c.Shutdown(unix.SHUT_WR) }

// Read implements io.Reader by reading directly from the underlying file
// descriptor.
func (c *Conn) Read(b []byte) (int, error) { return c.fd.Read(b) }

// Write implements io.Writer by writing directly to the underlying file
// descriptor.
func (c *Conn) Write(b []byte) (int, error) { return c.fd.Write(b) }

// SetDeadline sets both the read and write deadlines associated with the Conn.
func (c *Conn) SetDeadline(t time.Time) error { return c.fd.SetDeadline(t) }

// SetReadDeadline sets the read deadline associated with the Conn.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.fd.SetReadDeadline(t) }

// SetWriteDeadline sets the write deadline associated with the Conn.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.fd.SetWriteDeadline(t) }

// ReadBuffer gets the size of the operating system's receive buffer associated
// with the Conn.
func (c *Conn) ReadBuffer() (int, error) {
	return c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_RCVBUF)
}

// WriteBuffer gets the size of the operating system's transmit buffer
// associated with the Conn.
func (c *Conn) WriteBuffer() (int, error) {
	return c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_SNDBUF)
}

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
//
// When called with elevated privileges on Linux, the SO_RCVBUFFORCE option will
// be used to override operating system limits. Otherwise SO_RCVBUF is used
// (which obeys operating system limits).
func (c *Conn) SetReadBuffer(bytes int) error { return c.setReadBuffer(bytes) }

// SetWriteBuffer sets the size of the operating system's transmit buffer
// associated with the Conn.
//
// When called with elevated privileges on Linux, the SO_SNDBUFFORCE option will
// be used to override operating system limits. Otherwise SO_SNDBUF is used
// (which obeys operating system limits).
func (c *Conn) SetWriteBuffer(bytes int) error { return c.setWriteBuffer(bytes) }

// SyscallConn returns a raw network connection. This implements the
// syscall.Conn interface.
//
// SyscallConn is intended for advanced use cases, such as getting and setting
// arbitrary socket options using the socket's file descriptor. If possible,
// those operations should be performed using methods on Conn instead.
//
// Once invoked, it is the caller's responsibility to ensure that operations
// performed using Conn and the syscall.RawConn do not conflict with each other.
func (c *Conn) SyscallConn() (syscall.RawConn, error) {
	if atomic.LoadUint32(&c.closed) != 0 {
		return nil, os.NewSyscallError("syscallconn", unix.EBADF)
	}

	// TODO(mdlayher): mutex or similar to enforce syscall.RawConn contract of
	// FD remaining valid for duration of calls?
	return c.rc, nil
}

// Socket wraps the socket(2) system call to produce a Conn. domain, typ, and
// proto are passed directly to socket(2), and name should be a unique name for
// the socket type such as "netlink" or "vsock".
//
// The cfg parameter specifies optional configuration for the Conn. If nil, no
// additional configuration will be applied.
//
// If the operating system supports SOCK_CLOEXEC and SOCK_NONBLOCK, they are
// automatically applied to typ to mirror the standard library's socket flag
// behaviors.
func Socket(domain, typ, proto int, name string, cfg *Config) (*Conn, error) {
	if cfg == nil {
		cfg = &Config{}
	}

	if cfg.NetNS == 0 {
		// Non-Linux or no network namespace.
		return socket(domain, typ, proto, name)
	}

	// Linux only: create Conn in the specified network namespace.
	return withNetNS(cfg.NetNS, func() (*Conn, error) {
		return socket(domain, typ, proto, name)
	})
}

// socket is the internal, cross-platform entry point for socket(2).
func socket(domain, typ, proto int, name string) (*Conn, error) {
	var (
		fd  int
		err error
	)

	for {
		fd, err = unix.Socket(domain, typ|socketFlags, proto)
		switch {
		case err == nil:
			// Some OSes already set CLOEXEC with typ.
			if !flagCLOEXEC {
				unix.CloseOnExec(fd)
			}

			// No error, prepare the Conn.
			return New(fd, name)
		case !ready(err):
			// System call interrupted or not ready, try again.
			continue
		case err == unix.EINVAL, err == unix.EPROTONOSUPPORT:
			// On Linux, SOCK_NONBLOCK and SOCK_CLOEXEC were introduced in
			// 2.6.27. On FreeBSD, both flags were introduced in FreeBSD 10.
			// EINVAL and EPROTONOSUPPORT check for earlier versions of these
			// OSes respectively.
			//
			// Mirror what the standard library does when creating file
			// descriptors: avoid racing a fork/exec with the creation of new
			// file descriptors, so that child processes do not inherit socket
			// file descriptors unexpectedly.
			//
			// For a more thorough explanation, see similar work in the Go tree:
			// func sysSocket in net/sock_cloexec.go, as well as the detailed
			// comment in syscall/exec_unix.go.
			syscall.ForkLock.RLock()
			fd, err = unix.Socket(domain, typ, proto)
			if err != nil {
				syscall.ForkLock.RUnlock()
				return nil, os.NewSyscallError("socket", err)
			}
			unix.CloseOnExec(fd)
			syscall.ForkLock.RUnlock()

			return New(fd, name)
		default:
			// Unhandled error.
			return nil, os.NewSyscallError("socket", err)
		}
	}
}

// FileConn returns a copy of the network connection corresponding to the open
// file. It is the caller's responsibility to close the file when finished.
// Closing the Conn does not affect the File, and closing the File does not
// affect the Conn.
func FileConn(f *os.File, name string) (*Conn, error) {
	// First we'll try to do fctnl(2) with F_DUPFD_CLOEXEC because we can dup
	// the file descriptor and set the flag in one syscall.
	fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	switch err {
	case nil:
		// OK, ready to set up non-blocking I/O.
		return New(fd, name)
	case unix.EINVAL:
		// The kernel rejected our fcntl(2), fall back to separate dup(2) and
		// setting close on exec.
		//
		// Mirror what the standard library does when creating file descriptors:
		// avoid racing a fork/exec with the creation of new file descriptors,
		// so that child processes do not inherit socket file descriptors
		// unexpectedly.
		syscall.ForkLock.RLock()
		fd, err := unix.Dup(fd)
		if err != nil {
			syscall.ForkLock.RUnlock()
			return nil, os.NewSyscallError("dup", err)
		}
		unix.CloseOnExec(fd)
		syscall.ForkLock.RUnlock()

		return New(fd, name)
	default:
		// Any other errors.
		return nil, os.NewSyscallError("fcntl", err)
	}
}

// New wraps an existing file descriptor to create a Conn. name should be a
// unique name for the socket type such as "netlink" or "vsock".
//
// Most callers should use Socket or FileConn to construct a Conn. New is
// intended for integrating with specific system calls which provide a file
// descriptor that supports asynchronous I/O. The file descriptor is immediately
// set to nonblocking mode and registered with Go's runtime network poller for
// future I/O operations.
//
// Unlike FileConn, New does not duplicate the existing file descriptor in any
// way. The returned Conn takes ownership of the underlying file descriptor.
func New(fd int, name string) (*Conn, error) {
	// All Conn I/O is nonblocking for integration with Go's runtime network
	// poller. Depending on the OS this might already be set but it can't hurt
	// to set it again.
	if err := unix.SetNonblock(fd, true); err != nil {
		return nil, os.NewSyscallError("setnonblock", err)
	}

	// os.NewFile registers the non-blocking file descriptor with the runtime
	// poller, which is then used for most subsequent operations except those
	// that require raw I/O via SyscallConn.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(fd), name)
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	return &Conn{
		name: name,
		fd:   f,
		rc:   rc,
	}, nil
}

// Low-level methods which provide raw system call access.

// Accept wraps accept(2) or accept4(2) depending on the operating system, but
// returns a Conn for the accepted connection rather than a raw file descriptor.
//
// If the operating system supports accept4(2) (which allows flags),
// SOCK_CLOEXEC and SOCK_NONBLOCK are automatically applied to flags to mirror
// the standard library's socket flag behaviors.
//
// If the operating system only supports accept(2) (which does not allow flags)
// and flags is not zero, an error will be returned.
func (c *Conn) Accept(flags int) (*Conn, unix.Sockaddr, error) {
	var (
		nfd int
		sa  unix.Sockaddr
		err error
	)

	doErr := c.read(sysAccept, func(fd int) error {
		// Either accept(2) or accept4(2) depending on the OS.
		nfd, sa, err = accept(fd, flags|socketFlags)
		return err
	})
	if doErr != nil {
		return nil, nil, doErr
	}
	if err != nil {
		// sysAccept is either "accept" or "accept4" depending on the OS.
		return nil, nil, os.NewSyscallError(sysAccept, err)
	}

	// Successfully accepted a connection, wrap it in a Conn for use by the
	// caller.
	ac, err := New(nfd, c.name)
	if err != nil {
		return nil, nil, err
	}

	return ac, sa, nil
}

// Bind wraps bind(2).
func (c *Conn) Bind(sa unix.Sockaddr) error {
	return c.controlErr("bind", func(fd int) error {
		return unix.Bind(fd, sa)
	})
}

// Connect wraps connect(2). In order to verify that the underlying socket is
// connected to a remote peer, Connect calls getpeername(2) and returns the
// unix.Sockaddr from that call.
func (c *Conn) Connect(sa unix.Sockaddr) (unix.Sockaddr, error) {
	const op = "connect"

	// TODO(mdlayher): it would seem that trying to connect to unbound vsock
	// listeners by calling Connect multiple times results in ECONNRESET for the
	// first and nil error for subsequent calls. Do we need to memoize the
	// error? Check what the stdlib behavior is.

	var (
		// Track progress between invocations of the write closure. We don't
		// have an explicit WaitWrite call like internal/poll does, so we have
		// to wait until the runtime calls the closure again to indicate we can
		// write.
		progress uint32

		// Capture closure sockaddr and error.
		rsa unix.Sockaddr
		err error
	)

	doErr := c.write(op, func(fd int) error {
		if atomic.AddUint32(&progress, 1) == 1 {
			// First call: initiate connect.
			return unix.Connect(fd, sa)
		}

		// Subsequent calls: the runtime network poller indicates fd is
		// writable. Check for errno.
		errno, gerr := c.GetsockoptInt(unix.SOL_SOCKET, unix.SO_ERROR)
		if gerr != nil {
			return gerr
		}
		if errno != 0 {
			// Connection is still not ready or failed. If errno indicates
			// the socket is not ready, we will wait for the next write
			// event. Otherwise we propagate this errno back to the as a
			// permanent error.
			uerr := unix.Errno(errno)
			err = uerr
			return uerr
		}

		// According to internal/poll, it's possible for the runtime network
		// poller to spuriously wake us and return errno 0 for SO_ERROR.
		// Make sure we are actually connected to a peer.
		peer, err := c.Getpeername()
		if err != nil {
			// internal/poll unconditionally goes back to WaitWrite.
			// Synthesize an error that will do the same for us.
			return unix.EAGAIN
		}

		// Connection complete.
		rsa = peer
		return nil
	})
	if doErr != nil {
		return nil, doErr
	}

	if err == unix.EISCONN {
		// TODO(mdlayher): is this block obsolete with the addition of the
		// getsockopt SO_ERROR check above?
		//
		// EISCONN is reported if the socket is already established and should
		// not be treated as an error.
		//  - Darwin reports this for at least TCP sockets
		//  - Linux reports this for at least AF_VSOCK sockets
		return rsa, nil
	}

	return rsa, os.NewSyscallError(op, err)
}

// Getsockname wraps getsockname(2).
func (c *Conn) Getsockname() (unix.Sockaddr, error) {
	const op = "getsockname"

	var (
		sa  unix.Sockaddr
		err error
	)

	doErr := c.control(op, func(fd int) error {
		sa, err = unix.Getsockname(fd)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}

	return sa, os.NewSyscallError(op, err)
}

// Getpeername wraps getpeername(2).
func (c *Conn) Getpeername() (unix.Sockaddr, error) {
	const op = "getpeername"

	var (
		sa  unix.Sockaddr
		err error
	)

	doErr := c.control(op, func(fd int) error {
		sa, err = unix.Getpeername(fd)
		return err
	})
	if doErr != nil {
		return nil, doErr
	}

	return sa, os.NewSyscallError(op, err)
}

// GetsockoptInt wraps getsockopt(2) for integer values.
func (c *Conn) GetsockoptInt(level, opt int) (int, error) {
	const op = "getsockopt"

	var (
		value int
		err   error
	)

	doErr := c.control(op, func(fd int) error {
		value, err = unix.GetsockoptInt(fd, level, opt)
		return err
	})
	if doErr != nil {
		return 0, doErr
	}

	return value, os.NewSyscallError(op, err)
}

// Listen wraps listen(2).
func (c *Conn) Listen(n int) error {
	return c.controlErr("listen", func(fd int) error {
		return unix.Listen(fd, n)
	})
}

// Recvmsg wraps recvmsg(2).
func (c *Conn) Recvmsg(p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
	const op = "recvmsg"

	var (
		n, oobn, recvflags int
		from               unix.Sockaddr
		err                error
	)

	doErr := c.read(op, func(fd int) error {
		n, oobn, recvflags, from, err = unix.Recvmsg(fd, p, oob, flags)
		return err
	})
	if doErr != nil {
		return 0, 0, 0, nil, doErr
	}

	return n, oobn, recvflags, from, os.NewSyscallError(op, err)
}

// Recvfrom wraps recvfrom(2)
func (c *Conn) Recvfrom(p []byte, flags int) (int, unix.Sockaddr, error) {
	const op = "recvfrom"

	var (
		n    int
		addr unix.Sockaddr
		err  error
	)

	doErr := c.read(op, func(fd int) error {
		n, addr, err = unix.Recvfrom(fd, p, flags)
		return err
	})
	if doErr != nil {
		return 0, nil, doErr
	}

	return n, addr, os.NewSyscallError(op, err)
}

// Sendmsg wraps sendmsg(2).
func (c *Conn) Sendmsg(p, oob []byte, to unix.Sockaddr, flags int) error {
	return c.writeErr("sendmsg", func(fd int) error {
		return unix.Sendmsg(fd, p, oob, to, flags)
	})
}

// Sendto wraps sendto(2).
func (c *Conn) Sendto(p []byte, to unix.Sockaddr, flags int) error {
	// TODO(mdlayher): we accidentally swapped argument order when creating this
	// wrapper. Consider fixing.
	return c.writeErr("sendto", func(fd int) error {
		return unix.Sendto(fd, p, flags, to)
	})
}

// SetsockoptInt wraps setsockopt(2) for integer values.
func (c *Conn) SetsockoptInt(level, opt, value int) error {
	return c.controlErr("setsockopt", func(fd int) error {
		return unix.SetsockoptInt(fd, level, opt, value)
	})
}

// Shutdown wraps shutdown(2).
func (c *Conn) Shutdown(how int) error {
	return c.controlErr("shutdown", func(fd int) error {
		return unix.Shutdown(fd, how)
	})
}

// Conn low-level read/write/control functions. These functions mirror the
// syscall.RawConn APIs but the input closures return errors rather than
// booleans. Any syscalls invoked within f should return their error to allow
// the Conn to check for readiness with the runtime network poller, or to retry
// operations which may have been interrupted by EINTR or similar.
//
// Note that errors from the input closure functions are not propagated to the
// error return values of read/write/control, and the caller is still
// responsible for error handling.

// read executes f, a read function, against the associated file descriptor.
// op is used to create an *os.SyscallError if the file descriptor is closed.
func (c *Conn) read(op string, f func(fd int) error) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return os.NewSyscallError(op, unix.EBADF)
	}

	return c.rc.Read(func(fd uintptr) bool {
		return ready(f(int(fd)))
	})
}

// write executes f, a write function, against the associated file descriptor.
// op is used to create an *os.SyscallError if the file descriptor is closed.
func (c *Conn) write(op string, f func(fd int) error) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return os.NewSyscallError(op, unix.EBADF)
	}

	return c.rc.Write(func(fd uintptr) bool {
		return ready(f(int(fd)))
	})
}

// writeErr wraps write to execute a function and capture its error result.
// This is a convenience wrapper for functions which don't return any extra
// values to capture in a closure.
func (c *Conn) writeErr(op string, f func(fd int) error) error {
	var err error
	doErr := c.write(op, func(fd int) error {
		err = f(fd)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// control executes f, a control function, against the associated file
// descriptor. op is used to create an *os.SyscallError if the file descriptor
// is closed.
func (c *Conn) control(op string, f func(fd int) error) error {
	if atomic.LoadUint32(&c.closed) != 0 {
		return os.NewSyscallError(op, unix.EBADF)
	}

	return c.rc.Control(func(fd uintptr) {
		// Repeatedly attempt the syscall(s) invoked by f until completion is
		// indicated by the return value of ready.
		for {
			if ready(f(int(fd))) {
				return
			}
		}
	})
}

// controlErr wraps control to execute a function and capture its error result.
// This is a convenience wrapper for functions which don't return any extra
// values to capture in a closure.
func (c *Conn) controlErr(op string, f func(fd int) error) error {
	var err error
	doErr := c.control(op, func(fd int) error {
		err = f(fd)
		return err
	})
	if doErr != nil {
		return doErr
	}

	return os.NewSyscallError(op, err)
}

// ready indicates readiness based on the value of err.
func ready(err error) bool {
	// When a socket is in non-blocking mode, we might see a variety of errors:
	//  - EAGAIN: most common case for a socket read not being ready
	//  - EINPROGRESS: reported by some sockets when first calling connect
	//  - EINTR: system call interrupted, more frequently occurs in Go 1.14+
	//    because goroutines can be asynchronously preempted
	//
	// Return false to let the poller wait for readiness. See the source code
	// for internal/poll.FD.RawRead for more details.
	switch err {
	case unix.EAGAIN, unix.EINPROGRESS, unix.EINTR:
		// Not ready.
		return false
	default:
		// Ready regardless of whether there was an error or no error.
		return true
	}
}
