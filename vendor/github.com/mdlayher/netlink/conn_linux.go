//+build linux

package netlink

import (
	"math"
	"os"
	"runtime"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var _ Socket = &conn{}

// A conn is the Linux implementation of a netlink sockets connection.
//
// All conn methods must wrap system call errors with os.NewSyscallError to
// enable more intelligible error messages in OpError.
type conn struct {
	s *socket
}

// dial is the entry point for Dial. dial opens a netlink socket using
// system calls, and returns its PID.
func dial(family int, config *Config) (*conn, uint32, error) {
	// Prepare sysSocket's internal loop and create the socket.
	//
	// The conditional is inverted because a zero value of false is desired
	// if no config, but it's easier to interpret within this code when the
	// value is inverted.
	if config == nil {
		config = &Config{}
	}

	// The caller has indicated it wants the netlink socket to be created
	// inside another network namespace.
	if config.NetNS != 0 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		// Retrieve and store the calling OS thread's network namespace so
		// the thread can be reassigned to it after creating a socket in another
		// network namespace.
		threadNS, err := threadNetNS()
		if err != nil {
			return nil, 0, err
		}
		// Always close the netns handle created above.
		defer threadNS.Close()

		// Assign the current OS thread the goroutine is locked to to the given
		// network namespace.
		if err := threadNS.Set(config.NetNS); err != nil {
			return nil, 0, err
		}

		// Thread's namespace has been successfully set. Return the thread
		// back to its original namespace after attempting to create the
		// netlink socket.
		defer threadNS.Restore()
	}

	// Socket will establish the internal state of the socket structure.
	s, err := newSocket(family)
	if err != nil {
		return nil, 0, os.NewSyscallError("socket", err)
	}

	return newConn(s, config)
}

// newConn binds a connection to netlink using the input socket.
func newConn(s *socket, config *Config) (*conn, uint32, error) {
	if config == nil {
		config = &Config{}
	}

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: config.Groups,
	}

	// Socket must be closed in the event of any system call errors, to avoid
	// leaking file descriptors.

	if err := s.Bind(addr); err != nil {
		_ = s.Close()
		return nil, 0, os.NewSyscallError("bind", err)
	}

	sa, err := s.Getsockname()
	if err != nil {
		_ = s.Close()
		return nil, 0, os.NewSyscallError("getsockname", err)
	}

	return &conn{
		s: s,
	}, sa.(*unix.SockaddrNetlink).Pid, nil
}

// SendMessages serializes multiple Messages and sends them to netlink.
func (c *conn) SendMessages(messages []Message) error {
	var buf []byte
	for _, m := range messages {
		b, err := m.MarshalBinary()
		if err != nil {
			return err
		}

		buf = append(buf, b...)
	}

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return os.NewSyscallError("sendmsg", c.s.Sendmsg(buf, nil, sa, 0))
}

// Send sends a single Message to netlink.
func (c *conn) Send(m Message) error {
	b, err := m.MarshalBinary()
	if err != nil {
		return err
	}

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	return os.NewSyscallError("sendmsg", c.s.Sendmsg(b, nil, sa, 0))
}

// Receive receives one or more Messages from netlink.
func (c *conn) Receive() ([]Message, error) {
	b := make([]byte, os.Getpagesize())
	for {
		// Peek at the buffer to see how many bytes are available.
		//
		// TODO(mdlayher): deal with OOB message data if available, such as
		// when PacketInfo ConnOption is true.
		n, _, _, _, err := c.s.Recvmsg(b, nil, unix.MSG_PEEK)
		if err != nil {
			return nil, os.NewSyscallError("recvmsg", err)
		}

		// Break when we can read all messages
		if n < len(b) {
			break
		}

		// Double in size if not enough bytes
		b = make([]byte, len(b)*2)
	}

	// Read out all available messages
	n, _, _, _, err := c.s.Recvmsg(b, nil, 0)
	if err != nil {
		return nil, os.NewSyscallError("recvmsg", err)
	}

	raw, err := syscall.ParseNetlinkMessage(b[:nlmsgAlign(n)])
	if err != nil {
		return nil, err
	}

	msgs := make([]Message, 0, len(raw))
	for _, r := range raw {
		m := Message{
			Header: sysToHeader(r.Header),
			Data:   r.Data,
		}

		msgs = append(msgs, m)
	}

	return msgs, nil
}

// Close closes the connection.
func (c *conn) Close() error {
	return os.NewSyscallError("close", c.s.Close())
}

// JoinGroup joins a multicast group by ID.
func (c *conn) JoinGroup(group uint32) error {
	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_NETLINK,
		unix.NETLINK_ADD_MEMBERSHIP,
		int(group),
	))
}

// LeaveGroup leaves a multicast group by ID.
func (c *conn) LeaveGroup(group uint32) error {
	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_NETLINK,
		unix.NETLINK_DROP_MEMBERSHIP,
		int(group),
	))
}

// SetBPF attaches an assembled BPF program to a conn.
func (c *conn) SetBPF(filter []bpf.RawInstruction) error {
	// We can't point to the first instruction in the array if no instructions
	// are present.
	if len(filter) == 0 {
		return os.NewSyscallError("setsockopt", unix.EINVAL)
	}

	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	return os.NewSyscallError("setsockopt", c.s.SetSockoptSockFprog(
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		&prog,
	))
}

// RemoveBPF removes a BPF filter from a conn.
func (c *conn) RemoveBPF() error {
	// 0 argument is ignored by SO_DETACH_FILTER.
	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_SOCKET,
		unix.SO_DETACH_FILTER,
		0,
	))
}

// SetOption enables or disables a netlink socket option for the Conn.
func (c *conn) SetOption(option ConnOption, enable bool) error {
	o, ok := linuxOption(option)
	if !ok {
		// Return the typical Linux error for an unknown ConnOption.
		return os.NewSyscallError("setsockopt", unix.ENOPROTOOPT)
	}

	var v int
	if enable {
		v = 1
	}

	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_NETLINK,
		o,
		v,
	))
}

func (c *conn) SetDeadline(t time.Time) error      { return c.s.SetDeadline(t) }
func (c *conn) SetReadDeadline(t time.Time) error  { return c.s.SetReadDeadline(t) }
func (c *conn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
func (c *conn) SetReadBuffer(bytes int) error {
	// First try SO_RCVBUFFORCE. Given necessary permissions this syscall
	// ignores limits. Fall back to the non-force version.
	err := os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_SOCKET,
		unix.SO_RCVBUFFORCE,
		bytes,
	))
	if err != nil {
		err = os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
			unix.SOL_SOCKET,
			unix.SO_RCVBUF,
			bytes,
		))
	}
	return err
}

// SetReadBuffer sets the size of the operating system's transmit buffer
// associated with the Conn.
func (c *conn) SetWriteBuffer(bytes int) error {
	// First try SO_SNDBUFFORCE. Given necessary permissions this syscall
	// ignores limits. Fall back to the non-force version.
	err := os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_SOCKET,
		unix.SO_SNDBUFFORCE,
		bytes,
	))
	if err != nil {
		err = os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
			unix.SOL_SOCKET,
			unix.SO_SNDBUF,
			bytes,
		))
	}
	return err
}

func (c *conn) SyscallConn() (syscall.RawConn, error) { return c.s.SyscallConn() }

// linuxOption converts a ConnOption to its Linux value.
func linuxOption(o ConnOption) (int, bool) {
	switch o {
	case PacketInfo:
		return unix.NETLINK_PKTINFO, true
	case BroadcastError:
		return unix.NETLINK_BROADCAST_ERROR, true
	case NoENOBUFS:
		return unix.NETLINK_NO_ENOBUFS, true
	case ListenAllNSID:
		return unix.NETLINK_LISTEN_ALL_NSID, true
	case CapAcknowledge:
		return unix.NETLINK_CAP_ACK, true
	case ExtendedAcknowledge:
		return unix.NETLINK_EXT_ACK, true
	case GetStrictCheck:
		return unix.NETLINK_GET_STRICT_CHK, true
	default:
		return 0, false
	}
}

// sysToHeader converts a syscall.NlMsghdr to a Header.
func sysToHeader(r syscall.NlMsghdr) Header {
	// NB: the memory layout of Header and syscall.NlMsgHdr must be
	// exactly the same for this unsafe cast to work
	return *(*Header)(unsafe.Pointer(&r))
}

// newError converts an error number from netlink into the appropriate
// system call error for Linux.
func newError(errno int) error {
	return syscall.Errno(errno)
}

// A socket wraps system call operations.
type socket struct {
	// Atomics must come first.
	closed uint32

	fd *os.File
	rc syscall.RawConn
}

// read executes f, a read function, against the associated file descriptor.
func (s *socket) read(f func(fd int) bool) error {
	if atomic.LoadUint32(&s.closed) != 0 {
		return syscall.EBADF
	}

	return s.rc.Read(func(sysfd uintptr) bool {
		return f(int(sysfd))
	})
}

// write executes f, a write function, against the associated file descriptor.
func (s *socket) write(f func(fd int) bool) error {
	if atomic.LoadUint32(&s.closed) != 0 {
		return syscall.EBADF
	}

	return s.rc.Write(func(sysfd uintptr) bool {
		return f(int(sysfd))
	})
}

// control executes f, a control function, against the associated file descriptor.
func (s *socket) control(f func(fd int)) error {
	if atomic.LoadUint32(&s.closed) != 0 {
		return syscall.EBADF
	}

	return s.rc.Control(func(sysfd uintptr) {
		f(int(sysfd))
	})
}

func (s *socket) SyscallConn() (syscall.RawConn, error) {
	if atomic.LoadUint32(&s.closed) != 0 {
		return nil, syscall.EBADF
	}

	return s.rc, nil
}

func newSocket(family int) (*socket, error) {
	// Mirror what the standard library does when creating file
	// descriptors: avoid racing a fork/exec with the creation
	// of new file descriptors, so that child processes do not
	// inherit netlink socket file descriptors unexpectedly.
	//
	// On Linux, SOCK_CLOEXEC was introduced in 2.6.27. OTOH,
	// Go supports Linux 2.6.23 and above. If we get EINVAL on
	// the first try, it may be that we are running on a kernel
	// older than 2.6.27. In that case, take syscall.ForkLock
	// and try again without SOCK_CLOEXEC.
	//
	// For a more thorough explanation, see similar work in the
	// Go tree: func sysSocket in net/sock_cloexec.go, as well
	// as the detailed comment in syscall/exec_unix.go.
	fd, err := unix.Socket(
		unix.AF_NETLINK,
		unix.SOCK_RAW|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC,
		family,
	)
	if err == unix.EINVAL {
		syscall.ForkLock.RLock()
		fd, err = unix.Socket(
			unix.AF_NETLINK,
			unix.SOCK_RAW,
			family,
		)
		if err == nil {
			unix.CloseOnExec(fd)
		}
		syscall.ForkLock.RUnlock()

		if err := unix.SetNonblock(fd, true); err != nil {
			return nil, err
		}
	}

	// os.NewFile registers the file descriptor with the runtime poller, which
	// is then used for most subsequent operations except those that require
	// raw I/O via SyscallConn.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(fd), "netlink")
	rc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	return &socket{
		fd: f,
		rc: rc,
	}, nil
}

func (s *socket) Bind(sa unix.Sockaddr) error {
	var err error
	doErr := s.control(func(fd int) {
		err = unix.Bind(fd, sa)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *socket) Close() error {
	// The caller has expressed an intent to close the socket, so immediately
	// increment s.closed to force further calls to result in EBADF before also
	// closing the file descriptor to unblock any outstanding operations.
	//
	// Because other operations simply check for s.closed != 0, we will permit
	// double Close, which would increment s.closed beyond 1.
	if atomic.AddUint32(&s.closed, 1) != 1 {
		// Multiple Close calls.
		return nil
	}

	return s.fd.Close()
}

func (s *socket) Getsockname() (unix.Sockaddr, error) {
	var (
		sa  unix.Sockaddr
		err error
	)

	doErr := s.control(func(fd int) {
		sa, err = unix.Getsockname(fd)
	})
	if doErr != nil {
		return nil, doErr
	}

	return sa, err
}

func (s *socket) Recvmsg(p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
	var (
		n, oobn, recvflags int
		from               unix.Sockaddr
		err                error
	)

	doErr := s.read(func(fd int) bool {
		n, oobn, recvflags, from, err = unix.Recvmsg(fd, p, oob, flags)

		// Check for readiness.
		return ready(err)
	})
	if doErr != nil {
		return 0, 0, 0, nil, doErr
	}

	return n, oobn, recvflags, from, err
}

func (s *socket) Sendmsg(p, oob []byte, to unix.Sockaddr, flags int) error {
	var err error
	doErr := s.write(func(fd int) bool {
		err = unix.Sendmsg(fd, p, oob, to, flags)

		// Check for readiness.
		return ready(err)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *socket) SetDeadline(t time.Time) error      { return s.fd.SetDeadline(t) }
func (s *socket) SetReadDeadline(t time.Time) error  { return s.fd.SetReadDeadline(t) }
func (s *socket) SetWriteDeadline(t time.Time) error { return s.fd.SetWriteDeadline(t) }

func (s *socket) SetSockoptInt(level, opt, value int) error {
	// Value must be in range of a C integer.
	if value < math.MinInt32 || value > math.MaxInt32 {
		return unix.EINVAL
	}

	var err error
	doErr := s.control(func(fd int) {
		err = unix.SetsockoptInt(fd, level, opt, value)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *socket) SetSockoptSockFprog(level, opt int, fprog *unix.SockFprog) error {
	var err error
	doErr := s.control(func(fd int) {
		err = unix.SetsockoptSockFprog(fd, level, opt, fprog)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

// ready indicates readiness based on the value of err.
func ready(err error) bool {
	// When a socket is in non-blocking mode, we might see
	// EAGAIN. In that case, return false to let the poller wait for readiness.
	// See the source code for internal/poll.FD.RawRead for more details.
	//
	// Starting in Go 1.14, goroutines are asynchronously preemptible. The 1.14
	// release notes indicate that applications should expect to see EINTR more
	// often on slow system calls (like recvmsg while waiting for input), so
	// we must handle that case as well.
	//
	// If the socket is in blocking mode, EAGAIN should never occur.
	switch err {
	case syscall.EAGAIN, syscall.EINTR:
		// Not ready.
		return false
	default:
		// Ready whether there was error or no error.
		return true
	}
}
