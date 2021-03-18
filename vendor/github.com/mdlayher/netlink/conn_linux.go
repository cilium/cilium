//+build linux

package netlink

import (
	"errors"
	"math"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

var _ Socket = &conn{}

var _ deadlineSetter = &conn{}

// A conn is the Linux implementation of a netlink sockets connection.
//
// All conn methods must wrap system call errors with os.NewSyscallError to
// enable more intelligible error messages in OpError.
type conn struct {
	s  socket
	sa *unix.SockaddrNetlink
}

// A socket is an interface over socket system calls.
type socket interface {
	Bind(sa unix.Sockaddr) error
	Close() error
	FD() int
	File() *os.File
	Getsockname() (unix.Sockaddr, error)
	Recvmsg(p, oob []byte, flags int) (n int, oobn int, recvflags int, from unix.Sockaddr, err error)
	Sendmsg(p, oob []byte, to unix.Sockaddr, flags int) error
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
	SetSockoptSockFprog(level, opt int, fprog *unix.SockFprog) error
	SetSockoptInt(level, opt, value int) error
}

// dial is the entry point for Dial.  dial opens a netlink socket using
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

	sock, err := newSysSocket(config)
	if err != nil {
		return nil, 0, err
	}

	if err := sock.Socket(family); err != nil {
		return nil, 0, os.NewSyscallError("socket", err)
	}

	return bind(sock, config)
}

// bind binds a connection to netlink using the input socket, which may be
// a system call implementation or a mocked one for tests.
func bind(s socket, config *Config) (*conn, uint32, error) {
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

	pid := sa.(*unix.SockaddrNetlink).Pid

	return &conn{
		s:  s,
		sa: addr,
	}, pid, nil
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

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
	}

	return os.NewSyscallError("sendmsg", c.s.Sendmsg(buf, nil, addr, 0))
}

// Send sends a single Message to netlink.
func (c *conn) Send(m Message) error {
	b, err := m.MarshalBinary()
	if err != nil {
		return err
	}

	addr := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
	}

	return os.NewSyscallError("sendmsg", c.s.Sendmsg(b, nil, addr, 0))
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

	n = nlmsgAlign(n)

	raw, err := syscall.ParseNetlinkMessage(b[:n])
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

// FD retrieves the file descriptor of the Conn.
func (c *conn) FD() int {
	return c.s.FD()
}

// File retrieves the *os.File associated with the Conn.
func (c *conn) File() *os.File {
	return c.s.File()
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

func (c *conn) SetDeadline(t time.Time) error {
	return c.s.SetDeadline(t)
}

func (c *conn) SetReadDeadline(t time.Time) error {
	return c.s.SetReadDeadline(t)
}

func (c *conn) SetWriteDeadline(t time.Time) error {
	return c.s.SetWriteDeadline(t)
}

// SetReadBuffer sets the size of the operating system's receive buffer
// associated with the Conn.
func (c *conn) SetReadBuffer(bytes int) error {
	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_SOCKET,
		unix.SO_RCVBUF,
		bytes,
	))
}

// SetReadBuffer sets the size of the operating system's transmit buffer
// associated with the Conn.
func (c *conn) SetWriteBuffer(bytes int) error {
	return os.NewSyscallError("setsockopt", c.s.SetSockoptInt(
		unix.SOL_SOCKET,
		unix.SO_SNDBUF,
		bytes,
	))
}

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

var _ socket = &sysSocket{}

// A sysSocket is a socket which uses system calls for socket operations.
type sysSocket struct {
	mu     sync.RWMutex
	fd     *os.File
	closed bool
	g      *lockedNetNSGoroutine
}

// newSysSocket creates a sysSocket that optionally locks its internal goroutine
// to a single thread.
func newSysSocket(config *Config) (*sysSocket, error) {
	// Determine network namespaces using the threadNetNS function.
	g, err := newLockedNetNSGoroutine(config.NetNS, threadNetNS, !config.DisableNSLockThread)
	if err != nil {
		return nil, err
	}
	return &sysSocket{
		g: g,
	}, nil
}

// do runs f in a worker goroutine which can be locked to one thread.
func (s *sysSocket) do(f func()) error {
	// All operations handled by this function are assumed to only
	// read from s.done.
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return syscall.EBADF
	}

	s.g.run(f)
	return nil
}

// read executes f, a read function, against the associated file descriptor.
func (s *sysSocket) read(f func(fd int) bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return syscall.EBADF
	}

	var err error
	s.g.run(func() {
		err = fdread(s.fd, f)
	})
	return err
}

// write executes f, a write function, against the associated file descriptor.
func (s *sysSocket) write(f func(fd int) bool) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return syscall.EBADF
	}

	var err error
	s.g.run(func() {
		err = fdwrite(s.fd, f)
	})
	return err
}

// control executes f, a control function, against the associated file descriptor.
func (s *sysSocket) control(f func(fd int)) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.closed {
		return syscall.EBADF
	}

	var err error
	s.g.run(func() {
		err = fdcontrol(s.fd, f)
	})
	return err
}

func (s *sysSocket) Socket(family int) error {
	var (
		fd  int
		err error
	)

	doErr := s.do(func() {
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
		// SOCK_NONBLOCK was also added in 2.6.27, but we don't
		// use SOCK_NONBLOCK here for now, not until we remove support
		// for Go 1.11, since we still support the old blocking file
		// descriptor behavior.
		//
		// For a more thorough explanation, see similar work in the
		// Go tree: func sysSocket in net/sock_cloexec.go, as well
		// as the detailed comment in syscall/exec_unix.go.
		//
		// TODO(acln): update this to mirror net.sysSocket completely:
		// use SOCK_NONBLOCK as well, and remove the separate
		// setBlockingMode step once Go 1.11 support is removed and
		// we switch to using entirely non-blocking file descriptors.
		fd, err = unix.Socket(
			unix.AF_NETLINK,
			unix.SOCK_RAW|unix.SOCK_CLOEXEC,
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
		}
	})
	if doErr != nil {
		return doErr
	}
	if err != nil {
		return err
	}

	if err := setBlockingMode(fd); err != nil {
		return err
	}

	// When using Go 1.12+, the setBlockingMode call we just did puts the
	// file descriptor into non-blocking mode. In that case, os.NewFile
	// registers the file descriptor with the runtime poller, which is
	// then used for all subsequent operations.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	s.fd = os.NewFile(uintptr(fd), "netlink")
	return nil
}

func (s *sysSocket) Bind(sa unix.Sockaddr) error {
	var err error
	doErr := s.control(func(fd int) {
		err = unix.Bind(fd, sa)
	})
	if doErr != nil {
		return doErr
	}

	return err
}

func (s *sysSocket) Close() error {
	// Be sure to acquire a write lock because we need to stop any other
	// goroutines from sending system call requests after close.
	// Any invocation of do() after this write lock unlocks is guaranteed
	// to find s.done being true.
	s.mu.Lock()
	defer s.mu.Unlock()

	// Close the socket from the main thread, this operation has no risk
	// of routing data to the wrong socket.
	err := s.fd.Close()
	s.closed = true

	// Stop the associated goroutine and wait for it to return.
	s.g.stop()

	return err
}

func (s *sysSocket) FD() int { return int(s.fd.Fd()) }

func (s *sysSocket) File() *os.File { return s.fd }

func (s *sysSocket) Getsockname() (unix.Sockaddr, error) {
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

func (s *sysSocket) Recvmsg(p, oob []byte, flags int) (int, int, int, unix.Sockaddr, error) {
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

func (s *sysSocket) Sendmsg(p, oob []byte, to unix.Sockaddr, flags int) error {
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

func (s *sysSocket) SetDeadline(t time.Time) error {
	return s.fd.SetDeadline(t)
}

func (s *sysSocket) SetReadDeadline(t time.Time) error {
	return s.fd.SetReadDeadline(t)
}

func (s *sysSocket) SetWriteDeadline(t time.Time) error {
	return s.fd.SetWriteDeadline(t)
}

func (s *sysSocket) SetSockoptInt(level, opt, value int) error {
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

func (s *sysSocket) SetSockoptSockFprog(level, opt int, fprog *unix.SockFprog) error {
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

// lockedNetNSGoroutine is a worker goroutine locked to an operating system
// thread, optionally configured to run in a non-default network namespace.
type lockedNetNSGoroutine struct {
	wg    sync.WaitGroup
	doneC chan struct{}
	funcC chan func()
}

// newLockedNetNSGoroutine creates a lockedNetNSGoroutine that will enter the
// specified network namespace netNS (by file descriptor), and will use the
// getNS function to produce netNS handles.
func newLockedNetNSGoroutine(netNS int, getNS func() (*netNS, error), lockThread bool) (*lockedNetNSGoroutine, error) {
	// Any bare syscall errors (e.g. setns) should be wrapped with
	// os.NewSyscallError for the remainder of this function.

	// If the caller has instructed us to not lock OS thread but also attempts
	// to set a namespace, return an error.
	if !lockThread && netNS != 0 {
		return nil, errors.New("netlink Conn attempted to set a namespace with OS thread locking disabled")
	}

	callerNS, err := getNS()
	if err != nil {
		return nil, err
	}
	defer callerNS.Close()

	g := &lockedNetNSGoroutine{
		doneC: make(chan struct{}),
		funcC: make(chan func()),
	}

	errC := make(chan error)
	g.wg.Add(1)

	go func() {
		// It is important to lock this goroutine to its OS thread for the duration
		// of the netlink socket being used, or else the kernel may end up routing
		// messages to the wrong places.
		// See: http://lists.infradead.org/pipermail/libnl/2017-February/002293.html.
		//
		//
		// In addition, the OS thread must also remain locked because we attempt
		// to manipulate the network namespace of the thread within this goroutine.
		//
		// The intent is to never unlock the OS thread, so that the thread
		// will terminate when the goroutine exits starting in Go 1.10:
		// https://go-review.googlesource.com/c/go/+/46038.
		//
		// However, due to recent instability and a potential bad interaction
		// with the Go runtime for threads which are not unlocked, we have
		// elected to temporarily unlock the thread when the goroutine terminates:
		// https://github.com/golang/go/issues/25128#issuecomment-410764489.
		//
		// Locking the thread is not implemented if the caller explicitly asks
		// for an unlocked thread.

		// Only lock the tread, if the lockThread is set.
		if lockThread {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
		}

		defer g.wg.Done()

		// Get the current namespace of the thread the goroutine is locked to.
		threadNS, err := getNS()
		if err != nil {
			errC <- err
			return
		}
		defer threadNS.Close()

		// Attempt to set the network namespace of the current thread to either:
		// - the namespace referred to by the provided file descriptor from config
		// - the calling thread's namespace
		//
		// See the rules specified in the Config.NetNS documentation.
		explicitNS := true
		if netNS == 0 {
			explicitNS = false
			netNS = int(callerNS.FD())
		}

		// Only return an error if the network namespace was explicitly
		// configured; implicit configuration by zero value should be ignored.
		err = threadNS.Set(netNS)
		switch {
		case err != nil && explicitNS:
			errC <- err
			return
		case err == nil:
			// If the thread's namespace has been successfully manipulated,
			// make sure we change it back when the goroutine returns.
			defer threadNS.Restore()
		default:
			// We couldn't successfully set the namespace, but the caller didn't
			// explicitly ask for it to be set either. Continue.
		}

		// Signal to caller that initialization was successful.
		errC <- nil

		for {
			select {
			case <-g.doneC:
				return
			case f := <-g.funcC:
				f()
			}
		}
	}()

	// Wait for the goroutine to return err or nil.
	if err := <-errC; err != nil {
		return nil, err
	}

	return g, nil
}

// stop signals the goroutine to stop and blocks until it does.
//
// It is invalid to call run concurrently with stop. It is also invalid to
// call run after stop has returned.
func (g *lockedNetNSGoroutine) stop() {
	close(g.doneC)
	g.wg.Wait()
}

// run runs f on the worker goroutine.
func (g *lockedNetNSGoroutine) run(f func()) {
	done := make(chan struct{})
	g.funcC <- func() {
		defer close(done)
		f()
	}
	<-done
}
