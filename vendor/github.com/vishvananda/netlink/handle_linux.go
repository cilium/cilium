package netlink

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Empty handle used by the netlink package methods
var pkgHandle = &Handle{}

var configMu sync.Mutex
var configDone bool

// ConfigureHandle configures the default, package-wide netlink handle used by
// the netlink package's global functions like [LinkList] and [AddrList] with
// the given opts. It does not affect any existing or future [Handle] returned
// by the library.
//
// This function is not safe to call concurrently with any netlink operations
// using the global package handle. Invoke it from init() functions only.
//
// Returns an error if called more than once per process.
func ConfigureHandle(opts HandleOptions) error {
	configMu.Lock()
	defer configMu.Unlock()

	if configDone {
		return fmt.Errorf("netlink package handle already configured")
	}

	h, err := NewHandleWithOptions(opts)
	if err != nil {
		return fmt.Errorf("creating handle: %w", err)
	}

	configDone = true
	pkgHandle = h

	return nil
}

// HandleOptions defines the options for creating a netlink Handle, allowing the
// caller to customize its behaviour.
type HandleOptions struct {
	// DisableVFInfoCollection controls whether to fetch VF information for each
	// link. This is an expensive operation and should be disabled if the caller
	// does not need the VF information.
	DisableVFInfoCollection bool

	// RetryInterrupted controls whether to automatically retry dump operations a
	// number of times if they fail with EINTR before finally returning
	// [ErrDumpInterrupted].
	RetryInterrupted bool

	// NetNS specifies the network namespace to operate on. If not set, the
	// current network namespace will be used.
	NetNS *netns.NsHandle
}

// Handle is a handle for the netlink requests on a
// specific network namespace. All the requests on the
// same netlink family share the same netlink socket,
// which gets released when the handle is Close'd.
type Handle struct {
	sockets map[int]*nl.SocketHandle
	options HandleOptions

	lookupByDump atomic.Bool
}

// DisableVFInfoCollection configures the handle to skip VF information fetching
//
// Deprecated: Use [NewHandleWithOptions] and set
// [HandleOptions.DisableVFInfoCollection] instead.
func (h *Handle) DisableVFInfoCollection() *Handle {
	h.options.DisableVFInfoCollection = true
	return h
}

// SetSocketTimeout configures timeout for default netlink sockets
func SetSocketTimeout(to time.Duration) error {
	if to < time.Microsecond {
		return fmt.Errorf("invalid timeout, minimul value is %s", time.Microsecond)
	}

	nl.SocketTimeoutTv = unix.NsecToTimeval(to.Nanoseconds())
	return nil
}

// GetSocketTimeout returns the timeout value used by default netlink sockets
func GetSocketTimeout() time.Duration {
	nsec := unix.TimevalToNsec(nl.SocketTimeoutTv)
	return time.Duration(nsec) * time.Nanosecond
}

// SupportsNetlinkFamily reports whether the passed netlink family is supported by this Handle
func (h *Handle) SupportsNetlinkFamily(nlFamily int) bool {
	_, ok := h.sockets[nlFamily]
	return ok
}

// NewHandle returns a netlink handle on the current network namespace.
// Caller may specify the netlink families the handle should support.
// If no families are specified, all the families the netlink package
// supports will be automatically added.
func NewHandle(nlFamilies ...int) (*Handle, error) {
	none := netns.None()
	return newHandle(none, HandleOptions{NetNS: &none}, nlFamilies...)
}

// SetSocketTimeout sets the send and receive timeout for each socket in the
// netlink handle. Although the socket timeout has granularity of one
// microsecond, the effective granularity is floored by the kernel timer tick,
// which default value is four milliseconds.
func (h *Handle) SetSocketTimeout(to time.Duration) error {
	if to < time.Microsecond {
		return fmt.Errorf("invalid timeout, minimul value is %s", time.Microsecond)
	}
	tv := unix.NsecToTimeval(to.Nanoseconds())
	for _, sh := range h.sockets {
		if err := sh.Socket.SetSendTimeout(&tv); err != nil {
			return err
		}
		if err := sh.Socket.SetReceiveTimeout(&tv); err != nil {
			return err
		}
	}
	return nil
}

// SetSocketReceiveBufferSize sets the receive buffer size for each
// socket in the netlink handle. The maximum value is capped by
// /proc/sys/net/core/rmem_max.
func (h *Handle) SetSocketReceiveBufferSize(size int, force bool) error {
	opt := unix.SO_RCVBUF
	if force {
		opt = unix.SO_RCVBUFFORCE
	}
	for _, sh := range h.sockets {
		fd := sh.Socket.GetFd()
		err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, opt, size)
		if err != nil {
			return err
		}
	}
	return nil
}

// GetSocketReceiveBufferSize gets the receiver buffer size for each
// socket in the netlink handle. The retrieved value should be the
// double to the one set for SetSocketReceiveBufferSize.
func (h *Handle) GetSocketReceiveBufferSize() ([]int, error) {
	results := make([]int, len(h.sockets))
	i := 0
	for _, sh := range h.sockets {
		fd := sh.Socket.GetFd()
		size, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
		if err != nil {
			return nil, err
		}
		results[i] = size
		i++
	}
	return results, nil
}

// SetStrictCheck sets the strict check socket option for each socket in the netlink handle. Returns early if any set operation fails
func (h *Handle) SetStrictCheck(state bool) error {
	for _, sh := range h.sockets {
		var stateInt int = 0
		if state {
			stateInt = 1
		}
		err := unix.SetsockoptInt(sh.Socket.GetFd(), unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, stateInt)
		if err != nil {
			return err
		}
	}
	return nil
}

// NewHandleAt returns a netlink handle on the network namespace
// specified by ns. If ns=netns.None(), current network namespace
// will be assumed
func NewHandleAt(ns netns.NsHandle, nlFamilies ...int) (*Handle, error) {
	return newHandle(netns.None(), HandleOptions{NetNS: &ns}, nlFamilies...)
}

// NewHandleAtFrom works as NewHandle but allows client to specify the
// new and the origin netns Handle.
func NewHandleAtFrom(newNs, curNs netns.NsHandle) (*Handle, error) {
	return newHandle(curNs, HandleOptions{NetNS: &newNs})
}

// NewHandleWithOptions returns a Handle created using the specified options.
func NewHandleWithOptions(opts HandleOptions, nlFamilies ...int) (*Handle, error) {
	return newHandle(netns.None(), opts, nlFamilies...)
}

func newHandle(curNs netns.NsHandle, opts HandleOptions, nlFamilies ...int) (*Handle, error) {
	h := &Handle{
		sockets: map[int]*nl.SocketHandle{},
		options: opts,
	}
	fams := nl.SupportedNlFamilies
	if len(nlFamilies) != 0 {
		fams = nlFamilies
	}

	newNs := netns.None()
	if opts.NetNS != nil {
		newNs = *opts.NetNS
	}

	for _, f := range fams {
		s, err := nl.GetNetlinkSocketAt(newNs, curNs, f)
		if err != nil {
			return nil, err
		}
		h.sockets[f] = &nl.SocketHandle{Socket: s}
	}
	return h, nil
}

// Close closes all netlink sockets held by this Handle.
func (h *Handle) Close() error {
	var firstErr error
	for _, sh := range h.sockets {
		if err := sh.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	h.sockets = nil
	return firstErr
}

// Delete releases the resources allocated to this handle
//
// Deprecated: use Close instead which is in line with typical resource release
// patterns for files and other resources.
func (h *Handle) Delete() {
	_ = h.Close()
}

func (h *Handle) newNetlinkRequest(proto, flags int) *nl.NetlinkRequest {
	// Do this so that package API still use nl package variable nextSeqNr
	if h.sockets == nil {
		return nl.NewNetlinkRequest(proto, flags)
	}
	return &nl.NetlinkRequest{
		NlMsghdr: unix.NlMsghdr{
			Len:   uint32(unix.SizeofNlMsghdr),
			Type:  uint16(proto),
			Flags: unix.NLM_F_REQUEST | uint16(flags),
		},
		Sockets: h.sockets,

		RetryInterrupted: h.options.RetryInterrupted,
	}
}
