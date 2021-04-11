// +build linux

package raw

import (
	"net"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// Must implement net.PacketConn at compile-time.
var _ net.PacketConn = &packetConn{}

// packetConn is the Linux-specific implementation of net.PacketConn for this
// package.
type packetConn struct {
	ifi *net.Interface
	s   socket
	pbe uint16

	// Should stats be accumulated instead of reset on each call?
	noCumulativeStats bool

	// Internal storage for cumulative stats.
	stats Stats
}

// socket is an interface which enables swapping out socket syscalls for
// testing.
type socket interface {
	Bind(unix.Sockaddr) error
	Close() error
	GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error)
	Recvfrom([]byte, int) (int, unix.Sockaddr, error)
	Sendto([]byte, int, unix.Sockaddr) error
	SetSockoptPacketMreq(level, name int, mreq *unix.PacketMreq) error
	SetSockoptSockFprog(level, name int, fprog *unix.SockFprog) error
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
}

// htons converts a short (uint16) from host-to-network byte order.
// Thanks to mikioh for this neat trick:
// https://github.com/mikioh/-stdyng/blob/master/afpacket.go
func htons(i uint16) uint16 {
	return (i<<8)&0xff00 | i>>8
}

// listenPacket creates a net.PacketConn which can be used to send and receive
// data at the device driver level.
func listenPacket(ifi *net.Interface, proto uint16, cfg Config) (*packetConn, error) {
	filename := "eth-packet-socket"
	// Enabling overriding the socket type via config.
	typ := unix.SOCK_RAW
	if cfg.LinuxSockDGRAM {
		filename = "packet-socket"
		typ = unix.SOCK_DGRAM
	}

	// Open a packet socket using specified socket type. Do not specify
	// a protocol to avoid capturing packets which to not match cfg.Filter.
	// The later call to bind() will set up the correct protocol for us.
	sock, err := unix.Socket(unix.AF_PACKET, typ, 0)
	if err != nil {
		return nil, err
	}

	if err := unix.SetNonblock(sock, true); err != nil {
		return nil, err
	}

	// When using Go 1.12+, the SetNonblock call we just did puts the file
	// descriptor into non-blocking mode. In that case, os.NewFile
	// registers the file descriptor with the runtime poller, which is then
	// used for all subsequent operations.
	//
	// See also: https://golang.org/pkg/os/#NewFile
	f := os.NewFile(uintptr(sock), filename)
	sc, err := f.SyscallConn()
	if err != nil {
		return nil, err
	}

	// Wrap raw socket in socket interface.
	pc, err := newPacketConn(ifi, &sysSocket{f: f, rc: sc}, htons(proto), cfg.Filter)
	if err != nil {
		return nil, err
	}

	pc.noCumulativeStats = cfg.NoCumulativeStats
	return pc, nil
}

// newPacketConn creates a net.PacketConn using the specified network
// interface, wrapped socket and big endian protocol number.
//
// It is the entry point for tests in this package.
func newPacketConn(ifi *net.Interface, s socket, pbe uint16, filter []bpf.RawInstruction) (*packetConn, error) {
	pc := &packetConn{
		ifi: ifi,
		s:   s,
		pbe: pbe,
	}

	if len(filter) > 0 {
		if err := pc.SetBPF(filter); err != nil {
			return nil, err
		}
	}

	// Bind the packet socket to the interface specified by ifi
	// packet(7):
	//   Only the sll_protocol and the sll_ifindex address fields are used for
	//   purposes of binding.
	// This overrides the protocol given to socket(AF_PACKET).
	err := s.Bind(&unix.SockaddrLinklayer{
		Protocol: pc.pbe,
		Ifindex:  ifi.Index,
	})
	if err != nil {
		return nil, err
	}

	return pc, nil
}

// ReadFrom implements the net.PacketConn.ReadFrom method.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	// Attempt to receive on socket
	n, addr, err := p.s.Recvfrom(b, 0)
	if err != nil {
		return n, nil, err
	}

	// Retrieve hardware address and other information from addr.
	sa, ok := addr.(*unix.SockaddrLinklayer)
	if !ok {
		return n, nil, unix.EINVAL
	}

	// Use length specified to convert byte array into a hardware address slice.
	mac := make(net.HardwareAddr, sa.Halen)
	copy(mac, sa.Addr[:])

	// packet(7):
	//   sll_hatype and sll_pkttype are set on received packets for your
	//   information.
	// TODO(mdlayher): determine if similar fields exist and are useful on
	// non-Linux platforms
	return n, &Addr{
		HardwareAddr: mac,
	}, nil
}

// WriteTo implements the net.PacketConn.WriteTo method.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	// Ensure correct Addr type.
	a, ok := addr.(*Addr)
	if !ok || a.HardwareAddr == nil {
		return 0, unix.EINVAL
	}

	// Convert hardware address back to byte array form.
	var baddr [8]byte
	copy(baddr[:], a.HardwareAddr)

	// Send message on socket to the specified hardware address from addr
	// packet(7):
	//   When you send packets it is enough to specify sll_family, sll_addr,
	//   sll_halen, sll_ifindex, and sll_protocol. The other fields should
	//   be 0.
	// In this case, sll_family is taken care of automatically by unix.
	err := p.s.Sendto(b, 0, &unix.SockaddrLinklayer{
		Ifindex:  p.ifi.Index,
		Halen:    uint8(len(a.HardwareAddr)),
		Addr:     baddr,
		Protocol: p.pbe,
	})
	return len(b), err
}

// Close closes the connection.
func (p *packetConn) Close() error {
	return p.s.Close()
}

// LocalAddr returns the local network address.
func (p *packetConn) LocalAddr() net.Addr {
	return &Addr{
		HardwareAddr: p.ifi.HardwareAddr,
	}
}

// SetDeadline implements the net.PacketConn.SetDeadline method.
func (p *packetConn) SetDeadline(t time.Time) error {
	return p.s.SetDeadline(t)
}

// SetReadDeadline implements the net.PacketConn.SetReadDeadline method.
func (p *packetConn) SetReadDeadline(t time.Time) error {
	return p.s.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.PacketConn.SetWriteDeadline method.
func (p *packetConn) SetWriteDeadline(t time.Time) error {
	return p.s.SetWriteDeadline(t)
}

// SetBPF attaches an assembled BPF program to a raw net.PacketConn.
func (p *packetConn) SetBPF(filter []bpf.RawInstruction) error {
	prog := unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: (*unix.SockFilter)(unsafe.Pointer(&filter[0])),
	}

	err := p.s.SetSockoptSockFprog(
		unix.SOL_SOCKET,
		unix.SO_ATTACH_FILTER,
		&prog,
	)
	if err != nil {
		return os.NewSyscallError("setsockopt", err)
	}
	return nil
}

// SetPromiscuous enables or disables promiscuous mode on the interface, allowing it
// to receive traffic that is not addressed to the interface.
func (p *packetConn) SetPromiscuous(b bool) error {
	mreq := unix.PacketMreq{
		Ifindex: int32(p.ifi.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	membership := unix.PACKET_ADD_MEMBERSHIP
	if !b {
		membership = unix.PACKET_DROP_MEMBERSHIP
	}

	return p.s.SetSockoptPacketMreq(unix.SOL_PACKET, membership, &mreq)
}

// Stats retrieves statistics from the Conn.
func (p *packetConn) Stats() (*Stats, error) {
	stats, err := p.s.GetSockoptTpacketStats(unix.SOL_PACKET, unix.PACKET_STATISTICS)
	if err != nil {
		return nil, err
	}

	return p.handleStats(stats), nil
}

// handleStats handles creation of Stats structures from raw packet socket stats.
func (p *packetConn) handleStats(s *unix.TpacketStats) *Stats {
	// Does the caller want instantaneous stats as provided by Linux?  If so,
	// return the structure directly.
	if p.noCumulativeStats {
		return &Stats{
			Packets: uint64(s.Packets),
			Drops:   uint64(s.Drops),
		}
	}

	// The caller wants cumulative stats.  Add stats with the internal stats
	// structure and return a copy of the resulting stats.
	packets := atomic.AddUint64(&p.stats.Packets, uint64(s.Packets))
	drops := atomic.AddUint64(&p.stats.Drops, uint64(s.Drops))

	return &Stats{
		Packets: packets,
		Drops:   drops,
	}
}

// sysSocket is the default socket implementation.  It makes use of
// Linux-specific system calls to handle raw socket functionality.
type sysSocket struct {
	f  *os.File
	rc syscall.RawConn
}

func (s *sysSocket) SetDeadline(t time.Time) error {
	return s.f.SetDeadline(t)
}

func (s *sysSocket) SetReadDeadline(t time.Time) error {
	return s.f.SetReadDeadline(t)
}

func (s *sysSocket) SetWriteDeadline(t time.Time) error {
	return s.f.SetWriteDeadline(t)
}

func (s *sysSocket) Bind(sa unix.Sockaddr) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		err = unix.Bind(int(fd), sa)
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) Close() error {
	return s.f.Close()
}

func (s *sysSocket) GetSockoptTpacketStats(level, name int) (*unix.TpacketStats, error) {
	var stats *unix.TpacketStats
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		s, errno := unix.GetsockoptTpacketStats(int(fd), level, name)
		stats = s
		if errno != nil {
			err = os.NewSyscallError("getsockopt", errno)
		}
	})
	if err != nil {
		return stats, err
	}
	return stats, cerr
}

func (s *sysSocket) Recvfrom(p []byte, flags int) (n int, addr unix.Sockaddr, err error) {
	cerr := s.rc.Read(func(fd uintptr) bool {
		n, addr, err = unix.Recvfrom(int(fd), p, flags)
		// When the socket is in non-blocking mode, we might see EAGAIN
		// and end up here. In that case, return false to let the
		// poller wait for readiness. See the source code for
		// internal/poll.FD.RawRead for more details.
		//
		// If the socket is in blocking mode, EAGAIN should never occur.
		return err != unix.EAGAIN
	})
	if err != nil {
		return n, addr, err
	}
	return n, addr, cerr
}

func (s *sysSocket) Sendto(p []byte, flags int, to unix.Sockaddr) error {
	var err error
	cerr := s.rc.Write(func(fd uintptr) bool {
		err = unix.Sendto(int(fd), p, flags, to)
		// See comment in Recvfrom.
		return err != unix.EAGAIN
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) SetSockoptSockFprog(level, name int, fprog *unix.SockFprog) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		errno := unix.SetsockoptSockFprog(int(fd), level, name, fprog)
		if errno != nil {
			err = os.NewSyscallError("setsockopt", errno)
		}
	})
	if err != nil {
		return err
	}
	return cerr
}

func (s *sysSocket) SetSockoptPacketMreq(level, name int, mreq *unix.PacketMreq) error {
	var err error
	cerr := s.rc.Control(func(fd uintptr) {
		errno := unix.SetsockoptPacketMreq(int(fd), level, name, mreq)
		if errno != nil {
			err = os.NewSyscallError("setsockopt", errno)
		}
	})
	if err != nil {
		return err
	}
	return cerr
}
