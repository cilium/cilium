package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/cilium/dns"
)

// This is the required size of the OOB buffer to pass to ReadMsgUDP.
var udpOOBSize = func() int {
	var hdr syscall.Cmsghdr
	var addr unix.RawSockaddrInet6
	return int(unsafe.Sizeof(hdr) + unsafe.Sizeof(addr))
}()

// sessionUDP implements the dns.SessionUDP, holding the remote address and the associated
// out-of-band data.
type sessionUDP struct {
	conn  *net.UDPConn // UDP socket for receiving both IPv4 and IPv6
	raddr *net.UDPAddr
	laddr *net.UDPAddr
	m     []byte
	oob   []byte
}

type sessionUDPFactory struct{}

var ciliumSessionUDPFactory *sessionUDPFactory

var rawconn4 *net.IPConn // raw socket for sending IPv4
var rawconn6 *net.IPConn // raw socket for sending IPv6

// Set the socket options needed for tranparent proxying for the listening socket
// IP(V6)_TRANSPARENT allows socket to receive packets with any destination address/port
// IP(V6)_RECVORIGDSTADDR tells the kernel to pass the original destination address/port on recvmsg
// The socket may be receiving both IPv4 and IPv6 data, so set both options, if possible.
func transparentSetsockopt(fd int) error {
	err6 := unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
	if err6 == nil {
		err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
	}
	err4 := unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
	if err4 == nil {
		err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
	}
	// Only error out if both IPv4 and IPv6 fail
	if err4 != nil && err6 != nil {
		return err4
	}
	return nil
}

func listenConfig() *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = transparentSetsockopt(int(fd))
			})
			if err != nil {
				return err
			}

			return opErr
		}}
}

func listenPacket(network, addr string) *net.IPConn {
	conn, err := listenConfig().ListenPacket(context.Background(), network, addr)
	if err != nil {
		log.Printf("ListenPacket failed on address %s for %s: %s", addr, network, err)
		return nil
	}
	return conn.(*net.IPConn)
}

func (f *sessionUDPFactory) CreateSessionUDP(msgSize int) dns.SessionUDP {
	return &sessionUDP{
		m:   make([]byte, msgSize),
		oob: make([]byte, udpOOBSize),
	}
}

var udpOnce sync.Once

func (s *sessionUDPFactory) InitConn(conn *net.UDPConn) error {
	// Set up the raw socket for sending responses.
	// - Must use a raw UDP socket for sending responses so that we can send
	//   from a specific port without binding to it.
	// - The raw UDP socket must be bound to a specific IP address to prevent
	//   it receiving ALL UDP packets on the host.
	// - We use oob data to override the source IP address when sending
	// - Must use separate sockets for IPv4/IPv6, as sending to a v6-mapped
	//   v4 address from a socket bound to "::1" does not work due to kernel
	//   checking that a route exists from the source address before
	//   the source address is replaced with the (transparently) changed one
	udpOnce.Do(func() {
		rawconn4 = listenPacket("ip:udp", "127.0.0.1") // raw socket for sending IPv4
		rawconn6 = listenPacket("ip:udp", "::1")       // raw socket for sending IPv6
	})

	UDPFile, err := conn.File()
	if err != nil {
		return err
	}
	err = transparentSetsockopt(int(UDPFile.Fd()))
	return err
}

// Clear re-initializes sessionUDP to the same state it was when new.
// Returns the interface for convenience.
// This is required for pooling of dns.SessionUDP objects.
func (s *sessionUDP) Clear() dns.SessionUDP {
	s.conn = nil
	s.raddr = nil
	s.laddr = nil
	s.m = s.m[:cap(s.m)]
	s.oob = s.oob[:cap(s.oob)]
	return s
}

// RemoteAddr returns the remote network address.
func (s *sessionUDP) RemoteAddr() net.Addr { return s.raddr }

// LocalAddr returns the local network address for the current request.
func (s *sessionUDP) LocalAddr() net.Addr { return s.laddr }

// ReadRequest reads a single request from the session and keeps the request context
func (s *sessionUDP) ReadRequest(conn *net.UDPConn) ([]byte, error) {
	n, oobn, _, raddr, err := conn.ReadMsgUDP(s.m, s.oob)
	if err == nil {
		s.conn = conn
		s.raddr = raddr
		s.m = s.m[:n]        // Re-slice to the actual size
		s.oob = s.oob[:oobn] // Re-slice to the actual size
		s.laddr, err = parseDstFromOOB(s.oob)
	}
	return s.m, err
}

// WriteResponse writes a response to a request received earlier
func (s *sessionUDP) WriteResponse(b []byte) (int, error) {
	// Must give the UDP header to get the source port right.
	// Reuse the msg buffer, figure out if golang can do gatter-scather IO
	// with raw sockets?
	bb := bytes.NewBuffer(s.m[:0])
	binary.Write(bb, binary.BigEndian, uint16(s.laddr.Port))
	binary.Write(bb, binary.BigEndian, uint16(s.raddr.Port))
	binary.Write(bb, binary.BigEndian, uint16(8+len(b)))
	binary.Write(bb, binary.BigEndian, uint16(0)) // checksum
	bb.Write(b)
	buf := bb.Bytes()

	var n int
	var err error
	dst := net.IPAddr{
		IP: s.raddr.IP,
	}
	if s.raddr.IP.To4() == nil {
		n, _, err = rawconn6.WriteMsgIP(buf, s.controlMessage(s.laddr), &dst)
	} else {
		n, _, err = rawconn4.WriteMsgIP(buf, s.controlMessage(s.laddr), &dst)
	}
	if err != nil {
		log.Fatalf("WriteMsgIP: %s", err)
	}
	log.Printf("WriteMsgIP: wrote %d bytes", n)

	return n, err
}

// parseDstFromOOB takes oob data and returns the destination IP.
func parseDstFromOOB(oob []byte) (*net.UDPAddr, error) {
	msgs, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parsing socket control message: %s", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_ORIGDSTADDR {
			pp := &syscall.RawSockaddrInet4{}
			// Address family is in native byte order
			family := *(*uint16)(unsafe.Pointer(&msg.Data[unsafe.Offsetof(pp.Family)]))
			if family != unix.AF_INET {
				return nil, fmt.Errorf("original destination is not IP.")
			}
			// Port is in big-endian byte order
			if err = binary.Read(bytes.NewReader(msg.Data), binary.BigEndian, pp); err != nil {
				return nil, fmt.Errorf("reading original destination address: %s", err)
			}
			laddr := &net.UDPAddr{
				IP:   net.IPv4(pp.Addr[0], pp.Addr[1], pp.Addr[2], pp.Addr[3]),
				Port: int(pp.Port),
			}
			return laddr, nil
		}
		if msg.Header.Level == unix.SOL_IPV6 && msg.Header.Type == unix.IPV6_ORIGDSTADDR {
			pp := &syscall.RawSockaddrInet6{}
			// Address family is in native byte order
			family := *(*uint16)(unsafe.Pointer(&msg.Data[unsafe.Offsetof(pp.Family)]))
			if family != unix.AF_INET6 {
				return nil, fmt.Errorf("original destination is not IPV6.")
			}
			// Scope ID is in native byte order
			scopeId := *(*uint32)(unsafe.Pointer(&msg.Data[unsafe.Offsetof(pp.Scope_id)]))
			// Rest of the data is big-endian (port)
			if err = binary.Read(bytes.NewReader(msg.Data), binary.BigEndian, pp); err != nil {
				return nil, fmt.Errorf("reading original destination address: %s", err)
			}
			laddr := &net.UDPAddr{
				IP:   net.IP(pp.Addr[:]),
				Port: int(pp.Port),
				Zone: strconv.Itoa(int(scopeId)),
			}
			return laddr, nil
		}
	}
	return nil, fmt.Errorf("No original destination found!")
}

// correctSource returns the oob data with the given source address
func (s *sessionUDP) controlMessage(src *net.UDPAddr) []byte {
	// If the src is definitely an IPv6, then use ipv6's ControlMessage to
	// respond otherwise use ipv4's because ipv6's marshal ignores ipv4
	// addresses.
	if src.IP.To4() == nil {
		cm := new(ipv6.ControlMessage)
		cm.Src = src.IP
		return cm.Marshal()
	}
	cm := new(ipv4.ControlMessage)
	cm.Src = src.IP
	return cm.Marshal()
}
