// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package dnsproxy

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/dns"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/datapath/linux/linux_defaults"
	"github.com/cilium/cilium/pkg/fqdn/proxy/ipfamily"
	"github.com/cilium/cilium/pkg/option"
)

// This is the required size of the OOB buffer to pass to ReadMsgUDP.
var udpOOBSize = func() int {
	var hdr unix.Cmsghdr
	var addr unix.RawSockaddrInet6
	return int(unsafe.Sizeof(hdr) + unsafe.Sizeof(addr))
}()

// Set up new SessionUDPFactory with dedicated raw socket for sending responses.
//   - Must use a raw UDP socket for sending responses so that we can send
//     from a specific port without binding to it.
//   - The raw UDP socket must be bound to a specific IP address to prevent
//     it receiving ALL UDP packets on the host.
//   - We use oob data to override the source IP address when sending
//   - Must use separate sockets for IPv4/IPv6, as sending to a v6-mapped
//     v4 address from a socket bound to "::1" does not work due to kernel
//     checking that a route exists from the source address before
//     the source address is replaced with the (transparently) changed one
func NewSessionUDPFactory(ipFamily ipfamily.IPFamily) (dns.SessionUDPFactory, error) {
	rawResponseConn, err := bindResponseUDPConnection(ipFamily)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw UDP %s socket for DNS Proxy: %w", ipFamily.Name, err)
	}

	return &sessionUDPFactory{rawResponseConn: rawResponseConn}, nil
}

type sessionUDPFactory struct {
	// A pool for UDP message buffers.
	udpPool sync.Pool

	// rawResponseConn is used to send the response
	// See sessionUDP.WriteResponse
	rawResponseConn *net.IPConn
}

// sessionUDP implements the dns.SessionUDP, holding the remote address and the associated
// out-of-band data.
type sessionUDP struct {
	f     *sessionUDPFactory // owner
	conn  *net.UDPConn       // UDP socket for receiving both IPv4 and IPv6
	raddr *net.UDPAddr
	laddr *net.UDPAddr
	m     []byte
	oob   []byte
}

// Set the socket options needed for tranparent proxying for the listening socket
// IP(V6)_TRANSPARENT allows socket to receive packets with any destination address/port
// IP(V6)_RECVORIGDSTADDR tells the kernel to pass the original destination address/port on recvmsg
// By design, a socket of a DNS Server can only receive IPv4 or IPv6 traffic.
func transparentSetsockopt(fd int, ipFamily ipfamily.IPFamily) error {
	if err := unix.SetsockoptInt(fd, ipFamily.SocketOptsFamily, ipFamily.SocketOptsTransparent, 1); err != nil {
		return fmt.Errorf("setsockopt(IP_TRANSPARENT) for %s failed: %w", ipFamily.Name, err)
	}
	if err := unix.SetsockoptInt(fd, ipFamily.SocketOptsFamily, ipFamily.SocketOptsRecvOrigDstAddr, 1); err != nil {
		return fmt.Errorf("setsockopt(IP_RECVORIGDSTADDR) for %s failed: %w", ipFamily.Name, err)
	}

	return nil
}

// listenConfig sets the socket options for the fqdn proxy transparent socket.
// Note that it is also used for TCP sockets.
func listenConfig(mark int, ipFamily ipfamily.IPFamily) *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(_, _ string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				if err := transparentSetsockopt(int(fd), ipFamily); err != nil {
					opErr = err
					return
				}
				if mark != 0 {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark); err != nil {
						opErr = fmt.Errorf("setsockopt(SO_MARK) failed: %w", err)
						return
					}
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1); err != nil {
					opErr = fmt.Errorf("setsockopt(SO_REUSEADDR) failed: %w", err)
					return
				}
				if !option.Config.EnableBPFTProxy {
					if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						opErr = fmt.Errorf("setsockopt(SO_REUSEPORT) failed: %w", err)
						return
					}
				}
			})
			if err != nil {
				return err
			}

			return opErr
		},
	}
}

func bindResponseUDPConnection(ipFamily ipfamily.IPFamily) (*net.IPConn, error) {
	// Mark outgoing packets as proxy egress return traffic (0x0b00)
	conn, err := listenConfig(linux_defaults.MagicMarkEgress, ipFamily).ListenPacket(context.Background(), "ip:udp", ipFamily.Localhost)
	if err != nil {
		return nil, fmt.Errorf("failed to bind UDP for address %s: %w", ipFamily.Localhost, err)
	}
	return conn.(*net.IPConn), nil
}

// SetSocketOptions set's up 'conn' to be used with a SessionUDP.
func (f *sessionUDPFactory) SetSocketOptions(_ *net.UDPConn) error {
	// Response connections (IPv4 & IPv6) will be used to response.
	// They are already properly setup in NewSessionUDPFactory.
	return nil
}

// InitPool initializes a pool of buffers to be used with SessionUDP.
func (f *sessionUDPFactory) InitPool(msgSize int) {
	f.udpPool.New = func() interface{} {
		return &sessionUDP{
			f:   f,
			m:   make([]byte, msgSize),
			oob: make([]byte, udpOOBSize),
		}
	}
}

// ReadRequest reads a single request from 'conn' and returns the request context
func (f *sessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, dns.SessionUDP, error) {
	s := f.udpPool.Get().(*sessionUDP)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(s.m, s.oob)
	if err != nil {
		s.Discard()
		return nil, nil, err
	}
	s.conn = conn
	s.raddr = raddr
	s.m = s.m[:n]        // Re-slice to the actual size
	s.oob = s.oob[:oobn] // Re-slice to the actual size
	s.laddr, err = parseDstFromOOB(s.oob)
	if err != nil {
		s.Discard()
		return nil, nil, err
	}
	return s.m, s, err
}

func (f *sessionUDPFactory) ReadRequestConn(conn net.PacketConn) ([]byte, net.Addr, error) {
	return []byte{}, nil, errors.New("ReadRequestConn is not supported")
}

// Discard returns 's' to the factory pool
func (s *sessionUDP) Discard() {
	s.conn = nil
	s.raddr = nil
	s.laddr = nil
	s.m = s.m[:cap(s.m)]
	s.oob = s.oob[:cap(s.oob)]

	s.f.udpPool.Put(s)
}

// RemoteAddr returns the remote network address.
func (s *sessionUDP) RemoteAddr() net.Addr { return s.raddr }

// LocalAddr returns the local network address for the current request.
func (s *sessionUDP) LocalAddr() net.Addr { return s.laddr }

// WriteResponse writes a response to a request received earlier
// It uses the raw udp connections (IPv4 or IPv6) from its sessionUDPFactory.
func (s *sessionUDP) WriteResponse(b []byte) (int, error) {
	// Must give the UDP header to get the source port right.
	// Reuse the msg buffer, figure out if golang can do gatter-scather IO
	// with raw sockets?
	l := len(b)
	bb := bytes.NewBuffer(s.m[:0])
	binary.Write(bb, binary.BigEndian, uint16(s.laddr.Port))
	binary.Write(bb, binary.BigEndian, uint16(s.raddr.Port))
	binary.Write(bb, binary.BigEndian, uint16(8+l))
	binary.Write(bb, binary.BigEndian, uint16(0)) // checksum
	bb.Write(b)
	buf := bb.Bytes()

	var n int
	var err error
	dst := net.IPAddr{
		IP: s.raddr.IP,
	}

	n, _, err = s.f.rawResponseConn.WriteMsgIP(buf, s.controlMessage(s.laddr), &dst)
	if err != nil {
		log.WithError(err).Warning("WriteMsgIP failed")
	} else {
		log.Debugf("dnsproxy: Wrote DNS response (%d/%d bytes) from %s to %s", n-8, l, s.laddr.String(), s.raddr.String())
	}
	return n, err
}

// parseDstFromOOB takes oob data and returns the destination IP.
func parseDstFromOOB(oob []byte) (*net.UDPAddr, error) {
	msgs, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, fmt.Errorf("parsing socket control message: %s", err)
	}

	for _, msg := range msgs {
		if msg.Header.Level == unix.SOL_IP && msg.Header.Type == unix.IP_ORIGDSTADDR {
			pp := &unix.RawSockaddrInet4{}
			// Address family is in native byte order
			family := *(*uint16)(unsafe.Pointer(&msg.Data[unsafe.Offsetof(pp.Family)]))
			if family != unix.AF_INET {
				return nil, fmt.Errorf("original destination is not IPv4")
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
			pp := &unix.RawSockaddrInet6{}
			// Address family is in native byte order
			family := *(*uint16)(unsafe.Pointer(&msg.Data[unsafe.Offsetof(pp.Family)]))
			if family != unix.AF_INET6 {
				return nil, fmt.Errorf("original destination is not IPv6")
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
	return nil, fmt.Errorf("no original destination found")
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
