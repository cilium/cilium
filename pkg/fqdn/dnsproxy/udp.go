// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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

	"github.com/cilium/cilium/pkg/option"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"

	"github.com/miekg/dns"
)

// This is the required size of the OOB buffer to pass to ReadMsgUDP.
var udpOOBSize = func() int {
	var hdr unix.Cmsghdr
	var addr unix.RawSockaddrInet6
	return int(unsafe.Sizeof(hdr) + unsafe.Sizeof(addr))
}()

type sessionUDPFactory struct {
	// A pool for UDP message buffers.
	udpPool sync.Pool

	// ipv4Enabled and ipv6Enabled are used when setting up the proxy sockets
	// later, and determine if we bind to 127.0.0.1 and ::1, respectively.
	// See sessionUDPFactory.SetSocketOptions
	ipv4Enabled, ipv6Enabled bool
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

var rawconn4 *net.IPConn // raw socket for sending IPv4
var rawconn6 *net.IPConn // raw socket for sending IPv6

// Set the socket options needed for tranparent proxying for the listening socket
// IP(V6)_TRANSPARENT allows socket to receive packets with any destination address/port
// IP(V6)_RECVORIGDSTADDR tells the kernel to pass the original destination address/port on recvmsg
// The socket may be receiving both IPv4 and IPv6 data, so set both options, if enabled.
func transparentSetsockopt(fd int, ipv4, ipv6 bool) error {
	var err4, err6 error
	if ipv6 {
		err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
		if err6 == nil {
			err6 = unix.SetsockoptInt(fd, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		}
		if err6 != nil {
			return err6
		}
	}
	if ipv4 {
		err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_TRANSPARENT, 1)
		if err4 == nil {
			err4 = unix.SetsockoptInt(fd, unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		}
		if err4 != nil {
			return err4
		}
	}
	return nil
}

func listenConfig(mark int, ipv4, ipv6 bool) *net.ListenConfig {
	return &net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				opErr = transparentSetsockopt(int(fd), ipv4, ipv6)
				if opErr == nil && mark != 0 {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, mark)
				}
				if opErr == nil {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				}
				if opErr == nil && !option.Config.EnableBPFTProxy {
					opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				}
			})
			if err != nil {
				return err
			}

			return opErr
		}}
}

func bindUDP(addr string, ipv4, ipv6 bool) *net.IPConn {
	// Mark outgoing packets as proxy egress return traffic (0x0b00)
	conn, err := listenConfig(0xb00, ipv4, ipv6).ListenPacket(context.Background(), "ip:udp", addr)
	if err != nil {
		log.WithError(err).Errorf("bindUDP failed for address %s", addr)
		return nil
	}
	return conn.(*net.IPConn)
}

// NOTE: udpOnce is used in SetSocketOptions below, but assumes we have a
// global singleton sessionUDPFactory. This is created in StartDNSProxy in
// order to have option.Config.EnableIPv{4,6} parsed correctly.
var udpOnce sync.Once

// SetSocketOptions set's up 'conn' to be used with a SessionUDP.
func (f *sessionUDPFactory) SetSocketOptions(conn *net.UDPConn) error {
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
		if f.ipv4Enabled {
			rawconn4 = bindUDP("127.0.0.1", f.ipv4Enabled, false) // raw socket for sending IPv4
		}
		if f.ipv6Enabled {
			rawconn6 = bindUDP("::1", false, f.ipv6Enabled) // raw socket for sending IPv6
		}
	})
	if (f.ipv4Enabled && rawconn4 == nil) || (f.ipv6Enabled && rawconn6 == nil) {
		return fmt.Errorf("Unable to open raw UDP sockets for DNS Proxy")
	}
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
	if s.raddr.IP.To4() == nil {
		n, _, err = rawconn6.WriteMsgIP(buf, s.controlMessage(s.laddr), &dst)
	} else {
		n, _, err = rawconn4.WriteMsgIP(buf, s.controlMessage(s.laddr), &dst)
	}
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
				return nil, fmt.Errorf("original destination is not IPv4.")
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
				return nil, fmt.Errorf("original destination is not IPv6.")
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
