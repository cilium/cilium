// +build !windows

package dns

import (
	"net"
	"sync"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type SessionUDPFactory interface {
	// SetSocketOptions sets the required UDP socket options on 'conn'.
	// Must be called before 'conn' is passed to ReadRequest()
	SetSocketOptions(conn *net.UDPConn) error

	// InitPool initializes a pool of buffers to be used with SessionUDP.
	// Must be called before calling ReadRequest()
	InitPool(msgSize int)

	// ReadRequest reads a single request from 'conn'.
	// Returns the message buffer and the SessionUDP instance
	// that is used to send the response.
	ReadRequest(conn *net.UDPConn) ([]byte, SessionUDP, error)
}

// SessionUDP holds manages a UDP Request/Response transaction.
type SessionUDP interface {
	// Discard returns the SessionUDP back to the factory pool.
	// Must be called whenever the request is not needed any more.
	Discard()
	// RemoteAddr returns the remote address of the last read UDP request
	RemoteAddr() net.Addr
	// LocalAddr returns the local address of the last read UDP request
	LocalAddr() net.Addr
	// WriteResponse writes a response to the UDP request managed
	// by this SessionUDP.  The response is sent to the UDP
	// address the request came from.
	WriteResponse(b []byte) (int, error)
}

// This is the required size of the OOB buffer to pass to ReadMsgUDP.
var udpOOBSize = func() int {
	// We can't know whether we'll get an IPv4 control message or an
	// IPv6 control message ahead of time. To get around this, we size
	// the buffer equal to the largest of the two.

	oob4 := ipv4.NewControlMessage(ipv4.FlagDst | ipv4.FlagInterface)
	oob6 := ipv6.NewControlMessage(ipv6.FlagDst | ipv6.FlagInterface)

	if len(oob4) > len(oob6) {
		return len(oob4)
	}

	return len(oob6)
}()

type sessionUDPFactory struct {
	// A pool for UDP message buffers.
	udpPool sync.Pool
}

// sessionUDP implements the SessionUDP, holding the connection to use
// for the response, the remote address and the associated out-of-band
// data.
type sessionUDP struct {
	f     *sessionUDPFactory // owner
	conn  *net.UDPConn
	raddr *net.UDPAddr
	m     []byte
	oob   []byte
}

var defaultSessionUDPFactory = &sessionUDPFactory{}

// SetSocketOptions sets the required UDP socket options on 'conn'.
func (s *sessionUDPFactory) SetSocketOptions(conn *net.UDPConn) error {
	// Try setting the flags for both families and ignore the errors unless they
	// both error.
	err6 := ipv6.NewPacketConn(conn).SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
	err4 := ipv4.NewPacketConn(conn).SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
	if err6 != nil && err4 != nil {
		return err4
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
func (f *sessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, SessionUDP, error) {
	s := f.udpPool.Get().(*sessionUDP)
	n, oobn, _, raddr, err := conn.ReadMsgUDP(s.m, s.oob)
	if err != nil {
		s.Discard()
		return nil, nil, err
	}
	// Keep context for response
	s.conn = conn
	s.raddr = raddr
	s.m = s.m[:n]        // Re-slice to the actual size
	s.oob = s.oob[:oobn] // Re-slice to the actual size
	return s.m, s, err
}

// Discard returns 's' to the factory pool
func (s *sessionUDP) Discard() {
	s.conn = nil
	s.raddr = nil
	s.m = s.m[:cap(s.m)]
	s.oob = s.oob[:cap(s.oob)]

	s.f.udpPool.Put(s)
}

// RemoteAddr returns the remote network address for the current request.
func (s *sessionUDP) RemoteAddr() net.Addr { return s.raddr }

// LocalAddr returns the local network address for the current request.
func (s *sessionUDP) LocalAddr() net.Addr { return s.conn.LocalAddr() }

// WriteResponse writes a response to a request received earlier
func (s *sessionUDP) WriteResponse(b []byte) (int, error) {
	oob := correctSource(s.oob)
	n, _, err := s.conn.WriteMsgUDP(b, oob, s.raddr)
	return n, err
}

// parseDstFromOOB takes oob data and returns the destination IP.
func parseDstFromOOB(oob []byte) net.IP {
	// Start with IPv6 and then fallback to IPv4
	// TODO(fastest963): Figure out a way to prefer one or the other. Looking at
	// the lvl of the header for a 0 or 41 isn't cross-platform.
	cm6 := new(ipv6.ControlMessage)
	if cm6.Parse(oob) == nil && cm6.Dst != nil {
		return cm6.Dst
	}
	cm4 := new(ipv4.ControlMessage)
	if cm4.Parse(oob) == nil && cm4.Dst != nil {
		return cm4.Dst
	}
	return nil
}

// correctSource takes oob data and returns new oob data with the Src equal to the Dst
func correctSource(oob []byte) []byte {
	dst := parseDstFromOOB(oob)
	if dst == nil {
		return nil
	}
	// If the dst is definitely an IPv6, then use ipv6's ControlMessage to
	// respond otherwise use ipv4's because ipv6's marshal ignores ipv4
	// addresses.
	if dst.To4() == nil {
		cm := new(ipv6.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	} else {
		cm := new(ipv4.ControlMessage)
		cm.Src = dst
		oob = cm.Marshal()
	}
	return oob
}
