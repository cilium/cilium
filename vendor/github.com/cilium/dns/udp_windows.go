// +build windows

package dns

import "net"

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

	// ReadRequestConn reads a single request from 'conn'.
	// Returns the message buffer and the source address
	ReadRequestConn(conn net.PacketConn) ([]byte, net.Addr, error)
}

type sessionUDPFactory struct{}

var defaultSessionUDPFactory = &sessionUDPFactory{}

// SetSocketOptions sets the required UDP socket options on 'conn'.
func (s *sessionUDPFactory) SetSocketOptions(conn *net.UDPConn) error {
	return nil
}

// InitPool initializes a pool of buffers to be used with SessionUDP.
func (f *sessionUDPFactory) InitPool(msgSize int) {}

// ReadRequest reads a single request from 'conn' and returns the request context
func (f *sessionUDPFactory) ReadRequest(conn *net.UDPConn) ([]byte, SessionUDP, error) {
	return nil, SessionUDP{}, nil
}

func (f *sessionUDPFactory) ReadRequestConn(conn net.PacketConn) ([]byte, net.Addr, error) {
	return nil, nil, nil
}

// SessionUDP holds the remote address
type SessionUDP struct {
	raddr *net.UDPAddr
}

func (s *SessionUDP) Discard() {}

// RemoteAddr returns the remote network address.
func (s *SessionUDP) RemoteAddr() net.Addr { return s.raddr }

func (s *SessionUDP) LocalAddr() net.Addr { return &net.UDPAddr{} }

func (s *SessionUDP) WriteResponse(b []byte) (int, error) { return 0, nil }

// ReadFromSessionUDP acts just like net.UDPConn.ReadFrom(), but returns a session object instead of a
// net.UDPAddr.
// TODO(fastest963): Once go1.10 is released, use ReadMsgUDP.
func ReadFromSessionUDP(conn *net.UDPConn, b []byte) (int, *SessionUDP, error) {
	n, raddr, err := conn.ReadFrom(b)
	if err != nil {
		return n, nil, err
	}
	return n, &SessionUDP{raddr.(*net.UDPAddr)}, err
}

// WriteToSessionUDP acts just like net.UDPConn.WriteTo(), but uses a *SessionUDP instead of a net.Addr.
// TODO(fastest963): Once go1.10 is released, use WriteMsgUDP.
func WriteToSessionUDP(conn *net.UDPConn, b []byte, session *SessionUDP) (int, error) {
	return conn.WriteTo(b, session.raddr)
}

// TODO(fastest963): Once go1.10 is released and we can use *MsgUDP methods
// use the standard method in udp.go for these.
func setUDPSocketOptions(*net.UDPConn) error { return nil }
func parseDstFromOOB([]byte, net.IP) net.IP  { return nil }
