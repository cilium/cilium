// Package raw enables reading and writing data at the device driver level for
// a network interface.
package raw

import (
	"errors"
	"net"
	"time"

	"golang.org/x/net/bpf"
)

// ErrNotImplemented is returned when certain functionality is not yet
// implemented for the host operating system.
var ErrNotImplemented = errors.New("raw: not implemented")

var _ net.Addr = &Addr{}

// Addr is a network address which can be used to contact other machines, using
// their hardware addresses.
type Addr struct {
	HardwareAddr net.HardwareAddr
}

// Network returns the address's network name, "raw".
func (a *Addr) Network() string {
	return "raw"
}

// String returns the address's hardware address.
func (a *Addr) String() string {
	return a.HardwareAddr.String()
}

var _ net.PacketConn = &Conn{}

// Conn is an implementation of the net.PacketConn interface which can send
// and receive data at the network interface device driver level.
type Conn struct {
	// packetConn is the operating system-specific implementation of
	// a raw connection.
	p *packetConn
}

// ReadFrom implements the net.PacketConn ReadFrom method.
func (c *Conn) ReadFrom(b []byte) (int, net.Addr, error) {
	return c.p.ReadFrom(b)
}

// WriteTo implements the net.PacketConn WriteTo method.
func (c *Conn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.p.WriteTo(b, addr)
}

// Close closes the connection.
func (c *Conn) Close() error {
	return c.p.Close()
}

// LocalAddr returns the local network address.
func (c *Conn) LocalAddr() net.Addr {
	return c.p.LocalAddr()
}

// SetDeadline implements the net.PacketConn SetDeadline method.
func (c *Conn) SetDeadline(t time.Time) error {
	return c.p.SetDeadline(t)
}

// SetReadDeadline implements the net.PacketConn SetReadDeadline method.
func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.p.SetReadDeadline(t)
}

// SetWriteDeadline implements the net.PacketConn SetWriteDeadline method.
func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.p.SetWriteDeadline(t)
}

var _ bpf.Setter = &Conn{}

// SetBPF attaches an assembled BPF program to the connection.
func (c *Conn) SetBPF(filter []bpf.RawInstruction) error {
	return c.p.SetBPF(filter)
}

// SetPromiscuous enables or disables promiscuous mode on the interface, allowing it
// to receive traffic that is not addressed to the interface.
func (c *Conn) SetPromiscuous(b bool) error {
	return c.p.SetPromiscuous(b)
}

// Stats contains statistics about a Conn.
type Stats struct {
	// The total number of packets received.
	Packets uint64

	// The number of packets dropped.
	Drops uint64
}

// Stats retrieves statistics from the Conn.
//
// Only supported on Linux at this time.
func (c *Conn) Stats() (*Stats, error) {
	return c.p.Stats()
}

// ListenPacket creates a net.PacketConn which can be used to send and receive
// data at the network interface device driver level.
//
// ifi specifies the network interface which will be used to send and receive
// data.
//
// proto specifies the protocol (usually the EtherType) which should be
// captured and transmitted.  proto, if needed, is automatically converted to
// network byte order (big endian), akin to the htons() function in C.
//
// cfg specifies optional configuration which may be operating system-specific.
// A nil Config is equivalent to the default configuration: send and receive
// data at the network interface device driver level (usually raw Ethernet frames).
func ListenPacket(ifi *net.Interface, proto uint16, cfg *Config) (*Conn, error) {
	// A nil config is an empty Config.
	if cfg == nil {
		cfg = &Config{}
	}

	p, err := listenPacket(ifi, proto, *cfg)
	if err != nil {
		return nil, err
	}

	return &Conn{
		p: p,
	}, nil
}

// A Config can be used to specify additional options for a Conn.
type Config struct {
	// Linux only: call socket(7) with SOCK_DGRAM instead of SOCK_RAW.
	// Has no effect on other operating systems.
	LinuxSockDGRAM bool

	// Linux only: do not accumulate packet socket statistic counters.  Packet
	// socket statistics are reset on each call to retrieve them via getsockopt,
	// but this package's default behavior is to continue accumulating the
	// statistics internally per Conn.  To use the Linux default behavior of
	// resetting statistics on each call to Stats, set this value to true.
	NoCumulativeStats bool

	// Linux only: initial filter to apply to the connection. This avoids
	// capturing random packets before SetBPF is called.
	Filter []bpf.RawInstruction

	// BSD only: configure the BPF direction flag to allow selection of inbound
	// only (0 - default) or bidirectional (1) packet processing.
	// Has no effect on other operating systems.
	BPFDirection int
}
