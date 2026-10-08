package ndp

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

// HopLimit is the expected IPv6 hop limit for all NDP messages.
const HopLimit = 255

// A Conn is a Neighbor Discovery Protocol connection.
type Conn struct {
	pc *ipv6.PacketConn
	cm *ipv6.ControlMessage

	ifi  *net.Interface
	addr netip.Addr

	// icmpTest disables the self-filtering mechanism in ReadFrom.
	icmpTest bool
}

// Listen creates a NDP connection using the specified interface and address
// type.
//
// As a special case, literal IPv6 addresses may be specified to bind to a
// specific address for an interface. If the IPv6 address does not exist on the
// interface, an error will be returned.
//
// Listen returns a Conn and the chosen IPv6 address of the interface.
func Listen(ifi *net.Interface, addr Addr) (*Conn, netip.Addr, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, netip.Addr{}, err
	}

	ip, err := chooseAddr(addrs, ifi.Name, addr)
	if err != nil {
		return nil, netip.Addr{}, err
	}

	ic, err := icmp.ListenPacket("ip6:ipv6-icmp", ip.String())
	if err != nil {
		return nil, netip.Addr{}, err
	}

	pc := ic.IPv6PacketConn()

	// Hop limit is always 255, per RFC 4861.
	if err := pc.SetHopLimit(HopLimit); err != nil {
		return nil, netip.Addr{}, err
	}
	if err := pc.SetMulticastHopLimit(HopLimit); err != nil {
		return nil, netip.Addr{}, err
	}

	if runtime.GOOS != "windows" {
		// Calculate and place ICMPv6 checksum at correct offset in all
		// messages (not implemented by golang.org/x/net/ipv6 on Windows).
		const chkOff = 2
		if err := pc.SetChecksum(true, chkOff); err != nil {
			return nil, netip.Addr{}, err
		}
	}

	return newConn(pc, ip, ifi)
}

// newConn is an internal test constructor used for creating a Conn from an
// arbitrary ipv6.PacketConn.
func newConn(pc *ipv6.PacketConn, src netip.Addr, ifi *net.Interface) (*Conn, netip.Addr, error) {
	c := &Conn{
		pc: pc,

		// The default control message used when none is specified.
		cm: &ipv6.ControlMessage{
			HopLimit: HopLimit,
			Src:      src.AsSlice(),
			IfIndex:  ifi.Index,
		},

		ifi:  ifi,
		addr: src,
	}

	return c, src, nil
}

// Close closes the Conn's underlying connection.
func (c *Conn) Close() error { return c.pc.Close() }

// SetDeadline sets the read and write deadlines for Conn.  It is
// equivalent to calling both SetReadDeadline and SetWriteDeadline.
func (c *Conn) SetDeadline(t time.Time) error { return c.pc.SetDeadline(t) }

// SetReadDeadline sets a deadline for the next NDP message to arrive.
func (c *Conn) SetReadDeadline(t time.Time) error { return c.pc.SetReadDeadline(t) }

// SetWriteDeadline sets a deadline for the next NDP message to be written.
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

// JoinGroup joins the specified multicast group. If group contains an IPv6
// zone, it is overwritten by the zone of the network interface which backs
// Conn.
func (c *Conn) JoinGroup(group netip.Addr) error {
	return c.pc.JoinGroup(c.ifi, &net.IPAddr{
		IP:   group.AsSlice(),
		Zone: c.ifi.Name,
	})
}

// LeaveGroup leaves the specified multicast group. If group contains an IPv6
// zone, it is overwritten by the zone of the network interface which backs
// Conn.
func (c *Conn) LeaveGroup(group netip.Addr) error {
	return c.pc.LeaveGroup(c.ifi, &net.IPAddr{
		IP:   group.AsSlice(),
		Zone: c.ifi.Name,
	})
}

// SetICMPFilter applies the specified ICMP filter. This option can be used
// to ensure a Conn only accepts certain kinds of NDP messages.
func (c *Conn) SetICMPFilter(f *ipv6.ICMPFilter) error { return c.pc.SetICMPFilter(f) }

// SetControlMessage enables the reception of *ipv6.ControlMessages based on
// the specified flags.
func (c *Conn) SetControlMessage(cf ipv6.ControlFlags, on bool) error {
	return c.pc.SetControlMessage(cf, on)
}

// ReadFrom reads a Message from the Conn and returns its control message and
// source network address. Messages sourced from this machine and malformed or
// unrecognized ICMPv6 messages are filtered.
//
// If more control and/or a more efficient low-level API are required, see
// ReadRaw.
func (c *Conn) ReadFrom() (Message, *ipv6.ControlMessage, netip.Addr, error) {
	b := make([]byte, c.ifi.MTU)
	for {
		n, cm, ip, err := c.ReadRaw(b)
		if err != nil {
			return nil, nil, netip.Addr{}, err
		}

		// Filter if this address sent this message, but allow toggling that
		// behavior in tests.
		if !c.icmpTest && ip == c.addr {
			continue
		}

		m, err := ParseMessage(b[:n])
		if err != nil {
			// Filter parsing errors on the caller's behalf.
			if errors.Is(err, errParseMessage) {
				continue
			}

			return nil, nil, netip.Addr{}, err
		}

		return m, cm, ip, nil
	}
}

// ReadRaw reads ICMPv6 message bytes into b from the Conn and returns the
// number of bytes read, the control message, and the source network address.
//
// Most callers should use ReadFrom instead, which parses bytes into Messages
// and also handles malformed and unrecognized ICMPv6 messages.
func (c *Conn) ReadRaw(b []byte) (int, *ipv6.ControlMessage, netip.Addr, error) {
	n, cm, src, err := c.pc.ReadFrom(b)
	if err != nil {
		return n, nil, netip.Addr{}, err
	}

	// We fully control the underlying ipv6.PacketConn, so panic if the
	// conversions fail.
	ip, ok := netip.AddrFromSlice(src.(*net.IPAddr).IP)
	if !ok {
		panicf("ndp: invalid source IP address: %s", src)
	}

	// Always apply the IPv6 zone of this interface.
	return n, cm, ip.WithZone(c.ifi.Name), nil
}

// WriteTo writes a Message to the Conn, with an optional control message and
// destination network address. If dst contains an IPv6 zone, it is overwritten
// by the zone of the network interface which backs Conn.
//
// If cm is nil, a default control message will be sent.
func (c *Conn) WriteTo(m Message, cm *ipv6.ControlMessage, dst netip.Addr) error {
	b, err := MarshalMessage(m)
	if err != nil {
		return err
	}

	return c.writeRaw(b, cm, dst)
}

// writeRaw allows writing raw bytes with a Conn.
func (c *Conn) writeRaw(b []byte, cm *ipv6.ControlMessage, dst netip.Addr) error {
	// Set reasonable defaults if control message is nil.
	if cm == nil {
		cm = c.cm
	}

	_, err := c.pc.WriteTo(b, cm, &net.IPAddr{
		IP:   dst.AsSlice(),
		Zone: c.ifi.Name,
	})
	return err
}

// SolicitedNodeMulticast returns the solicited-node multicast address for
// an IPv6 address.
func SolicitedNodeMulticast(ip netip.Addr) (netip.Addr, error) {
	if err := checkIPv6(ip); err != nil {
		return netip.Addr{}, err
	}

	// Fixed prefix, and low 24 bits taken from input address.
	var (
		// ff02::1:ff00:0/104
		snm = [16]byte{0: 0xff, 1: 0x02, 11: 0x01, 12: 0xff}
		ips = ip.As16()
	)

	for i := 13; i < 16; i++ {
		snm[i] = ips[i]
	}

	return netip.AddrFrom16(snm), nil
}

func panicf(format string, a ...any) {
	panic(fmt.Sprintf(format, a...))
}
