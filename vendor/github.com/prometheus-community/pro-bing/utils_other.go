//go:build !linux && !windows
// +build !linux,!windows

package probing

// Returns the length of an ICMP message.
func (p *Pinger) getMessageLength() int {
	return p.Size + 8
}

// Attempts to match the ID of an ICMP packet.
func (p *Pinger) matchID(ID int) bool {
	return ID == p.id
}

// SetMark sets the SO_MARK socket option on outgoing ICMP packets.
// Setting this option requires CAP_NET_ADMIN.
func (c *icmpConn) SetMark(mark uint) error {
	return ErrMarkNotSupported
}

// SetMark sets the SO_MARK socket option on outgoing ICMP packets.
// Setting this option requires CAP_NET_ADMIN.
func (c *icmpv4Conn) SetMark(mark uint) error {
	return ErrMarkNotSupported
}

// SetMark sets the SO_MARK socket option on outgoing ICMP packets.
// Setting this option requires CAP_NET_ADMIN.
func (c *icmpV6Conn) SetMark(mark uint) error {
	return ErrMarkNotSupported
}

// SetDoNotFragment sets the do-not-fragment bit in the IP header of outgoing ICMP packets.
func (c *icmpConn) SetDoNotFragment() error {
	return ErrDFNotSupported
}

// SetDoNotFragment sets the do-not-fragment bit in the IP header of outgoing ICMP packets.
func (c *icmpv4Conn) SetDoNotFragment() error {
	return ErrDFNotSupported
}

// SetDoNotFragment sets the do-not-fragment bit in the IPv6 header of outgoing ICMPv6 packets.
func (c *icmpV6Conn) SetDoNotFragment() error {
	return ErrDFNotSupported
}

// No need for SetBroadcastFlag in non-linux OSes
func (c *icmpConn) SetBroadcastFlag() error {
	return nil
}

func (c *icmpv4Conn) SetBroadcastFlag() error {
	return nil
}

func (c *icmpV6Conn) SetBroadcastFlag() error {
	return nil
}
