//go:build windows
// +build windows

package probing

import (
	"math"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	minimumBufferLength = 2048
)

// Returns the length of an ICMP message, plus the IP packet header.
// Calculated as:
// len(ICMP request data) + 2 * (len(ICMP header) + len(IP header))
//
// On Windows, the buffer needs to be able to contain:
// - Response IP Header
// - Response ICMP Header
// - Request IP Header
// - Request ICMP Header
// - Request Data
func (p *Pinger) getMessageLength() int {
	if p.ipv4 {
		calculatedLength := p.Size + (ipv4.HeaderLen+8)*2
		return int(math.Max(float64(calculatedLength), float64(minimumBufferLength)))
	}
	calculatedLength := p.Size + (ipv6.HeaderLen+8)*2
	return int(math.Max(float64(calculatedLength), float64(minimumBufferLength)))
}

// Attempts to match the ID of an ICMP packet.
func (p *Pinger) matchID(ID int) bool {
	if ID != p.id {
		return false
	}
	return true
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

func (c *icmpv4Conn) InstallICMPIDFilter(id int) error {
	return nil
}

func (c *icmpV6Conn) InstallICMPIDFilter(id int) error {
	return nil
}
