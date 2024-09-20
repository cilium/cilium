package probing

import (
	"net"
	"runtime"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

type packetConn interface {
	Close() error
	ICMPRequestType() icmp.Type
	ReadFrom(b []byte) (n int, ttl int, src net.Addr, err error)
	SetFlagTTL() error
	SetReadDeadline(t time.Time) error
	WriteTo(b []byte, dst net.Addr) (int, error)
	SetTTL(ttl int)
	SetMark(m uint) error
	SetDoNotFragment() error
	SetBroadcastFlag() error
}

type icmpConn struct {
	c   *icmp.PacketConn
	ttl int
}

func (c *icmpConn) Close() error {
	return c.c.Close()
}

func (c *icmpConn) SetTTL(ttl int) {
	c.ttl = ttl
}

func (c *icmpConn) SetReadDeadline(t time.Time) error {
	return c.c.SetReadDeadline(t)
}

func (c *icmpConn) WriteTo(b []byte, dst net.Addr) (int, error) {
	if c.c.IPv6PacketConn() != nil {
		if err := c.c.IPv6PacketConn().SetHopLimit(c.ttl); err != nil {
			return 0, err
		}
	}
	if c.c.IPv4PacketConn() != nil {
		if err := c.c.IPv4PacketConn().SetTTL(c.ttl); err != nil {
			return 0, err
		}
	}

	return c.c.WriteTo(b, dst)
}

type icmpv4Conn struct {
	icmpConn
}

func (c *icmpv4Conn) SetFlagTTL() error {
	err := c.c.IPv4PacketConn().SetControlMessage(ipv4.FlagTTL, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpv4Conn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	ttl := -1
	n, cm, src, err := c.c.IPv4PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.TTL
	}
	return n, ttl, src, err
}

func (c icmpv4Conn) ICMPRequestType() icmp.Type {
	return ipv4.ICMPTypeEcho
}

type icmpV6Conn struct {
	icmpConn
}

func (c *icmpV6Conn) SetFlagTTL() error {
	err := c.c.IPv6PacketConn().SetControlMessage(ipv6.FlagHopLimit, true)
	if runtime.GOOS == "windows" {
		return nil
	}
	return err
}

func (c *icmpV6Conn) ReadFrom(b []byte) (int, int, net.Addr, error) {
	ttl := -1
	n, cm, src, err := c.c.IPv6PacketConn().ReadFrom(b)
	if cm != nil {
		ttl = cm.HopLimit
	}
	return n, ttl, src, err
}

func (c icmpV6Conn) ICMPRequestType() icmp.Type {
	return ipv6.ICMPTypeEchoRequest
}
