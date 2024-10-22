// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multicast

import (
	"net"
	"net/netip"

	"github.com/vishvananda/netlink"
	"golang.org/x/net/ipv6"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	// v6Socket is the udp socket used to join/leave a multicast group
	v6Socket net.PacketConn

	mutex lock.Mutex

	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "multicast")
)

// Pre-Defined Multicast Addresses
// as defined in https://tools.ietf.org/html/rfc4291#section-2.7.1

var (
	// AllNodesIfcLocalMaddr is the multicast address that identifies the group of
	// all IPv6 nodes, within scope 1 (interface-local)
	AllNodesIfcLocalMaddr net.IP = net.ParseIP("ff01::1")

	// AllNodesLinkLocalMaddr is the multicast address that identifies the group of
	// all IPv6 nodes, within scope 2 (link-local)
	AllNodesLinkLocalMaddr net.IP = net.ParseIP("ff02::1")

	// AllRoutersIfcLocalMaddr is the multicast address that identifies the group of
	// all IPv6 routers, within scope 1 (interface-local)
	AllRoutersIfcLocalMaddr net.IP = net.ParseIP("ff01::2")

	// AllRoutersLinkLocalMaddr is the multicast address that identifies the group of
	// all IPv6 routers, within scope 2 (link-local)
	AllRoutersLinkLocalMaddr net.IP = net.ParseIP("ff02::2")

	// AllRoutersSiteLocalMaddr is the multicast address that identifies the group of
	// all IPv6 routers, within scope 5 (site-local)
	AllRoutersSiteLocalMaddr net.IP = net.ParseIP("ff05::2")

	// SolicitedNodeMaddrPrefix is the prefix of the multicast address that is used
	// as part of NDP
	SolicitedNodeMaddrPrefix net.IP = net.ParseIP("ff02::1:ff00:0")
)

func initSocket() error {
	mutex.Lock()
	defer mutex.Unlock()

	if v6Socket != nil {
		return nil
	}

	c, err := net.ListenPacket("udp6", "[::]:0")
	if err != nil {
		log.WithError(err).Warn("Failed to listen on socket for multicast")
		return err
	}

	v6Socket = c
	return nil
}

// JoinGroup joins the group address group on the interface ifc
func JoinGroup(ifc string, ip netip.Addr) error {
	if err := initSocket(); err != nil {
		return err
	}

	dev, err := interfaceByName(ifc)
	if err != nil {
		return err
	}

	return ipv6.NewPacketConn(v6Socket).JoinGroup(dev, &net.UDPAddr{IP: ip.AsSlice()})
}

// LeaveGroup leaves the group address group on the interface ifc
func LeaveGroup(ifc string, ip netip.Addr) error {
	if err := initSocket(); err != nil {
		return err
	}

	dev, err := interfaceByName(ifc)
	if err != nil {
		return err
	}

	return ipv6.NewPacketConn(v6Socket).LeaveGroup(dev, &net.UDPAddr{IP: ip.AsSlice()})
}

// ListGroup lists multicast addresses on the interface ifc
func ListGroup(ifc string) ([]net.Addr, error) {
	dev, err := interfaceByName(ifc)
	if err != nil {
		return nil, err
	}

	return dev.MulticastAddrs()
}

// IsInGroup tells if interface ifc belongs to group represented by maddr
func IsInGroup(ifc string, maddr netip.Addr) (bool, error) {
	ips, err := ListGroup(ifc)
	if err != nil {
		return false, err
	}

	maddrStr := maddr.String()
	for _, gip := range ips {
		if gip.String() == maddrStr {
			return true, nil
		}
	}

	return false, nil
}

// Address encapsulates the functionality to generate solicated node multicast address
type Address netip.Addr

// Key takes the last 3 bytes of endpoint's IPv6 address and compile them in to
// an int32 value as key of the endpoint. It assumes the input is a valid IPv6 address.
// Otherwise it returns 0 (https://tools.ietf.org/html/rfc4291#section-2.7.1)
func (a Address) Key() int32 {
	ipv6 := netip.Addr(a)
	if !ipv6.IsValid() {
		return 0
	}

	var key int32
	for _, v := range ipv6.AsSlice()[13:] {
		key <<= 8
		key += int32(v)
	}

	return key
}

// SolicitedNodeMaddr returns solicited node multicast address
func (a Address) SolicitedNodeMaddr() netip.Addr {
	ipv6 := netip.Addr(a)
	if !ipv6.IsValid() {
		return netip.Addr{}
	}

	maddr := make([]byte, 16)
	copy(maddr[:13], SolicitedNodeMaddrPrefix[:13])
	copy(maddr[13:], ipv6.AsSlice()[13:])

	// Use slice-to-array-pointer conversion, available since Go 1.17.
	// TODO: use slice-to-array conversion when switching to Go 1.20
	return netip.AddrFrom16(*(*[16]byte)(maddr))
}

// interfaceByName get *net.Interface by name using netlink.
//
// The reason not to use net.InterfaceByName directly is to avoid potential
// deadlocks (#15051).
func interfaceByName(name string) (*net.Interface, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return nil, err
	}

	return &net.Interface{
		Index:        link.Attrs().Index,
		MTU:          link.Attrs().MTU,
		Name:         link.Attrs().Name,
		Flags:        link.Attrs().Flags,
		HardwareAddr: link.Attrs().HardwareAddr,
	}, nil
}
