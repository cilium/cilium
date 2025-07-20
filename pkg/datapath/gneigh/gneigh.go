// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gneigh

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/mdlayher/ndp"
	"github.com/vishvananda/netlink"
)

type Sender interface {
	// Send a Gratuitous ARP packet for a given IP over an interface
	SendArp(iface Interface, ip netip.Addr) error

	// Send a Gratuitous ND packet for a given IP over an interface
	SendNd(iface Interface, ip netip.Addr) error

	// InterfaceByIndex get Interface by ifindex
	InterfaceByIndex(idx int) (Interface, error)
}

func newSender() Sender {
	return &sender{}
}

type Interface struct {
	iface *net.Interface
}

type sender struct{}

func (s *sender) SendArp(iface Interface, ip netip.Addr) error {
	if ip.Is6() {
		return fmt.Errorf("failed to send gratuitous ARP packet. Address is v6 %s", ip)
	}

	arpClient, err := arp.Dial(iface.iface)
	if err != nil {
		return fmt.Errorf("failed to open ARP socket: %w", err)
	}
	defer arpClient.Close()

	arp, err := arp.NewPacket(arp.OperationReply, iface.iface.HardwareAddr, ip, ethernet.Broadcast, ip)
	if err != nil {
		return fmt.Errorf("failed to craft gratuitous ARP packet: %w", err)
	}

	err = arpClient.WriteTo(arp, ethernet.Broadcast)
	if err != nil {
		return fmt.Errorf("failed to send gratuitous ARP packet: %w", err)
	}

	return nil
}

func (s *sender) SendNd(iface Interface, ip netip.Addr) error {
	if ip.Is4() {
		return fmt.Errorf("failed to send gratuitous ND packet. Address is v4 %s", ip)
	}

	ndClient, _, err := ndp.Listen(iface.iface, ndp.LinkLocal)
	if err != nil {
		return fmt.Errorf("failed to open ND socket: %w", err)
	}
	defer ndClient.Close()

	msg := &ndp.NeighborAdvertisement{
		TargetAddress: ip,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      iface.iface.HardwareAddr,
			},
		},
	}

	dst, _ := netip.AddrFromSlice(net.IPv6linklocalallnodes)
	err = ndClient.WriteTo(msg, nil, dst)
	if err != nil {
		return fmt.Errorf("failed to send gratuitous ND packet: %w", err)
	}

	return nil
}

// InterfaceByIndex get Interface by ifindex
func (s *sender) InterfaceByIndex(idx int) (Interface, error) {
	link, err := netlink.LinkByIndex(idx)
	if err != nil {
		return Interface{}, err
	}

	return Interface{
		iface: &net.Interface{
			Index:        link.Attrs().Index,
			MTU:          link.Attrs().MTU,
			Name:         link.Attrs().Name,
			Flags:        link.Attrs().Flags,
			HardwareAddr: link.Attrs().HardwareAddr,
		},
	}, nil
}
