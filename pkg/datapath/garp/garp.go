// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package garp

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/mdlayher/arp"
	"github.com/mdlayher/ethernet"
	"github.com/vishvananda/netlink"
)

type Sender interface {
	// Send a Gratuitous ARP packet, for a given IP over the given interface.
	Send(iface Interface, ip netip.Addr) error

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

func (s *sender) Send(iface Interface, ip netip.Addr) error {
	arpClient, err := arp.Dial(iface.iface)
	if err != nil {
		return fmt.Errorf("failed to open ARP socket: %w", err)
	}
	defer arpClient.Close()

	arp, err := arp.NewPacket(arp.OperationReply, iface.iface.HardwareAddr, ip, ethernet.Broadcast, ip)
	if err != nil {
		return fmt.Errorf("failed to craft ARP reply packet: %w", err)
	}

	err = arpClient.WriteTo(arp, ethernet.Broadcast)
	if err != nil {
		return fmt.Errorf("failed to send ARP packet: %w", err)
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
