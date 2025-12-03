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
	"github.com/mdlayher/packet"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv6"
)

type Sender interface {
	// Send a Gratuitous ARP packet for a given IP, mapping it to a given source hardware
	// address.
	SendArp(iface Interface, ip netip.Addr, srcHW net.HardwareAddr) error

	// Send a Gratuitous ND packet for a given IP, mapping it to a given source hardware
	// address.
	SendNd(iface Interface, ip netip.Addr, srcHW net.HardwareAddr) error

	// NewArpSender returns a new client bound to a given interface that can
	// be used to send multiple Gratuitous ARP packets, for efficiency reasons.
	// It must be closed when no longer used.
	NewArpSender(iface Interface) (ArpSender, error)

	// NewNdSender returns a new client bound to a given interface that can
	// be used to send multiple Gratuitous ND packets, for efficiency reasons.
	// It must be closed when no longer used.
	NewNdSender(iface Interface) (NdSender, error)

	// InterfaceByIndex get Interface by ifindex
	InterfaceByIndex(idx int) (Interface, error)
}

type ArpSender interface {
	// Send a Gratuitous ARP packet for a given IP, mapping it to a given source hardware
	// address.
	Send(ip netip.Addr, srcHW net.HardwareAddr) error

	// Close the connection.
	Close() error
}

type NdSender interface {
	// Send a Gratuitous ND packet for a given IP, mapping it to a given source hardware
	// address.
	Send(ip netip.Addr, srcHW net.HardwareAddr) error

	// Close the connection.
	Close() error
}

func newSender() Sender {
	return &sender{}
}

type Interface struct {
	iface *net.Interface
}

// Name returns the interface name.
func (i Interface) Name() string {
	return i.iface.Name
}

// HardwareAddr returns the interface hardware address.
func (i Interface) HardwareAddr() net.HardwareAddr {
	return i.iface.HardwareAddr
}

// InterfaceFromNetInterface constructs an Interface from the given *net.Interface.
func InterfaceFromNetInterface(iface *net.Interface) Interface {
	return Interface{iface: iface}
}

type sender struct{}

// arpDropAllFilter filters out all packets, as we are only interested in
// sending gARPs, not receiving anything.
var arpDropAllFilter = packet.Config{
	Filter: []bpf.RawInstruction{
		func() bpf.RawInstruction {
			// [RetConstant.Assemble] never returns a non-nil error.
			ins, _ := bpf.RetConstant{Val: 0 /* discard the packet */}.Assemble()
			return ins
		}(),
	},
}

func (s *sender) NewArpSender(iface Interface) (ArpSender, error) {
	// We do not use [arp.Dial] as it strictly requires the iface to be assigned an IPv4 address.
	cl, err := packet.Listen(iface.iface, packet.Raw, int(ethernet.EtherTypeARP), &arpDropAllFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to open ARP socket: %w", err)
	}

	return &arpSender{
		cl: cl,
	}, nil
}

func (s *sender) SendArp(iface Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	cl, err := s.NewArpSender(iface)
	if err != nil {
		return err
	}
	defer cl.Close()

	return cl.Send(ip, srcHW)
}

// icmpDropAllFilter filters out all packets, as we are only interested in
// sending gNDs, not receiving anything.
var icmpDropAllFilter = func() (filter ipv6.ICMPFilter) {
	filter.SetAll(true)
	return filter
}()

func (s *sender) NewNdSender(iface Interface) (NdSender, error) {
	cl, _, err := ndp.Listen(iface.iface, ndp.LinkLocal)
	if err != nil {
		return nil, fmt.Errorf("failed to open ND socket: %w", err)
	}

	if err := cl.SetICMPFilter(&icmpDropAllFilter); err != nil {
		return nil, fmt.Errorf("failed to configure ICMP filter: %w", err)
	}

	return &ndSender{
		cl: cl,
	}, nil
}

func (s *sender) SendNd(iface Interface, ip netip.Addr, srcHW net.HardwareAddr) error {
	cl, err := s.NewNdSender(iface)
	if err != nil {
		return err
	}
	defer cl.Close()

	return cl.Send(ip, srcHW)
}

type arpSender struct {
	cl *packet.Conn
}

func (s *arpSender) Close() error {
	return s.cl.Close()
}

func (s *arpSender) Send(ip netip.Addr, srcHW net.HardwareAddr) error {
	if ip.Is6() {
		return fmt.Errorf("failed to send gratuitous ARP packet. Address is v6 %s", ip)
	}

	arp, err := arp.NewPacket(arp.OperationRequest, srcHW, ip, ethernet.Broadcast, ip)
	if err != nil {
		return fmt.Errorf("failed to craft gratuitous ARP packet: %w", err)
	}

	pb, err := arp.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal gratuitous ARP packet: %w", err)
	}

	f := &ethernet.Frame{
		Destination: ethernet.Broadcast,
		Source:      arp.SenderHardwareAddr,
		EtherType:   ethernet.EtherTypeARP,
		Payload:     pb,
	}

	fb, err := f.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal gratuitous ARP packet: %w", err)
	}

	_, err = s.cl.WriteTo(fb, &packet.Addr{HardwareAddr: ethernet.Broadcast})
	if err != nil {
		return fmt.Errorf("failed to send gratuitous ARP packet: %w", err)
	}

	return nil
}

type ndSender struct {
	cl *ndp.Conn
}

func (s *ndSender) Close() error {
	return s.cl.Close()
}

func (s *ndSender) Send(ip netip.Addr, srcHW net.HardwareAddr) error {
	if ip.Is4() {
		return fmt.Errorf("failed to send gratuitous ND packet. Address is v4 %s", ip)
	}

	msg := &ndp.NeighborAdvertisement{
		TargetAddress: ip,
		Options: []ndp.Option{
			&ndp.LinkLayerAddress{
				Direction: ndp.Source,
				Addr:      srcHW,
			},
		},
	}

	dst, _ := netip.AddrFromSlice(net.IPv6linklocalallnodes)
	err := s.cl.WriteTo(msg, nil, dst)
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

	return InterfaceFromNetInterface(
		&net.Interface{
			Index:        link.Attrs().Index,
			MTU:          link.Attrs().MTU,
			Name:         link.Attrs().Name,
			Flags:        link.Attrs().Flags,
			HardwareAddr: link.Attrs().HardwareAddr,
		},
	), nil
}
