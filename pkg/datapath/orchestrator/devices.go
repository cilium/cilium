// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package orchestrator

import (
	"fmt"
	"net"

	vnl "github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/datapath/tables"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/mac"
	"github.com/cilium/cilium/pkg/option"
)

// setupBaseDevice decides which and what kind of interfaces should be set up as
// the first step of datapath initialization, then performs the setup (and
// creation, if needed) of those interfaces. It returns two links and an error.
// By default, it sets up the veth pair - cilium_host and cilium_net.
func (o *orchestrator) setupBaseDevice() (vnl.Link, vnl.Link, error) {
	if err := o.setupVethPair(defaults.HostDevice, defaults.SecondHostDevice); err != nil {
		return nil, nil, err
	}

	linkHost, err := o.params.Netlink.LinkByName(defaults.HostDevice)
	if err != nil {
		return nil, nil, err
	}
	linkNet, err := o.params.Netlink.LinkByName(defaults.SecondHostDevice)
	if err != nil {
		return nil, nil, err
	}

	if err := o.params.Netlink.LinkSetARPOff(linkHost); err != nil {
		return nil, nil, err
	}
	if err := o.params.Netlink.LinkSetARPOff(linkNet); err != nil {
		return nil, nil, err
	}

	mtu := o.params.Mtu.GetDeviceMTU()
	if err := o.params.Netlink.LinkSetMTU(linkHost, mtu); err != nil {
		return nil, nil, err
	}
	if err := o.params.Netlink.LinkSetMTU(linkNet, mtu); err != nil {
		return nil, nil, err
	}

	return linkHost, linkNet, nil
}

func (o *orchestrator) setupVethPair(name, peerName string) error {
	// Create the veth pair if it doesn't exist.
	if _, err := o.params.Netlink.LinkByName(name); err != nil {
		hostMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}
		peerMac, err := mac.GenerateRandMAC()
		if err != nil {
			return err
		}

		veth := &vnl.Veth{
			LinkAttrs: vnl.LinkAttrs{
				Name:         name,
				HardwareAddr: net.HardwareAddr(hostMac),
				TxQLen:       1000,
			},
			PeerName:         peerName,
			PeerHardwareAddr: net.HardwareAddr(peerMac),
		}
		if err := o.params.Netlink.LinkAdd(veth); err != nil {
			return err
		}
	}

	veth, err := o.params.Netlink.LinkByName(name)
	if err != nil {
		return err
	}
	if err := o.enableForwarding(veth); err != nil {
		return err
	}
	peer, err := o.params.Netlink.LinkByName(peerName)
	if err != nil {
		return err
	}
	if err := o.enableForwarding(peer); err != nil {
		return err
	}

	return nil
}

// enableForwarding puts the given link into the up state and enables IP forwarding.
func (o *orchestrator) enableForwarding(link vnl.Link) error {
	ifName := link.Attrs().Name

	if err := o.params.Netlink.LinkSetUp(link); err != nil {
		o.params.Logger.WithError(err).WithField("device", ifName).Warn("Could not set up the link")
		return err
	}

	sysSettings := make([]tables.Sysctl, 0, 5)
	if option.Config.EnableIPv6 {
		sysSettings = append(sysSettings, tables.Sysctl{
			Name: fmt.Sprintf("net.ipv6.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false})
	}
	if option.Config.EnableIPv4 {
		sysSettings = append(sysSettings, []tables.Sysctl{
			{Name: fmt.Sprintf("net.ipv4.conf.%s.forwarding", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.rp_filter", ifName), Val: "0", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.accept_local", ifName), Val: "1", IgnoreErr: false},
			{Name: fmt.Sprintf("net.ipv4.conf.%s.send_redirects", ifName), Val: "0", IgnoreErr: false},
		}...)
	}
	if err := o.params.Sysctl.ApplySettings(sysSettings); err != nil {
		return err
	}

	return nil
}

// addHostDeviceAddr add internal ipv4 and ipv6 addresses to the cilium_host device.
func (o *orchestrator) addHostDeviceAddr(hostDev vnl.Link, ipv4, ipv6 net.IP) error {
	if ipv4 != nil {
		addr := vnl.Addr{
			IPNet: &net.IPNet{
				IP:   ipv4,
				Mask: net.CIDRMask(32, 32), // corresponds to /32
			},
		}

		if err := o.params.Netlink.AddrReplace(hostDev, &addr); err != nil {
			return err
		}
	}
	if ipv6 != nil {
		addr := vnl.Addr{
			IPNet: &net.IPNet{
				IP:   ipv6,
				Mask: net.CIDRMask(128, 128), // corresponds to /128
			},
		}

		if err := o.params.Netlink.AddrReplace(hostDev, &addr); err != nil {
			return err
		}

	}
	return nil
}
