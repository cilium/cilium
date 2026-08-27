// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/vishvananda/netlink"
	"go4.org/netipx"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/mac"
)

func configureCloudInterfaces(ipam *models.IPAMResponse, mtu int) error {
	if ipam == nil {
		return fmt.Errorf("missing IPAM configuration")
	}

	configured := map[mac.MAC]struct{}{}
	for _, address := range []*models.IPAMAddressResponse{ipam.IPv4, ipam.IPv6} {
		// An absent gateway means that this response does not require host-side
		// interface setup, matching the existing routing setup behavior.
		if address == nil || !address.Gateway.IsValid() {
			continue
		}
		if _, found := configured[address.MasterMac]; found {
			continue
		}

		if err := configureCloudInterface(address.MasterMac, mtu); err != nil {
			return err
		}
		configured[address.MasterMac] = struct{}{}
	}
	return nil
}

func configureCloudInterface(masterMAC mac.MAC, mtu int) error {
	link, err := linkFromMac(masterMAC)
	if err != nil {
		return err
	}
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return fmt.Errorf("unable to change MTU of link %s to %d: %w", link.Attrs().Name, mtu, err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("unable to set link %s up: %w", link.Attrs().Name, err)
	}
	return nil
}

func interfaceAdd(ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf *models.DaemonConfigurationStatus) error {
	if ipam == nil {
		return fmt.Errorf("missing IPAM configuration")
	}
	// If the gateway IP is not available, it is already set up
	if !ipam.Gateway.IsValid() {
		return nil
	}

	var allCIDRs []*net.IPNet

	for _, cidr := range ipam.Cidrs {
		if !cidr.IsValid() {
			return fmt.Errorf("invalid CIDR '%s'", cidr)
		}
		// Mask explicitly: net.ParseCIDR, which this loop replaces, returned
		// the masked network, and ip.CoalesceCIDRs below expects that shape.
		allCIDRs = append(allCIDRs, netipx.PrefixIPNet(cidr.Masked()))
	}

	// Coalesce CIDRs into minimum set needed for route rules
	// The routes set up here will be cleaned up by linuxrouting.Delete.
	// Therefor the code here should be kept in sync with the deletion code.
	ipv4CIDRs, ipv6CIDRs := ip.CoalesceCIDRs(allCIDRs)
	coalescedCIDRs := make([]string, 0, len(allCIDRs))
	var masq bool

	if ipConfig.Address.IP.To4() != nil {
		for _, cidr := range ipv4CIDRs {
			coalescedCIDRs = append(coalescedCIDRs, cidr.String())
		}

		masq = conf.MasqueradeProtocols.IPv4
	} else {
		for _, cidr := range ipv6CIDRs {
			coalescedCIDRs = append(coalescedCIDRs, cidr.String())
		}

		masq = conf.MasqueradeProtocols.IPv6
	}

	options := []linuxrouting.RoutingInfoOption{
		linuxrouting.WithCIDRsAndMasquerade(coalescedCIDRs, masq),
		// Ensure CNI ADD can repair interface MTU and state after a transient
		// setup failure before installing endpoint routing state.
		linuxrouting.WithMTU(int(conf.DeviceMTU)),
		linuxrouting.WithLinkState(true),
	}
	if conf.IpamMode == ipamOption.IPAMAzure {
		options = append(options, linuxrouting.WithCompatEgressPriority())
	}

	routingInfo, err := linuxrouting.NewRoutingInfo(
		ipam.Gateway.String(),
		ipam.MasterMac,
		ipam.InterfaceNumber,
		options...,
	)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %w", err)
	}

	if err := routingInfo.Configure(
		ip.AddrFromIP(ipConfig.Address.IP),
		false,
	); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %w", err)
	}

	return nil
}
