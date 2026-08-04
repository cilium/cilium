// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"log/slog"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"
	"go4.org/netipx"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"
)

func interfaceAdd(logger *slog.Logger, ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf *models.DaemonConfigurationStatus) error {
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

	routingInfo, err := linuxrouting.NewRoutingInfo(
		logger,
		ipam.Gateway.String(),
		coalescedCIDRs,
		ipam.MasterMac,
		ipam.InterfaceNumber,
		conf.IpamMode,
		masq,
	)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %w", err)
	}

	if err := routingInfo.Configure(
		ip.AddrFromIP(ipConfig.Address.IP),
		int(conf.DeviceMTU),
		false,
	); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %w", err)
	}

	return nil
}
