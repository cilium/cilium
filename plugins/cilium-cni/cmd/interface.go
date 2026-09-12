// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net/netip"
	"slices"

	current "github.com/containernetworking/cni/pkg/types/100"
	"go4.org/netipx"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"
	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
)

func interfaceAdd(ipConfig *current.IPConfig, ipam *models.IPAMAddressResponse, conf *models.DaemonConfigurationStatus) error {
	if ipam == nil {
		return fmt.Errorf("missing IPAM configuration")
	}
	// If the gateway IP is not available, it is already set up
	if !ipam.Gateway.IsValid() {
		return nil
	}

	// The set merges the CIDRs that cover a contiguous range and drops those
	// contained in another one, so that the prefixes it decomposes back into
	// are the minimum set needed for the route rules.
	var builder netipx.IPSetBuilder

	for _, cidr := range ipam.Cidrs {
		if !cidr.IsValid() {
			return fmt.Errorf("invalid CIDR '%s'", cidr)
		}
		builder.AddPrefix(cidr.Prefix)
	}

	cidrs, err := builder.IPSet()
	if err != nil {
		return fmt.Errorf("failed to build CIDR set: %w", err)
	}

	isIPv4 := ipConfig.Address.IP.To4() != nil

	// Keep only the address family of the endpoint, which is the one routed
	// through this interface. Ranges of different families are never
	// contiguous, so the two families coalesced independently above.
	// The routes set up here will be cleaned up by linuxrouting.Delete.
	// Therefor the code here should be kept in sync with the deletion code.
	coalescedPrefixes := slices.DeleteFunc(
		cidrs.Prefixes(),
		func(prefix netip.Prefix) bool { return prefix.Addr().Is4() != isIPv4 },
	)

	masq := conf.MasqueradeProtocols.IPv6
	if isIPv4 {
		masq = conf.MasqueradeProtocols.IPv4
	}

	options := []linuxrouting.RoutingInfoOption{
		linuxrouting.WithCIDRsAndMasquerade(coalescedPrefixes, masq),
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
