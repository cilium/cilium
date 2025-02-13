// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"fmt"
	"net"

	current "github.com/containernetworking/cni/pkg/types/100"
	"github.com/samber/lo"

	"github.com/cilium/cilium/api/v1/models"
	linuxrouting "github.com/cilium/cilium/pkg/datapath/linux/routing"
	"github.com/cilium/cilium/pkg/ip"
)

func interfaceAdd(ipConfig, ipv6Config *current.IPConfig, ipam, ipamV6 *models.IPAMAddressResponse, conf *models.DaemonConfigurationStatus) error {
	if ipam == nil && ipamV6 == nil {
		return fmt.Errorf("missing IPAM configuration")
	}
	// If the gateway IP is not available, it is already set up
	if ipam.Gateway == "" && ipamV6.Gateway == "" {
		return nil
	}

	var allCIDRs []*net.IPNet
	if ipam != nil {
		for _, cidrString := range ipam.Cidrs {
			_, cidr, err := net.ParseCIDR(cidrString)
			if err != nil {
				return fmt.Errorf("invalid CIDR '%s': %w", cidrString, err)
			}
			allCIDRs = append(allCIDRs, cidr)
		}
	}
	if ipamV6 != nil {
		for _, cidrString := range ipamV6.Cidrs {
			_, cidr, err := net.ParseCIDR(cidrString)
			if err != nil {
				return fmt.Errorf("invalid CIDR '%s': %w", cidrString, err)
			}
			allCIDRs = append(allCIDRs, cidr)
		}
	}

	// Coalesce CIDRs into minimum set needed for route rules
	// The routes set up here will be cleaned up by linuxrouting.Delete.
	// Therefor the code here should be kept in sync with the deletion code.
	ipv4CIDRs, ipv6CIDRs := ip.CoalesceCIDRs(allCIDRs)
	coalescedCIDRs := make([]string, 0, len(allCIDRs))
	for _, cidr := range ipv4CIDRs {
		coalescedCIDRs = append(coalescedCIDRs, cidr.String())
	}
	for _, cidr := range ipv6CIDRs {
		coalescedCIDRs = append(coalescedCIDRs, cidr.String())
	}

	routingInfo, err := linuxrouting.NewRoutingInfo(
		lo.Ternary(ipam != nil, ipam.Gateway, ""),
		lo.Ternary(ipamV6 != nil, ipamV6.Gateway, ""),
		coalescedCIDRs,
		ipam.MasterMac,
		ipam.InterfaceNumber,
		conf.IpamMode,
		conf.MasqueradeProtocols.IPV4,
		conf.MasqueradeProtocols.IPV6,
	)
	if err != nil {
		return fmt.Errorf("unable to parse routing info: %w", err)
	}

	if err := routingInfo.Configure(
		lo.Ternary(ipConfig != nil, ipConfig.Address.IP, nil),
		lo.Ternary(ipv6Config != nil, ipv6Config.Address.IP, nil),
		int(conf.DeviceMTU),
		conf.EgressMultiHomeIPRuleCompat,
		false,
	); err != nil {
		return fmt.Errorf("unable to install ip rules and routes: %w", err)
	}

	return nil
}
