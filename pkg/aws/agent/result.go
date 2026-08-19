// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipmasq"
	"github.com/cilium/cilium/pkg/option"
)

// allocationResult derives ENI-specific AllocationResult metadata
// (PrimaryMAC, GatewayIP, VPC CIDRs, InterfaceNumber) by finding which ENI
// owns the given IP.
func allocationResult(
	logger *slog.Logger,
	allocatedAddr netip.Addr,
	pool ipam.Pool,
	enis map[string]awsTypes.ENI,
	conf *option.DaemonConfig,
	ipMasqAgent *ipmasq.IPMasqAgent,
) (*ipam.AllocationResult, error) {
	for _, eni := range enis {
		if !eniContainsIP(eni, allocatedAddr) {
			continue
		}

		result := &ipam.AllocationResult{
			IP:         allocatedAddr,
			IPPoolName: pool,
			PrimaryMAC: eni.MAC,
		}
		if eni.VPC.PrimaryCIDR.IsValid() {
			result.CIDRs = append(result.CIDRs, eni.VPC.PrimaryCIDR.Prefix)
		}
		for _, c := range eni.VPC.CIDRs {
			if c.IsValid() {
				result.CIDRs = append(result.CIDRs, c.Prefix)
			}
		}

		// Add manually configured Native Routing CIDR
		if conf.IPv4NativeRoutingCIDR.IsValid() && conf.EnableIPv4 {
			result.CIDRs = append(result.CIDRs, conf.IPv4NativeRoutingCIDR)
		}
		if conf.IPv6NativeRoutingCIDR.IsValid() && conf.EnableIPv6 {
			result.CIDRs = append(result.CIDRs, conf.IPv6NativeRoutingCIDR)
		}

		// If the ip-masq-agent is enabled, get the CIDRs that are not masqueraded.
		// Note that the resulting ip rules will not be dynamically regenerated if the
		// ip-masq-agent configuration changes.
		if conf.EnableIPMasqAgent {
			for _, prefix := range ipMasqAgent.NonMasqCIDRsFromConfig() {
				if allocatedAddr.Is4() && prefix.Addr().Is4() {
					result.CIDRs = append(result.CIDRs, prefix)
				} else if !allocatedAddr.Is4() && prefix.Addr().Is6() {
					result.CIDRs = append(result.CIDRs, prefix)
				}
			}
		}

		if allocatedAddr.Is4() {
			if eni.Subnet.CIDR.IsValid() {
				// AWS reserves the first subnet IP for the gateway.
				// Ref: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_Route_Tables.html
				result.GatewayIP = eni.Subnet.CIDR.Addr().Next()
			}
		} else {
			// On AWS/VPC, the subnet gateway can always be reached at FE80:EC2::1
			// https://aws.amazon.com/about-aws/whats-new/2022/11/ipv6-subnet-default-gateway-router-multiple-addresses/
			result.GatewayIP = netip.MustParseAddr("fe80:ec2::1")
		}
		result.InterfaceNumber = strconv.Itoa(eni.Number)

		return result, nil
	}

	return nil, fmt.Errorf("unable to find ENI for IP %s", allocatedAddr)
}

// eniContainsIP returns true if the given IP belongs to the ENI: either as the
// primary IP, a secondary address, or within one of its delegated prefixes.
func eniContainsIP(eni awsTypes.ENI, addr netip.Addr) bool {
	if eni.IP.Addr == addr {
		return true
	}
	if slices.ContainsFunc(eni.Addresses, func(a iputil.Addr) bool { return a.Addr == addr }) {
		return true
	}

	for _, prefix := range slices.Concat(eni.Prefixes, eni.IPv6Prefixes) {
		if !prefix.IsValid() {
			continue
		}
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
