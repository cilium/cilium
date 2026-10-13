// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"fmt"
	"net/netip"
	"slices"
	"strconv"

	awsTypes "github.com/cilium/cilium/pkg/aws/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
)

// allocationResult derives ENI-specific AllocationResult metadata
// (PrimaryMAC, GatewayIP, InterfaceNumber) by finding which ENI owns the given
// IP.
func allocationResult(
	allocatedAddr netip.Addr,
	pool ipam.Pool,
	enis map[string]awsTypes.ENI,
) (*ipam.AllocationResult, error) {
	if pool == ipam.Pool(defaults.IPAMIPv4EgressPool) {
		return egressAllocationResult(allocatedAddr, pool, enis)
	}

	for _, eni := range enis {
		if !eniContainsIP(eni, allocatedAddr) {
			continue
		}

		result := &ipam.AllocationResult{
			IP:         allocatedAddr,
			IPPoolName: pool,
			PrimaryMAC: eni.MAC,
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

// egressAllocationResult routes an IPv4 egress-only address through the
// primary ENI. Such addresses belong to no ENI: they are masqueraded behind the
// IPv4 address of the interface they leave the node through, so that interface
// must be the one carrying the node IPv4 address. A secondary ENI might only
// hold IPv6 prefixes.
func egressAllocationResult(
	allocatedAddr netip.Addr,
	pool ipam.Pool,
	enis map[string]awsTypes.ENI,
) (*ipam.AllocationResult, error) {
	if !allocatedAddr.Is4() {
		return nil, fmt.Errorf("unexpected IPv6 address %s in the IPv4 egress pool", allocatedAddr)
	}

	for _, eni := range enis {
		if eni.Number != 0 {
			continue
		}
		if !eni.Subnet.CIDR.IsValid() || !eni.Subnet.CIDR.Addr().Is4() {
			return nil, fmt.Errorf("primary ENI %s is not in a subnet with IPv4: IPv4 egress-only mode requires a dual-stack subnet", eni.ID)
		}

		return &ipam.AllocationResult{
			IP:         allocatedAddr,
			IPPoolName: pool,
			PrimaryMAC: eni.MAC,
			// AWS reserves the first subnet IP for the gateway.
			GatewayIP:       eni.Subnet.CIDR.Addr().Next(),
			InterfaceNumber: strconv.Itoa(eni.Number),
		}, nil
	}

	return nil, fmt.Errorf("unable to find the primary ENI to route IPv4 egress address %s", allocatedAddr)
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
