// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var poolAccessor = ipam.PoolSpecAccessors{
	// FromResource returns the pool specification.
	// Unlike the standard multi-pool mode which reads Allocated CIDRs from
	// Spec.IPAM.Pools.Allocated, ENI mode derives them from Status.ENI.ENIs
	// which is maintained by the operator. This allows the agent to be the
	// sole writer of Spec.IPAM.Pools.Allocated while reading CIDRs from a
	// different source.
	//
	// Secondary IPs are represented as host-prefix CIDRs (/32 for IPv4, /128 for
	// IPv6) and delegated prefixes as /28 CIDRs for IPv4 and /80 CIDRs for IPv6.
	FromResource: func(node *ciliumv2.CiliumNode) ipamTypes.IPAMPoolSpec {
		pools := ipamTypes.IPAMPoolSpec{
			Requested: node.Spec.IPAM.Pools.Requested,
			Allocated: node.Spec.IPAM.Pools.Allocated,
		}

		if len(node.Status.ENI.ENIs) == 0 {
			return pools
		}

		var cidrs []iputil.Prefix
		for _, eni := range node.Status.ENI.ENIs {
			if eni.IsExcludedBySpec(node.Spec.ENI) {
				continue
			}

			var prefixes []netip.Prefix
			for _, p := range eni.Prefixes {
				cidrs = append(cidrs, p)
				if p.IsValid() {
					prefixes = append(prefixes, p.Prefix)
				}
			}

			cidrs = append(cidrs, eni.IPv6Prefixes...)

			// In parseENI (pkg/aws/api), we currently use PrefixToIps to flatten each prefixes
			// into 16 individual IPs and append those IPs to the ENI Addresses field.
			// Here we need to apply a reverse logic to only advertise as /32 CIDRs in the pool
			// regular secondary addresses (or the ENI primary IP when using UsePrimaryAddress)
			// and not addresses that are already being advertised through a /28 CIDR.
			for _, addr := range eni.Addresses {
				if !addr.IsValid() {
					continue
				}
				if addressCoveredByPrefix(addr.Addr, prefixes) {
					continue
				}
				cidrs = append(cidrs, iputil.PrefixFrom(netip.PrefixFrom(addr.Addr, addr.BitLen())))
			}
		}

		if len(cidrs) > 0 {
			pools.Allocated = []ipamTypes.IPAMPoolAllocation{
				{
					Pool:         defaults.IPAMDefaultIPPool,
					AllowFirstIP: true,
					AllowLastIP:  true,
					CIDRs:        cidrs,
				},
			}
		}

		return pools
	},
	ToResource: func(node *ciliumv2.CiliumNode, spec ipamTypes.IPAMPoolSpec) bool {
		if !node.Spec.IPAM.Pools.DeepEqual(&spec) {
			node.Spec.IPAM.Pools = spec
			return true
		}
		return false
	},
}

// addressCoveredByPrefix returns true if the given IP address falls
// within any of the provided prefixes.
func addressCoveredByPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
