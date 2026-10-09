// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package nodediscovery

import (
	"github.com/cilium/cilium/pkg/defaults"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// SeedPoolRequest writes an initial demand for the default pool, unless one
// is already present. It is meant for cloud IPAM modes, whose agents use the
// cloud multi-pool allocator.
func SeedPoolRequest(spec *ciliumv2.NodeSpec, ipv4Enabled, ipv6Enabled bool) {
	for _, req := range spec.IPAM.Pools.Requested {
		if req.Pool == defaults.IPAMDefaultIPPool {
			return
		}
	}

	preAllocate := spec.IPAM.PreAllocate
	if preAllocate == 0 {
		preAllocate = defaults.IPAMPreAllocation
	}

	var demand ipamTypes.IPAMPoolDemand
	if ipv4Enabled {
		demand.IPv4Addrs = preAllocate
	}
	if ipv6Enabled {
		demand.IPv6Addrs = preAllocate
	}
	if demand.IPv4Addrs == 0 && demand.IPv6Addrs == 0 {
		return
	}

	spec.IPAM.Pools.Requested = append(spec.IPAM.Pools.Requested, ipamTypes.IPAMPoolRequest{
		Pool:   defaults.IPAMDefaultIPPool,
		Needed: demand,
	})
}
