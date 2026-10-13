// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

// SinglePoolAccessor returns accessors restricting a NodeHandler to the given
// pool, for when it shares Spec.IPAM.Pools with another allocator.
//
// The requests and allocations of the other pools are neither read, which
// would make the PoolAllocator treat their CIDRs as orphans, nor written back,
// which would drop them from the CiliumNode.
func SinglePoolAccessor(pool string) ipam.PoolSpecAccessors {
	return ipam.PoolSpecAccessors{
		FromResource: func(cn *v2.CiliumNode) types.IPAMPoolSpec {
			var spec types.IPAMPoolSpec
			for _, req := range cn.Spec.IPAM.Pools.Requested {
				if req.Pool == pool {
					spec.Requested = append(spec.Requested, req)
				}
			}
			for _, alloc := range cn.Spec.IPAM.Pools.Allocated {
				if alloc.Pool == pool {
					spec.Allocated = append(spec.Allocated, alloc)
				}
			}
			return spec
		},
		ToResource: func(cn *v2.CiliumNode, spec types.IPAMPoolSpec) bool {
			newSpec := types.IPAMPoolSpec{
				Requested: replacePoolEntries(cn.Spec.IPAM.Pools.Requested, spec.Requested, pool,
					func(r types.IPAMPoolRequest) string { return r.Pool }),
				Allocated: replacePoolEntries(cn.Spec.IPAM.Pools.Allocated, spec.Allocated, pool,
					func(a types.IPAMPoolAllocation) string { return a.Pool }),
			}
			if cn.Spec.IPAM.Pools.DeepEqual(&newSpec) {
				return false
			}
			cn.Spec.IPAM.Pools = newSpec
			return true
		},
	}
}

// replacePoolEntries returns entries with those of pool replaced by the ones
// of replacement that belong to pool. The replacement takes the position of
// the first entry it replaces, or is appended if there is none.
func replacePoolEntries[T any](entries, replacement []T, pool string, poolOf func(T) string) []T {
	var own []T
	for _, e := range replacement {
		if poolOf(e) == pool {
			own = append(own, e)
		}
	}

	var result []T
	replaced := false
	for _, e := range entries {
		if poolOf(e) != pool {
			result = append(result, e)
		} else if !replaced {
			result = append(result, own...)
			replaced = true
		}
	}
	if !replaced {
		result = append(result, own...)
	}
	return result
}
