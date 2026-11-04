// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package agent

import (
	"net/netip"
	"slices"

	alibabaCloudTypes "github.com/cilium/cilium/pkg/alibabacloud/types"
	"github.com/cilium/cilium/pkg/defaults"
	iputil "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var poolAccessor = ipam.PoolSpecAccessors{
	FromResource: func(node *ciliumv2.CiliumNode) ipamTypes.IPAMPoolSpec {
		pools := ipamTypes.IPAMPoolSpec{
			Requested: node.Spec.IPAM.Pools.Requested,
			Allocated: node.Spec.IPAM.Pools.Allocated,
		}

		if len(node.Status.AlibabaCloud.ENIs) == 0 {
			return pools
		}

		var cidrs []iputil.Prefix
		for _, eni := range node.Status.AlibabaCloud.ENIs {
			// The primary interface belongs to the host. All addresses on
			// other ENIs, including their primary address, are allocatable.
			if eni.Type == alibabaCloudTypes.ENITypePrimary {
				continue
			}
			for _, address := range eni.PrivateIPSets {
				if !address.PrivateIpAddress.Is4() {
					continue
				}
				prefix := netip.PrefixFrom(address.PrivateIpAddress.Addr, 32)
				cidrs = append(cidrs, iputil.PrefixFrom(prefix))
			}
		}

		slices.SortFunc(cidrs, func(a, b iputil.Prefix) int {
			if c := a.Addr().Compare(b.Addr()); c != 0 {
				return c
			}
			return a.Bits() - b.Bits()
		})
		pools.Allocated = []ipamTypes.IPAMPoolAllocation{
			{
				Pool:         defaults.IPAMDefaultIPPool,
				AllowFirstIP: true,
				AllowLastIP:  true,
				CIDRs:        cidrs,
			},
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
