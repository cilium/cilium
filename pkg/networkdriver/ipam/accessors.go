// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"github.com/cilium/cilium/pkg/ipam"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

var ResourceMultiPoolAccessor = ipam.PoolSpecAccessors{
	FromResource: func(node *ciliumv2.CiliumNode) ipamTypes.IPAMPoolSpec {
		return node.Spec.IPAM.ResourcePools
	},
	ToResource: func(node *ciliumv2.CiliumNode, spec ipamTypes.IPAMPoolSpec) bool {
		if node.Spec.IPAM.ResourcePools.DeepEqual(&spec) {
			return false
		}
		node.Spec.IPAM.ResourcePools = spec
		return true
	},
}
