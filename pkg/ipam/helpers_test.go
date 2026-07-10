// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
)

func newCiliumNode(node string, preAllocate, minAllocate, used int) *v2.CiliumNode {
	cn := &v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{Name: node, Namespace: "default"},
		Spec: v2.NodeSpec{
			IPAM: ipamTypes.IPAMSpec{
				Pool:        ipamTypes.AllocationMap{},
				PreAllocate: preAllocate,
				MinAllocate: minAllocate,
			},
		},
		Status: v2.NodeStatus{
			IPAM: ipamTypes.IPAMStatus{
				Used:       ipamTypes.AllocationMap{},
				ReleaseIPs: map[string]ipamTypes.IPReleaseStatus{},
			},
		},
	}

	updateCiliumNode(cn, used)

	return cn
}

func updateCiliumNode(cn *v2.CiliumNode, used int) *v2.CiliumNode {
	cn.Spec.IPAM.Pool = ipamTypes.AllocationMap{}
	for i := 1; i <= used; i++ {
		cn.Spec.IPAM.Pool[fmt.Sprintf("1.1.1.%d", i)] = ipamTypes.AllocationIP{Resource: "foo"}
	}

	cn.Status.IPAM.Used = ipamTypes.AllocationMap{}
	for ip, ipAllocation := range cn.Spec.IPAM.Pool {
		if used > 0 {
			delete(cn.Spec.IPAM.Pool, ip)
			cn.Status.IPAM.Used[ip] = ipAllocation
			used--
		}
	}

	return cn
}
