// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package test

import (
	"net/netip"

	ipam_types "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	v2alpha1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_meta_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var (
	// uid is static ID used in tests
	uid = types.UID("610a54cf-e0e5-4dc6-ace9-0e6ca9a4aaae")
)

// policyConfig data used to create CiliumBGPPeeringPolicy
type policyConfig struct {
	nodeSelector   map[string]slim_meta_v1.MatchLabelsValue
	virtualRouters []v2alpha1.CiliumBGPVirtualRouter
}

// newPolicyObj created CiliumBGPPeeringPolicy based on passed policy config
func newPolicyObj(conf policyConfig) v2alpha1.CiliumBGPPeeringPolicy {
	policyObj := v2alpha1.CiliumBGPPeeringPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "policy-1",
			UID:               uid,
			CreationTimestamp: metav1.Now(),
		},
	}

	if conf.nodeSelector != nil {
		policyObj.Spec.NodeSelector = &slim_meta_v1.LabelSelector{
			MatchLabels: conf.nodeSelector,
		}
	}

	if conf.virtualRouters != nil {
		policyObj.Spec.VirtualRouters = conf.virtualRouters
	}

	return policyObj
}

// lbSrvConfig contains lb service configuration data
type lbSrvConfig struct {
	name      string
	ingressIP string
}

// newLBServiceObj creates slim_core_v1.Service object based on lbSrvConfig
func newLBServiceObj(conf lbSrvConfig) slim_core_v1.Service {
	srvObj := slim_core_v1.Service{
		ObjectMeta: slim_meta_v1.ObjectMeta{
			Name: conf.name,
		},
		Spec: slim_core_v1.ServiceSpec{
			Type: slim_core_v1.ServiceTypeLoadBalancer,
		},
	}

	srvObj.Status = slim_core_v1.ServiceStatus{
		LoadBalancer: slim_core_v1.LoadBalancerStatus{
			Ingress: []slim_core_v1.LoadBalancerIngress{{IP: conf.ingressIP}},
		},
	}

	return srvObj
}

// lbSrvConfig contains lb service configuration data
type lbPoolConfig struct {
	name   string
	labels map[string]string
	cidrs  []string
}

// newLBPoolObj creates CiliumLoadBalancerIPPool object based on lbSrvConfig
func newLBPoolObj(conf lbPoolConfig) v2alpha1.CiliumLoadBalancerIPPool {
	obj := v2alpha1.CiliumLoadBalancerIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:              conf.name,
			UID:               uid,
			CreationTimestamp: metav1.Now(),
			Labels:            make(map[string]string),
		},
	}
	if conf.labels != nil {
		obj.Labels = conf.labels
	}
	for _, cidr := range conf.cidrs {
		obj.Spec.Cidrs = append(obj.Spec.Cidrs, v2alpha1.CiliumLoadBalancerIPPoolIPBlock{Cidr: v2alpha1.IPv4orIPv6CIDR(cidr)})
	}
	return obj
}

// ipPoolConfig data used to create a CiliumPodIPPool resource.
type ipPoolConfig struct {
	name   string
	cidrs  []ipam_types.IPAMPodCIDR
	labels map[string]string
}

// newIPPoolObj creates a CiliumPodIPPool resource based on the provided conf.
func newIPPoolObj(conf ipPoolConfig) *v2alpha1.CiliumPodIPPool {
	obj := &v2alpha1.CiliumPodIPPool{
		ObjectMeta: metav1.ObjectMeta{
			Name:              conf.name,
			UID:               uid,
			CreationTimestamp: metav1.Now(),
			Labels:            make(map[string]string),
		},
		Spec: v2alpha1.IPPoolSpec{
			IPv4: &v2alpha1.IPv4PoolSpec{
				CIDRs:    []v2alpha1.PoolCIDR{},
				MaskSize: 24,
			},
			IPv6: &v2alpha1.IPv6PoolSpec{
				CIDRs:    []v2alpha1.PoolCIDR{},
				MaskSize: 64,
			},
		},
	}

	if conf.labels != nil {
		obj.Labels = conf.labels
	}

	for _, cidr := range conf.cidrs {
		if p := netip.MustParsePrefix(string(cidr)); p.Addr().Is4() {
			obj.Spec.IPv4.CIDRs = append(obj.Spec.IPv4.CIDRs, v2alpha1.PoolCIDR(cidr))
		}
		if p := netip.MustParsePrefix(string(cidr)); p.Addr().Is6() {
			obj.Spec.IPv6.CIDRs = append(obj.Spec.IPv6.CIDRs, v2alpha1.PoolCIDR(cidr))
		}
	}

	return obj
}

// ciliumNodeConfig data used to create a CiliumNode resource.
type ciliumNodeConfig struct {
	name        string
	labels      map[string]string
	annotations map[string]string
	ipamAllocs  map[string][]string
}

// newCiliumNode creates a CiliumNode resource based on the provided conf.
func newCiliumNode(conf ciliumNodeConfig) v2.CiliumNode {
	obj := v2.CiliumNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:              conf.name,
			UID:               uid,
			CreationTimestamp: metav1.Now(),
		},
	}

	if conf.labels != nil {
		obj.Labels = conf.labels
	}

	if conf.annotations != nil {
		obj.Annotations = conf.annotations
	}

	if conf.ipamAllocs != nil {
		var allocs []ipam_types.IPAMPoolAllocation
		for pool, cidrs := range conf.ipamAllocs {
			poolCIDRs := []ipam_types.IPAMPodCIDR{}
			for _, c := range cidrs {
				poolCIDRs = append(poolCIDRs, ipam_types.IPAMPodCIDR(c))
			}
			alloc := ipam_types.IPAMPoolAllocation{
				Pool:  pool,
				CIDRs: poolCIDRs,
			}
			allocs = append(allocs, alloc)
		}
		obj.Spec.IPAM.Pools.Allocated = allocs
	}

	return obj
}
