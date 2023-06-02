// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package mock

import (
	"fmt"

	metallbbgp "go.universe.tf/metallb/pkg/bgp"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipam/types"
	"github.com/cilium/cilium/pkg/k8s"
	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodetypes "github.com/cilium/cilium/pkg/node/types"
)

// GenTestNodeAndAdvertisements generates a v1.Node with its
// ObjectMeta and PodCidr(s) fields hardcoded along with
// the MetalLB Advertisements that would be announced by
// this node.
//
// The returned Node's name is set to nodetypes.GetName()
// to simulate it being the node the Cilium agent is running on.
//
// See definition for details.
func GenTestNodeAndAdvertisements() (slim_corev1.Node, []*metallbbgp.Advertisement) {
	const (
		CIDR = "1.1.0.0/16"
	)
	meta := slim_metav1.ObjectMeta{
		Name:      nodetypes.GetName(),
		Namespace: "TestNamespace",
		Labels: map[string]string{
			"TestLabel": "TestLabel",
		},
		ResourceVersion: "1",
	}
	spec := slim_corev1.NodeSpec{
		PodCIDR:  CIDR,
		PodCIDRs: []string{CIDR},
	}
	node := slim_corev1.Node{
		ObjectMeta: meta,
		Spec:       spec,
	}
	advertisements := []*metallbbgp.Advertisement{
		{
			Prefix: cidr.MustParseCIDR(CIDR).IPNet,
		},
	}
	return node, advertisements
}

// GenTestCiliumNodeAndAdvertisements generates a ciliumv2.CiliumNode with
// numPodCIDRs podCIDRs and the corresponding MetalLB Advertisements that would
// be announced by this node.
//
// The returned Node's name is set to nodetypes.GetName()
// to simulate it being the node the Cilium agent is running on.
//
// See definition for details.
func GenTestCiliumNodeAndAdvertisements(numPodCIDRs int) (ciliumv2.CiliumNode, []*metallbbgp.Advertisement) {
	podCIDRs := make([]string, numPodCIDRs)
	for i := 0; i < numPodCIDRs; i++ {
		podCIDRs[i] = fmt.Sprintf("10.%d.0.0/16", i)
	}

	meta := metav1.ObjectMeta{
		Name: nodetypes.GetName(),
		Labels: map[string]string{
			"TestLabel": "TestLabel",
		},
		ResourceVersion: "1",
	}
	spec := ciliumv2.NodeSpec{
		IPAM: types.IPAMSpec{
			PodCIDRs: podCIDRs,
		},
	}
	node := ciliumv2.CiliumNode{
		ObjectMeta: meta,
		Spec:       spec,
	}

	advertisements := make([]*metallbbgp.Advertisement, 0, numPodCIDRs)
	for _, podCIDR := range podCIDRs {
		advertisements = append(advertisements, &metallbbgp.Advertisement{
			Prefix: cidr.MustParseCIDR(podCIDR).IPNet,
		})
	}
	return node, advertisements
}

// GenTestServicePairs generates a slim_corev1.Service and a hardcoded conversion
// to a metallbspr.Service and k8s v1.Service, along with a hardcoded conversion to a k8s.ServiceID.
//
// Since the conversion is hardcoded, the returned types are useful for testing
// any code which transforms one data structure to the another.
//
// See definition for details.
func GenTestServicePairs() (slim_corev1.Service, v1.Service, metallbspr.Service, k8s.ServiceID) {
	const (
		IP = "10.10.10.10"
	)
	spec := slim_corev1.ServiceSpec{
		Type:                  "TestType",
		ExternalTrafficPolicy: "TestExternalTrafficPolicy",
	}
	meta := slim_metav1.ObjectMeta{
		Name:            "TestName",
		Namespace:       "TestNamespace",
		ResourceVersion: "1",
	}
	ingress := []slim_corev1.LoadBalancerIngress{
		{
			IP: IP,
		},
	}
	lbStatus := slim_corev1.LoadBalancerStatus{
		Ingress: ingress,
	}
	status := slim_corev1.ServiceStatus{
		LoadBalancer: lbStatus,
	}
	service := slim_corev1.Service{
		Spec:       spec,
		Status:     status,
		ObjectMeta: meta,
	}
	metallbService := metallbspr.Service{
		Type:          string(spec.Type),
		TrafficPolicy: string(spec.ExternalTrafficPolicy),
		Ingress: []v1.LoadBalancerIngress{
			{
				IP: ingress[0].IP,
			},
		},
	}
	v1Service := v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:            meta.Name,
			Namespace:       meta.Namespace,
			ResourceVersion: "1",
		},
		Spec: v1.ServiceSpec{
			Type:                  "TestType",
			ExternalTrafficPolicy: "TestExternalTrafficPolicy",
		},
		Status: v1.ServiceStatus{
			LoadBalancer: v1.LoadBalancerStatus{
				Ingress: []v1.LoadBalancerIngress{
					{
						IP:    IP,
						Ports: nil,
					},
				},
			},
		},
	}
	serviceID := k8s.ServiceID{
		Name:      service.Name,
		Namespace: service.Namespace,
	}

	return service, v1Service, metallbService, serviceID
}

// GenTestEndpointsPair generates a k8s.Endpoints and a hardcoded conversion
// to a metallbspr.Endpoints, along with a hardoced conversion to slim_corev1.Endpoints.
//
// Since the conversion are hardcoded, the returned types are useful for testing
// any code which transforms one data structure to the other.
func GenTestEndpointsPairs() (k8s.Endpoints, slim_corev1.Endpoints, metallbspr.Endpoints) {
	const (
		IP       = "1.1.1.1"
		NodeName = "TestNode"
	)
	meta := slim_metav1.ObjectMeta{
		Name:            "TestName",
		Namespace:       "TestNamespace",
		ResourceVersion: "1",
	}
	backend := k8s.Backend{
		NodeName: NodeName,
	}
	backends := map[cmtypes.AddrCluster]*k8s.Backend{
		cmtypes.MustParseAddrCluster(IP): &backend,
	}
	endpoints := k8s.Endpoints{Backends: backends}
	slimEndpoints := slim_corev1.Endpoints{
		ObjectMeta: meta,
		Subsets: []slim_corev1.EndpointSubset{
			{
				Addresses: []slim_corev1.EndpointAddress{
					{IP: IP, NodeName: &(backend.NodeName)},
				},
			},
		},
	}
	metallbEndpoints := metallbspr.Endpoints{
		Ready: []metallbspr.Endpoint{
			{
				IP:       IP,
				NodeName: &(backend.NodeName),
			},
		},
	}
	return endpoints, slimEndpoints, metallbEndpoints
}
