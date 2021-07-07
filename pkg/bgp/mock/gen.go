// Copyright 2016-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mock

import (
	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/k8s"
	slim_corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	nodetypes "github.com/cilium/cilium/pkg/node/types"

	metallbbgp "go.universe.tf/metallb/pkg/bgp"
	metallbspr "go.universe.tf/metallb/pkg/speaker"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// GenTestNodeAndAdvertisements generates a v1.Node with its
// ObjectMeta and PodCidr(s) fields hardcoded along with
// the MetalLB Advertisements that would be announced by
// this node.
//
// The returned Node's name is set to nodetypes.GetName()
//
// See definition for details.
func GenTestNodeAndAdvertisements() (v1.Node, []*metallbbgp.Advertisement) {
	const (
		CIDR = "1.1.0.0/16"
	)
	meta := metav1.ObjectMeta{
		Name:      nodetypes.GetName(),
		Namespace: "TestNamespace",
		Labels: map[string]string{
			"TestLabel": "TestLabel",
		},
	}
	spec := v1.NodeSpec{
		PodCIDR:  CIDR,
		PodCIDRs: []string{CIDR},
	}
	node := v1.Node{
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

// GenTestServicePair generates a slim_corev1.Service and a hardcoded conversion
// to a metallbspr.Service, along with a hardcoded k8s.ServiceID.
//
// Since the conversion is hardcoded, the returned types are useful for testing
// any code which transforms one data structure to the another.
func GenTestServicePair() (slim_corev1.Service, metallbspr.Service, k8s.ServiceID) {
	spec := slim_corev1.ServiceSpec{
		Type:                  "TestType",
		ExternalTrafficPolicy: "TestExternalTrafficPolicy",
	}
	meta := slim_metav1.ObjectMeta{
		Name:      "TestName",
		Namespace: "TestNamespace",
	}
	ingress := []slim_corev1.LoadBalancerIngress{
		{
			IP: "10.10.10.10",
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
	serviceID := k8s.ServiceID{
		Name:      service.Name,
		Namespace: service.Namespace,
	}
	return service, metallbService, serviceID
}

// GenTestEndpointsPair generates a k8s.Endpoints and a hardcoded conversion
// to a metallbspr.Endpoints, along with a hardoced k8s.Backend.
//
// Since the conversion are hardcoded, the returned types are useful for testing
// any code which transforms one data structure to the other.
func GenTestEndpointsPairs() (k8s.Endpoints, slim_corev1.Endpoints, metallbspr.Endpoints, k8s.Backend) {
	const (
		IP       = "1.1.1.1"
		NodeName = "TestNode"
	)
	meta := slim_metav1.ObjectMeta{
		Name:      "TestName",
		Namespace: "TestNamespace",
	}
	backend := k8s.Backend{
		NodeName: NodeName,
	}
	backends := map[string]*k8s.Backend{
		IP: &backend,
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
	return endpoints, slimEndpoints, metallbEndpoints, backend
}
