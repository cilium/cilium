// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	corev1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
)

// GatewayClassConfig is the struct for GatewayClass parameters
// The struct is used to unmarshal the ConfigMap data
type GatewayClassConfig struct {
	// Service is the front-end service configuration for the GatewayClass
	// Normally, this is used to configure the LoadBalancer type service,
	// and mapped to k8s Service object
	Service *ServiceConfig `json:"service,omitempty"`
}

type ServiceConfig struct {
	// Type is the type of the service (e.g. LoadBalancer, NodePort, ClusterIP).
	// Defaults to LoadBalancer
	Type                          *string  `json:"type,omitempty"`
	ExternalTrafficPolicy         *string  `json:"externalTrafficPolicy,omitempty"`
	LoadBalancerClass             *string  `json:"loadBalancerClass,omitempty"`
	LoadBalancerSourceRanges      []string `json:"loadBalancerSourceRanges,omitempty"`
	IPFamilies                    []string `json:"ipFamilies,omitempty"`
	IPFamilyPolicy                *string  `json:"ipFamilyPolicy,omitempty"`
	AllocateLoadBalancerNodePorts *bool    `json:"allocateLoadBalancerNodePorts,omitempty"`
	TrafficDistribution           *string  `json:"trafficDistribution,omitempty"`
}

func toServiceModel(params *v2alpha1.CiliumGatewayClassConfig) *model.Service {
	if params == nil || params.Spec.Service == nil {
		return nil
	}

	res := &model.Service{
		Type: string(corev1.ServiceTypeLoadBalancer),
	}
	res.Type = string(params.Spec.Service.Type)
	res.ExternalTrafficPolicy = string(params.Spec.Service.ExternalTrafficPolicy)
	res.LoadBalancerClass = params.Spec.Service.LoadBalancerClass
	res.LoadBalancerSourceRanges = params.Spec.Service.LoadBalancerSourceRanges
	if len(params.Spec.Service.LoadBalancerSourceRangesPolicy) != 0 {
		res.LoadBalancerSourceRangesPolicy = string(params.Spec.Service.LoadBalancerSourceRangesPolicy)
	} else {
		// Defaults to allowed, same as default value in CRD
		res.LoadBalancerSourceRangesPolicy = string(v2alpha1.LoadBalancerSourceRangesPolicyAllow)
	}
	res.IPFamilies = toIPFamilies(params.Spec.Service.IPFamilies)
	res.IPFamilyPolicy = (*string)(params.Spec.Service.IPFamilyPolicy)
	res.AllocateLoadBalancerNodePorts = params.Spec.Service.AllocateLoadBalancerNodePorts
	res.TrafficDistribution = params.Spec.Service.TrafficDistribution

	return res
}

func toIPFamilies(families []corev1.IPFamily) []string {
	res := make([]string, 0, len(families))
	for _, family := range families {
		res = append(res, string(family))
	}
	return res
}
