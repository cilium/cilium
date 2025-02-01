// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/operator/pkg/model"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
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
	Type                  *string `json:"type,omitempty"`
	ExternalTrafficPolicy *string `json:"externalTrafficPolicy,omitempty"`
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

	return res
}
