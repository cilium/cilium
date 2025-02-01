// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ingestion

import (
	corev1 "k8s.io/api/core/v1"
	k8syaml "sigs.k8s.io/yaml"

	"github.com/cilium/cilium/operator/pkg/model"
)

const (
	serviceConfigKey = "service"
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
	Type *string `json:"type,omitempty"`
}

func toServiceModel(params *GatewayClassConfig) *model.Service {
	if params == nil || params.Service == nil {
		return nil
	}

	res := &model.Service{
		Type: string(corev1.ServiceTypeLoadBalancer),
	}

	if params.Service.Type != nil {
		res.Type = *params.Service.Type
	}
	return res
}

func unmarshalGatewayClassConfig(configMap *corev1.ConfigMap) *GatewayClassConfig {
	if configMap == nil {
		return nil
	}

	sParam := &ServiceConfig{}
	err := k8syaml.Unmarshal([]byte(configMap.Data[serviceConfigKey]), sParam)
	if err != nil {
		return nil
	}
	return &GatewayClassConfig{
		Service: sParam,
	}
}
