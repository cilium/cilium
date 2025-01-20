// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

// ServiceSelector is a label selector for k8s services
type ServiceSelector EndpointSelector

// Service selects policy targets that are bundled as part of a
// logical load-balanced service.
//
// Currently only Kubernetes-based Services are supported.
type Service struct {
	// K8sServiceSelector selects services by k8s labels and namespace
	K8sServiceSelector *K8sServiceSelectorNamespace `json:"k8sServiceSelector,omitempty"`
	// K8sService selects service by name and namespace pair
	K8sService *K8sServiceNamespace `json:"k8sService,omitempty"`
}

// K8sServiceNamespace selects services by name and, optionally, namespace.
type K8sServiceNamespace struct {
	ServiceName string `json:"serviceName,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

// K8sServiceSelectorNamespace selects services by labels.
type K8sServiceSelectorNamespace struct {
	// +kubebuilder:validation:Required
	Selector  ServiceSelector `json:"selector"`
	Namespace string          `json:"namespace,omitempty"`
}
