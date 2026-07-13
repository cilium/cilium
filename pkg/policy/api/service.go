// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

// ServiceSelector is a label selector for k8s services
type ServiceSelector EndpointSelector

// Validate the underlying LabelSelector.
func (s *ServiceSelector) Validate() error {
	return (*EndpointSelector)(s).Validate()
}

// Sanitize the EndpointSelector.
func (s *ServiceSelector) Sanitize() {
	(*EndpointSelector)(s).Sanitize()
}

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

func (s *Service) Validate() error {
	if s.K8sServiceSelector != nil {
		if err := s.K8sServiceSelector.Selector.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) Sanitize() {
	if s.K8sServiceSelector != nil {
		s.K8sServiceSelector.Selector.Sanitize()
	}
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
