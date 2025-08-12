/*
Copyright 2020 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package v1alpha2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// UDPRoute provides a way to route UDP traffic. When combined with a Gateway
// listener, it can be used to forward traffic on the port specified by the
// listener to a set of backends specified by the UDPRoute.
type UDPRoute struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of UDPRoute.
	// +required
	Spec UDPRouteSpec `json:"spec"`

	// Status defines the current state of UDPRoute.
	// +optional
	Status UDPRouteStatus `json:"status,omitempty"`
}

// UDPRouteSpec defines the desired state of UDPRoute.
type UDPRouteSpec struct {
	CommonRouteSpec `json:",inline"`

	// Rules are a list of UDP matchers and actions.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// <gateway:experimental:validation:XValidation:message="Rule name must be unique within the route",rule="self.all(l1, !has(l1.name) || self.exists_one(l2, has(l2.name) && l1.name == l2.name))">
	Rules []UDPRouteRule `json:"rules"`
}

// UDPRouteStatus defines the observed state of UDPRoute.
type UDPRouteStatus struct {
	RouteStatus `json:",inline"`
}

// UDPRouteRule is the configuration for a given rule.
type UDPRouteRule struct {
	// Name is the name of the route rule. This name MUST be unique within a Route if it is set.
	//
	// Support: Extended
	// +optional
	Name *SectionName `json:"name,omitempty"`

	// BackendRefs defines the backend(s) where matching requests should be
	// sent. If unspecified or invalid (refers to a nonexistent resource or a
	// Service with no endpoints), the underlying implementation MUST actively
	// reject connection attempts to this backend. Packet drops must
	// respect weight; if an invalid backend is requested to have 80% of
	// the packets, then 80% of packets must be dropped instead.
	//
	// Support: Core for Kubernetes Service
	//
	// Support: Extended for Kubernetes ServiceImport
	//
	// Support: Implementation-specific for any other resource
	//
	// Support for weight: Extended
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	BackendRefs []BackendRef `json:"backendRefs,omitempty"`
}

// +kubebuilder:object:root=true

// UDPRouteList contains a list of UDPRoute
type UDPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []UDPRoute `json:"items"`
}
