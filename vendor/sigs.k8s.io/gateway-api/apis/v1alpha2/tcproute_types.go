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

	v1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:deprecatedversion:warning="The v1alpha2 version of TCPRoute has been deprecated and will be removed in a future release of the API. Please upgrade to v1."

// TCPRoute provides a way to route TCP requests. When combined with a Gateway
// listener, it can be used to forward connections on the port specified by the
// listener to a set of backends specified by the TCPRoute.
type TCPRoute struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of TCPRoute.
	// +required
	Spec TCPRouteSpec `json:"spec"`

	// Status defines the current state of TCPRoute.
	// +optional
	Status TCPRouteStatus `json:"status,omitempty"`
}

// TCPRouteSpec defines the desired state of TCPRoute
type TCPRouteSpec struct {
	CommonRouteSpec `json:",inline"`

	// Rules are a list of TCP matchers and actions.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// <gateway:experimental:validation:XValidation:message="Rule name must be unique within the route",rule="self.all(l1, !has(l1.name) || self.exists_one(l2, has(l2.name) && l1.name == l2.name))">
	Rules []TCPRouteRule `json:"rules,omitempty"`
}

// TCPRouteStatus defines the observed state of TCPRoute
type TCPRouteStatus v1.TCPRouteStatus

// TCPRouteRule is the configuration for a given rule.
type TCPRouteRule v1.TCPRouteRule

// +kubebuilder:object:root=true

// TCPRouteList contains a list of TCPRoute
type TCPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TCPRoute `json:"items"`
}
