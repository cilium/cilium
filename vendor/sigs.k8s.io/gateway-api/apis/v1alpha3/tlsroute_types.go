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

package v1alpha3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// The TLSRoute resource is similar to TCPRoute, but can be configured
// to match against TLS-specific metadata. This allows more flexibility
// in matching streams for a given TLS listener.
//
// If you need to forward traffic to a single target for a TLS listener, you
// could choose to use a TCPRoute with a TLS listener.
type TLSRoute struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of TLSRoute.
	// +required
	Spec TLSRouteSpec `json:"spec"`

	// Status defines the current state of TLSRoute.
	// +optional
	Status v1alpha2.TLSRouteStatus `json:"status,omitempty"`
}

// TLSRouteSpec defines the desired state of a TLSRoute resource.
type TLSRouteSpec struct {
	CommonRouteSpec `json:",inline"`

	// Hostnames defines a set of SNI hostnames that should match against the
	// SNI attribute of TLS ClientHello message in TLS handshake. This matches
	// the RFC 1123 definition of a hostname with 2 notable exceptions:
	//
	// 1. IPs are not allowed in SNI hostnames per RFC 6066.
	// 2. A hostname may be prefixed with a wildcard label (`*.`). The wildcard
	//    label must appear by itself as the first label.
	//
	// If a hostname is specified by both the Listener and TLSRoute, there
	// must be at least one intersecting hostname for the TLSRoute to be
	// attached to the Listener. For example:
	//
	// * A Listener with `test.example.com` as the hostname matches TLSRoutes
	//   that have specified at least one of `test.example.com` or
	//   `*.example.com`.
	// * A Listener with `*.example.com` as the hostname matches TLSRoutes
	//   that have specified at least one hostname that matches the Listener
	//   hostname. For example, `test.example.com` and `*.example.com` would both
	//   match. On the other hand, `example.com` and `test.example.net` would not
	//   match.
	//
	// If both the Listener and TLSRoute have specified hostnames, any
	// TLSRoute hostnames that do not match the Listener hostname MUST be
	// ignored. For example, if a Listener specified `*.example.com`, and the
	// TLSRoute specified `test.example.com` and `test.example.net`,
	// `test.example.net` must not be considered for a match.
	//
	// If both the Listener and TLSRoute have specified hostnames, and none
	// match with the criteria above, then the TLSRoute is not accepted. The
	// implementation must raise an 'Accepted' Condition with a status of
	// `False` in the corresponding RouteParentStatus.
	//
	// Support: Core
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of actions.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	// <gateway:experimental:validation:XValidation:message="Rule name must be unique within the route",rule="self.all(l1, !has(l1.name) || self.exists_one(l2, has(l2.name) && l1.name == l2.name))">
	Rules []v1alpha2.TLSRouteRule `json:"rules,omitempty"`
}

// +kubebuilder:object:root=true

// TLSRouteList contains a list of TLSRoute
type TLSRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSRoute `json:"items"`
}
