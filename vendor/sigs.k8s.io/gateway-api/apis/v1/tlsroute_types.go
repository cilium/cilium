/*
Copyright The Kubernetes Authors.

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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
	Status TLSRouteStatus `json:"status,omitempty"`
}

// TLSRouteSpec defines the expected behavior of a TLSRoute.
// A TLSRoute MUST be attached to a Listener of protocol TLS.
// Core: The listener CAN be of type Passthrough
// Extended: The listener CAN be of type Terminate
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
	// <gateway:util:excludeFromCRD>
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
	// * A listener with `something.example.com` as the hostname matches a
	//   TLSRoute with hostname `*.example.com`.
	//
	// If both the Listener and TLSRoute have specified hostnames, any
	// TLSRoute hostnames that do not match any Listener hostname MUST be
	// ignored. For example, if a Listener specified `*.example.com`, and the
	// TLSRoute specified `test.example.com` and `test.example.net`,
	// `test.example.net` must not be considered for a match.
	//
	// If both the Listener and TLSRoute have specified hostnames, and none
	// match with the criteria above, then the TLSRoute is not accepted for that
	// Listener. If the TLSRoute does not match any Listener on its parent, the
	// implementation must raise an 'Accepted' Condition with a status of
	// `False` in the corresponding RouteParentStatus.
	//
	// A Listener MUST be have protocol set to TLS when a TLSRoute attaches to it. The
	// implementation MUST raise an 'Accepted' Condition with a status of
	// `False` in the corresponding RouteParentStatus with the reason
	// of "UnsupportedValue" in case a Listener of the wrong type is used.
	// Core: Listener with `protocol` `TLS` and `tls.mode` `Passthrough`.
	// Extended: Listener with `protocol` `TLS` and `tls.mode` `Terminate`. The feature name for this Extended feature is `TLSRouteTermination`.
	// </gateway:util:excludeFromCRD>
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="Hostnames cannot contain an IP",rule="self.all(h, !isIP(h))"
	// +kubebuilder:validation:XValidation:message="Hostnames must be valid based on RFC-1123",rule="self.all(h, !h.contains('*') ? h.matches('^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\\\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)$') : true)"
	// +kubebuilder:validation:XValidation:message="Wildcards on hostnames must be the first label, and the rest of hostname must be valid based on RFC-1123",rule="self.all(h, h.contains('*') ? (h.startsWith('*.') && h.substring(2).matches('^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\\\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*)$')) : true)"
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of actions.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=1
	Rules []TLSRouteRule `json:"rules,omitempty"`
}

// TLSRouteStatus defines the observed state of TLSRoute
type TLSRouteStatus struct {
	RouteStatus `json:",inline"`
}

// TLSRouteRule is the configuration for a given rule.
type TLSRouteRule struct {
	// Name is the name of the route rule. This name MUST be unique within a Route if it is set.
	//
	// +optional
	Name *SectionName `json:"name,omitempty"`

	// BackendRefs defines the backend(s) where matching requests should be
	// sent. If unspecified or invalid (refers to a nonexistent resource or
	// a Service with no endpoints), the rule performs no forwarding; if no
	// filters are specified that would result in a response being sent, the
	// underlying implementation must actively reject request attempts to this
	// backend, by rejecting the connection. Request rejections must respect
	// weight; if an invalid backend is requested to have 80% of requests, then
	// 80% of requests must be rejected instead.
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

// TLSRouteList contains a list of TLSRoute
type TLSRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TLSRoute `json:"items"`
}
