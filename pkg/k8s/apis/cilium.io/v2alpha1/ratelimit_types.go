// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1alpha2 "sigs.k8s.io/gateway-api/apis/v1alpha2"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories={cilium},shortName=clrp
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// CiliumRateLimitPolicy is a high-performance, Envoy-powered rate limiting policy.
// It follows the Gateway API Policy Attachment pattern for fine-grained traffic control.
type CiliumRateLimitPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of the rate limit policy.
	Spec CiliumRateLimitPolicySpec `json:"spec"`

	// Status defines the current state of the policy.
	Status gatewayv1alpha2.PolicyStatus `json:"status,omitempty"`
}

// CiliumRateLimitPolicySpec defines the configuration for both Local and Global rate limiting.
type CiliumRateLimitPolicySpec struct {
	// TargetRef identifies the resource (Gateway or HTTPRoute) this policy attaches to.
	TargetRef gatewayv1alpha2.LocalPolicyTargetReference `json:"targetRef"`

	// Local defines the in-memory rate limiting applied per Envoy instance.
	// No external service required. Fast and simple.
	// +optional
	Local *LocalRateLimit `json:"local,omitempty"`

	// Global defines the external Rate Limit Service (RLS) configuration.
	// Requires an external gRPC server (e.g., Redis-backed RLS).
	// +optional
	Global *GlobalRateLimit `json:"global,omitempty"`
}

// =========================================================================
// Local Rate Limiting (Envoy filter: envoy.filters.http.local_ratelimit)
// =========================================================================

type LocalRateLimit struct {
	// DefaultLimit is the fallback limit if no specific descriptors match.
	// +optional
	DefaultLimit *RateLimitValue `json:"defaultLimit,omitempty"`

	// Rules allows for conditional rate limiting based on request attributes.
	// Maps to Envoy's local rate limit descriptors.
	// +optional
	Rules []LocalRateLimitRule `json:"rules,omitempty"`

	// StatusCode is the HTTP status returned when limit is reached.
	// +optional
	// +kubebuilder:default=429
	StatusCode *int32 `json:"statusCode,omitempty"`
}

type LocalRateLimitRule struct {
	// Matches defines the conditions (Headers, IP, etc.) to trigger this limit.
	// +kubebuilder:validation:MinItems=1
	Matches []HeaderMatchCondition `json:"matches"`

	// Limit is the specific rate for this match.
	Limit RateLimitValue `json:"limit"`
}

// =========================================================================
// Global Rate Limiting (Envoy filter: envoy.filters.http.ratelimit)
// =========================================================================

type GlobalRateLimit struct {
	// Domain is the logical grouping for RLS (e.g., "production" or "api").
	// +kubebuilder:default="cilium-global-limits"
	Domain string `json:"domain"`

	// Actions define how Envoy generates descriptors (keys) to send to the RLS server.
	// This is the core of Envoy's powerful global rate limiting.
	// +kubebuilder:validation:MinItems=1
	Actions []RateLimitAction `json:"actions"`
}

type RateLimitAction struct {
	// Type defines the action type.
	// Supported: SourceIp, RequestHeader, HeaderValueMatch, GenericKey.
	// +kubebuilder:validation:Enum=SourceIp;RequestHeader;HeaderValueMatch;GenericKey
	Type string `json:"type"`

	// RequestHeader configures a descriptor based on a dynamic header value.
	// +optional
	RequestHeader *RequestHeaderAction `json:"requestHeader,omitempty"`

	// HeaderValueMatch configures a static descriptor if headers match.
	// +optional
	HeaderValueMatch *HeaderValueMatchAction `json:"headerValueMatch,omitempty"`

	// GenericKey is a static descriptor key.
	// +optional
	GenericKey *string `json:"genericKey,omitempty"`
}

// =========================================================================
// Supporting Types (Envoy-aligned)
// =========================================================================

type RateLimitValue struct {
	// Requests is the number of tokens allowed per unit of time.
	Requests uint32 `json:"requests"`

	// Unit is the time bucket.
	// +kubebuilder:validation:Enum=Second;Minute;Hour;Day
	Unit string `json:"unit"`
}

type RequestHeaderAction struct {
	// HeaderName is the name of the header to extract.
	HeaderName string `json:"headerName"`

	// DescriptorKey is the key sent to the RLS server.
	DescriptorKey string `json:"descriptorKey"`
}

type HeaderValueMatchAction struct {
	// DescriptorValue is the value sent to RLS if the match is successful.
	DescriptorValue string `json:"descriptorValue"`

	// ExpectMatch defines if the match should exist or not.
	// +optional
	// +kubebuilder:default=true
	ExpectMatch *bool `json:"expectMatch,omitempty"`

	// Headers are the list of headers to match against.
	Headers []HeaderMatchCondition `json:"headers"`
}

type HeaderMatchCondition struct {
	// Name of the header to match.
	Name string `json:"name"`

	// Value to match exactly.
	// +optional
	Value *string `json:"value,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:object:root=true

// CiliumRateLimitPolicyList contains a list of CiliumRateLimitPolicy.
type CiliumRateLimitPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CiliumRateLimitPolicy `json:"items"`
}
