// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumenvoycircuitbreaker",path="ciliumenvoycircuitbreakers",scope="Namespaced",shortName={cecb}
// +kubebuilder:printcolumn:JSONPath=".metadata.creationTimestamp",description="The age of the resource",name="Age",type=date
// +kubebuilder:storageversion

// CiliumEnvoyCircuitBreaker is a CRD that defines circuit breaker thresholds for Envoy clusters.
// It can be referenced from a Service using the annotation `cilium.io/circuit-breaker`.
type CiliumEnvoyCircuitBreaker struct {
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +k8s:openapi-gen=false
	// +deepequal-gen=false
	metav1.ObjectMeta `json:"metadata"`

	// Spec is the desired state of the CiliumEnvoyCircuitBreaker.
	Spec CiliumEnvoyCircuitBreakerSpec `json:"spec,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumEnvoyCircuitBreakerList is a list of CiliumEnvoyCircuitBreaker objects.
type CiliumEnvoyCircuitBreakerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`

	// Items is a list of CiliumEnvoyCircuitBreaker.
	Items []CiliumEnvoyCircuitBreaker `json:"items"`
}

// CiliumEnvoyCircuitBreakerSpec defines the desired state of CiliumEnvoyCircuitBreaker.
type CiliumEnvoyCircuitBreakerSpec struct {
	// Thresholds is a list of circuit breaker thresholds with different priorities.
	// Each threshold defines limits for a specific priority level (DEFAULT or HIGH).
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	Thresholds []CircuitBreakerThreshold `json:"thresholds"`
}

// CircuitBreakerThreshold defines circuit breaker limits for a specific priority level.
type CircuitBreakerThreshold struct {
	// Priority specifies the routing priority for this threshold.
	// Valid values are "DEFAULT" and "HIGH".
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=DEFAULT;HIGH
	Priority string `json:"priority"`

	// MaxConnections is the maximum number of connections that Envoy can establish
	// to the upstream service. When this threshold is met, new connections will
	// not be established.
	//
	// +kubebuilder:validation:Optional
	MaxConnections *uint32 `json:"maxConnections,omitempty"`

	// MaxPendingRequests is the maximum number of pending requests in the queue.
	// When this threshold is met, overflowing requests will be terminated with
	// a 503 status code.
	//
	// +kubebuilder:validation:Optional
	MaxPendingRequests *uint32 `json:"maxPendingRequests,omitempty"`

	// MaxRequests is the maximum number of concurrent requests in-flight from
	// Envoy to the upstream service. When this threshold is met, requests will
	// be queued.
	//
	// +kubebuilder:validation:Optional
	MaxRequests *uint32 `json:"maxRequests,omitempty"`

	// MaxRetries is the maximum number of retries that can be outstanding to all
	// hosts in a cluster at any given time.
	//
	// +kubebuilder:validation:Optional
	MaxRetries *uint32 `json:"maxRetries,omitempty"`
}
