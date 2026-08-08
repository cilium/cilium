// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +kubebuilder:resource:categories={cilium},singular="ciliumenvoyextprocfilter",path="ciliumenvoyextprocfilters",scope="Namespaced",shortName={ceepf}
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"
// +kubebuilder:storageversion
//
// CiliumEnvoyExtProcFilter defines an Envoy ext_proc filter that can be
// referenced by Gateway API HTTPRoute or GRPCRoute ExtensionRef filters.
// It specifies an external gRPC processing service that will be inserted
// into the Envoy HTTP filter chain for matching routes.
type CiliumEnvoyExtProcFilter struct {
	// +deepequal-gen=false
	metav1.TypeMeta `json:",inline"`
	// +deepequal-gen=false
	// +kubebuilder:validation:Required
	metav1.ObjectMeta `json:"metadata"`

	// Spec defines the desired ext_proc filter configuration.
	//
	// +kubebuilder:validation:Required
	Spec CiliumEnvoyExtProcFilterSpec `json:"spec"`
}

// CiliumEnvoyExtProcFilterSpec specifies the configuration for an Envoy
// External Processing (ext_proc) filter.
type CiliumEnvoyExtProcFilterSpec struct {
	// BackendRef is a reference to the Kubernetes Service that implements
	// the ext_proc gRPC protocol. The service must expose a gRPC endpoint
	// compatible with the Envoy ext_proc API.
	//
	// Cross-namespace references require a ReferenceGrant in the target
	// namespace.
	//
	// +kubebuilder:validation:Required
	BackendRef ExtProcBackendRef `json:"backendRef"`

	// ProcessingMode determines which parts of the HTTP request and response
	// are sent to the ext_proc service for processing.
	//
	// If not specified, Envoy defaults apply: request and response headers
	// are sent, bodies and trailers are not.
	//
	// +kubebuilder:validation:Optional
	ProcessingMode *ExtProcProcessingMode `json:"processingMode,omitempty"`

	// FailureModeAllow determines behavior when the ext_proc service is
	// unavailable. If false (the default), requests fail with an error when
	// the ext_proc service cannot be reached. If true, requests proceed
	// without external processing.
	//
	// +kubebuilder:validation:Optional
	FailureModeAllow bool `json:"failureModeAllow,omitempty"`

	// MessageTimeout is the timeout for an individual message exchange with
	// the ext_proc service. If not specified, Envoy's default of 200ms is
	// used.
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Type=string
	MessageTimeout *ExtProcMessageTimeout `json:"messageTimeout,omitempty"`
}

// ExtProcMessageTimeout is a metav1.Duration wrapper with a DeepEqual method
// for generated CRD equality checks.
type ExtProcMessageTimeout metav1.Duration

// DeepEqual compares two ExtProcMessageTimeout values.
func (in *ExtProcMessageTimeout) DeepEqual(other *ExtProcMessageTimeout) bool {
	if in == nil || other == nil {
		return in == other
	}
	return in.Duration == other.Duration
}

// MarshalJSON serializes ExtProcMessageTimeout like metav1.Duration.
func (in ExtProcMessageTimeout) MarshalJSON() ([]byte, error) {
	return metav1.Duration(in).MarshalJSON()
}

// UnmarshalJSON deserializes ExtProcMessageTimeout like metav1.Duration.
func (in *ExtProcMessageTimeout) UnmarshalJSON(b []byte) error {
	var duration metav1.Duration
	if err := duration.UnmarshalJSON(b); err != nil {
		return err
	}
	*in = ExtProcMessageTimeout(duration)
	return nil
}

// ExtProcBackendRef is a reference to a Kubernetes Service that implements
// the ext_proc gRPC protocol.
type ExtProcBackendRef struct {
	// Name is the name of the Kubernetes Service. Must be a valid RFC 1123
	// label (lowercase alphanumeric characters or '-', starting and ending
	// with an alphanumeric character, up to 63 characters).
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	Name string `json:"name"`

	// Namespace is the namespace of the Service. When unspecified, the
	// namespace of the CiliumEnvoyExtProcFilter resource is used.
	//
	// Cross-namespace references require a ReferenceGrant.
	//
	// +kubebuilder:validation:Optional
	Namespace *string `json:"namespace,omitempty"`

	// Port is the port number on the Service to connect to for the ext_proc
	// gRPC service.
	//
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// ExtProcProcessingMode controls which parts of an HTTP request/response
// are sent to the ext_proc service.
type ExtProcProcessingMode struct {
	// RequestHeaderMode determines how request headers are handled.
	// Valid values are "SEND" and "SKIP". Default is "SEND".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=SEND;SKIP
	RequestHeaderMode *string `json:"requestHeaderMode,omitempty"`

	// ResponseHeaderMode determines how response headers are handled.
	// Valid values are "SEND" and "SKIP". Default is "SEND".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=SEND;SKIP
	ResponseHeaderMode *string `json:"responseHeaderMode,omitempty"`

	// RequestBodyMode determines how request bodies are handled.
	// Valid values are "NONE", "STREAMED", "BUFFERED", and "BUFFERED_PARTIAL".
	// Default is "NONE".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=NONE;STREAMED;BUFFERED;BUFFERED_PARTIAL
	RequestBodyMode *string `json:"requestBodyMode,omitempty"`

	// ResponseBodyMode determines how response bodies are handled.
	// Valid values are "NONE", "STREAMED", "BUFFERED", and "BUFFERED_PARTIAL".
	// Default is "NONE".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=NONE;STREAMED;BUFFERED;BUFFERED_PARTIAL
	ResponseBodyMode *string `json:"responseBodyMode,omitempty"`

	// RequestTrailerMode determines how request trailers are handled.
	// Valid values are "SEND" and "SKIP". Default is "SKIP".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=SEND;SKIP
	RequestTrailerMode *string `json:"requestTrailerMode,omitempty"`

	// ResponseTrailerMode determines how response trailers are handled.
	// Valid values are "SEND" and "SKIP". Default is "SKIP".
	//
	// +kubebuilder:validation:Optional
	// +kubebuilder:validation:Enum=SEND;SKIP
	ResponseTrailerMode *string `json:"responseTrailerMode,omitempty"`
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
// +deepequal-gen=false

// CiliumEnvoyExtProcFilterList is a list of CiliumEnvoyExtProcFilter resources.
type CiliumEnvoyExtProcFilterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata"`
	Items           []CiliumEnvoyExtProcFilter `json:"items"`
}
