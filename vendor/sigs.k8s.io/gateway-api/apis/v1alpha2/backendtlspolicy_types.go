/*
Copyright 2023 The Kubernetes Authors.

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

	"sigs.k8s.io/gateway-api/apis/v1beta1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:resource:categories=gateway-api,shortName=btlspolicy
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
//
// BackendTLSPolicy is a Direct Attached Policy.
// +kubebuilder:metadata:labels="gateway.networking.k8s.io/policy=Direct"

// BackendTLSPolicy provides a way to configure how a Gateway
// connects to a Backend via TLS.
type BackendTLSPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of BackendTLSPolicy.
	Spec BackendTLSPolicySpec `json:"spec"`

	// Status defines the current state of BackendTLSPolicy.
	Status PolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// BackendTLSPolicyList contains a list of BackendTLSPolicies
type BackendTLSPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BackendTLSPolicy `json:"items"`
}

// BackendTLSPolicySpec defines the desired state of BackendTLSPolicy.
//
// Support: Extended
type BackendTLSPolicySpec struct {
	// TargetRef identifies an API object to apply the policy to.
	// Only Services have Extended support. Implementations MAY support
	// additional objects, with Implementation Specific support.
	// Note that this config applies to the entire referenced resource
	// by default, but this default may change in the future to provide
	// a more granular application of the policy.
	//
	// Support: Extended for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	//
	TargetRef PolicyTargetReferenceWithSectionName `json:"targetRef"`

	// TLS contains backend TLS policy configuration.
	TLS BackendTLSPolicyConfig `json:"tls"`
}

// BackendTLSPolicyConfig contains backend TLS policy configuration.
// +kubebuilder:validation:XValidation:message="must not contain both CACertRefs and WellKnownCACerts",rule="!(has(self.caCertRefs) && size(self.caCertRefs) > 0 && has(self.wellKnownCACerts) && self.wellKnownCACerts != \"\")"
// +kubebuilder:validation:XValidation:message="must specify either CACertRefs or WellKnownCACerts",rule="(has(self.caCertRefs) && size(self.caCertRefs) > 0 || has(self.wellKnownCACerts) && self.wellKnownCACerts != \"\")"
type BackendTLSPolicyConfig struct {
	// CACertRefs contains one or more references to Kubernetes objects that
	// contain a PEM-encoded TLS CA certificate bundle, which is used to
	// validate a TLS handshake between the Gateway and backend Pod.
	//
	// If CACertRefs is empty or unspecified, then WellKnownCACerts must be
	// specified. Only one of CACertRefs or WellKnownCACerts may be specified,
	// not both. If CACertRefs is empty or unspecified, the configuration for
	// WellKnownCACerts MUST be honored instead.
	//
	// References to a resource in a different namespace are invalid for the
	// moment, although we will revisit this in the future.
	//
	// A single CACertRef to a Kubernetes ConfigMap kind has "Core" support.
	// Implementations MAY choose to support attaching multiple certificates to
	// a backend, but this behavior is implementation-specific.
	//
	// Support: Core - An optional single reference to a Kubernetes ConfigMap,
	// with the CA certificate in a key named `ca.crt`.
	//
	// Support: Implementation-specific (More than one reference, or other kinds
	// of resources).
	//
	// +kubebuilder:validation:MaxItems=8
	// +optional
	CACertRefs []v1beta1.LocalObjectReference `json:"caCertRefs,omitempty"`

	// WellKnownCACerts specifies whether system CA certificates may be used in
	// the TLS handshake between the gateway and backend pod.
	//
	// If WellKnownCACerts is unspecified or empty (""), then CACertRefs must be
	// specified with at least one entry for a valid configuration. Only one of
	// CACertRefs or WellKnownCACerts may be specified, not both.
	//
	// Support: Core for "System"
	//
	// +optional
	WellKnownCACerts *WellKnownCACertType `json:"wellKnownCACerts,omitempty"`

	// Hostname is used for two purposes in the connection between Gateways and
	// backends:
	//
	// 1. Hostname MUST be used as the SNI to connect to the backend (RFC 6066).
	// 2. Hostname MUST be used for authentication and MUST match the certificate
	//    served by the matching backend.
	//
	// Support: Core
	Hostname v1beta1.PreciseHostname `json:"hostname"`
}

// WellKnownCACertType is the type of CA certificate that will be used when
// the TLS.caCertRefs is unspecified.
// +kubebuilder:validation:Enum=System
type WellKnownCACertType string

const (
	// Indicates that well known system CA certificates should be used.
	WellKnownCACertSystem WellKnownCACertType = "System"
)
