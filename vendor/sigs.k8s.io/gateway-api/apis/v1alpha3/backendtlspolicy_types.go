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

package v1alpha3

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	v1 "sigs.k8s.io/gateway-api/apis/v1"
	"sigs.k8s.io/gateway-api/apis/v1alpha2"
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
	Status v1alpha2.PolicyStatus `json:"status,omitempty"`
}

// BackendTLSPolicyList contains a list of BackendTLSPolicies
// +kubebuilder:object:root=true
type BackendTLSPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BackendTLSPolicy `json:"items"`
}

// BackendTLSPolicySpec defines the desired state of BackendTLSPolicy.
//
// Support: Extended
type BackendTLSPolicySpec struct {
	// TargetRefs identifies an API object to apply the policy to.
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
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	TargetRefs []v1alpha2.LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`

	// Validation contains backend TLS validation configuration.
	Validation BackendTLSPolicyValidation `json:"validation"`
}

// BackendTLSPolicyValidation contains backend TLS validation configuration.
// +kubebuilder:validation:XValidation:message="must not contain both CACertificateRefs and WellKnownCACertificates",rule="!(has(self.caCertificateRefs) && size(self.caCertificateRefs) > 0 && has(self.wellKnownCACertificates) && self.wellKnownCACertificates != \"\")"
// +kubebuilder:validation:XValidation:message="must specify either CACertificateRefs or WellKnownCACertificates",rule="(has(self.caCertificateRefs) && size(self.caCertificateRefs) > 0 || has(self.wellKnownCACertificates) && self.wellKnownCACertificates != \"\")"
type BackendTLSPolicyValidation struct {
	// CACertificateRefs contains one or more references to Kubernetes objects that
	// contain a PEM-encoded TLS CA certificate bundle, which is used to
	// validate a TLS handshake between the Gateway and backend Pod.
	//
	// If CACertificateRefs is empty or unspecified, then WellKnownCACertificates must be
	// specified. Only one of CACertificateRefs or WellKnownCACertificates may be specified,
	// not both. If CACertifcateRefs is empty or unspecified, the configuration for
	// WellKnownCACertificates MUST be honored instead if supported by the implementation.
	//
	// References to a resource in a different namespace are invalid for the
	// moment, although we will revisit this in the future.
	//
	// A single CACertificateRef to a Kubernetes ConfigMap kind has "Core" support.
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
	CACertificateRefs []v1.LocalObjectReference `json:"caCertificateRefs,omitempty"`

	// WellKnownCACertificates specifies whether system CA certificates may be used in
	// the TLS handshake between the gateway and backend pod.
	//
	// If WellKnownCACertificates is unspecified or empty (""), then CACertificateRefs
	// must be specified with at least one entry for a valid configuration. Only one of
	// CACertificateRefs or WellKnownCACertificates may be specified, not both. If an
	// implementation does not support the WellKnownCACertificates field or the value
	// supplied is not supported, the Status Conditions on the Policy MUST be
	// updated to include an Accepted: False Condition with Reason: Invalid.
	//
	// Support: Implementation-specific
	//
	// +optional
	WellKnownCACertificates *WellKnownCACertificatesType `json:"wellKnownCACertificates,omitempty"`

	// Hostname is used for two purposes in the connection between Gateways and
	// backends:
	//
	// 1. Hostname MUST be used as the SNI to connect to the backend (RFC 6066).
	// 2. Hostname MUST be used for authentication and MUST match the certificate
	//    served by the matching backend.
	//
	// Support: Core
	Hostname v1.PreciseHostname `json:"hostname"`
}

// WellKnownCACertificatesType is the type of CA certificate that will be used
// when the caCertificateRefs field is unspecified.
// +kubebuilder:validation:Enum=System
type WellKnownCACertificatesType string

const (
	// WellKnownCACertificatesSystem indicates that well known system CA certificates should be used.
	WellKnownCACertificatesSystem WellKnownCACertificatesType = "System"
)
