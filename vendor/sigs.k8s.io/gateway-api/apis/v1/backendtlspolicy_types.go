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

package v1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of BackendTLSPolicy.
	// +required
	Spec BackendTLSPolicySpec `json:"spec"`

	// Status defines the current state of BackendTLSPolicy.
	// +optional
	Status PolicyStatus `json:"status,omitempty"`
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
	// TargetRefs must be _distinct_. This means either that:
	//
	// * They select different targets. If this is the case, then targetRef
	//   entries are distinct. In terms of fields, this means that the
	//   multi-part key defined by `group`, `kind`, and `name` must
	//   be unique across all targetRef entries in the BackendTLSPolicy.
	// * They select different sectionNames in the same target.
	//
	//
	// When more than one BackendTLSPolicy selects the same target and
	// sectionName, implementations MUST determine precedence using the
	// following criteria, continuing on ties:
	//
	// * The older policy by creation timestamp takes precedence. For
	//   example, a policy with a creation timestamp of "2021-07-15
	//   01:02:03" MUST be given precedence over a policy with a
	//   creation timestamp of "2021-07-15 01:02:04".
	// * The policy appearing first in alphabetical order by {name}.
	//   For example, a policy named `bar` is given precedence over a
	//   policy named `baz`.
	//
	// For any BackendTLSPolicy that does not take precedence, the
	// implementation MUST ensure the `Accepted` Condition is set to
	// `status: False`, with Reason `Conflicted`.
	//
	// Support: Extended for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="sectionName must be specified when targetRefs includes 2 or more references to the same target",rule="self.all(p1, self.all(p2, p1.group == p2.group && p1.kind == p2.kind && p1.name == p2.name ? ((!has(p1.sectionName) || p1.sectionName == '') == (!has(p2.sectionName) || p2.sectionName == '')) : true))"
	// +kubebuilder:validation:XValidation:message="sectionName must be unique when targetRefs includes 2 or more references to the same target",rule="self.all(p1, self.exists_one(p2, p1.group == p2.group && p1.kind == p2.kind && p1.name == p2.name && (((!has(p1.sectionName) || p1.sectionName == '') && (!has(p2.sectionName) || p2.sectionName == '')) || (has(p1.sectionName) && has(p2.sectionName) && p1.sectionName == p2.sectionName))))"
	TargetRefs []LocalPolicyTargetReferenceWithSectionName `json:"targetRefs"`

	// Validation contains backend TLS validation configuration.
	// +required
	Validation BackendTLSPolicyValidation `json:"validation"`

	// Options are a list of key/value pairs to enable extended TLS
	// configuration for each implementation. For example, configuring the
	// minimum TLS version or supported cipher suites.
	//
	// A set of common keys MAY be defined by the API in the future. To avoid
	// any ambiguity, implementation-specific definitions MUST use
	// domain-prefixed names, such as `example.com/my-custom-option`.
	// Un-prefixed names are reserved for key names defined by Gateway API.
	//
	// Support: Implementation-specific
	//
	// +optional
	// +kubebuilder:validation:MaxProperties=16
	Options map[AnnotationKey]AnnotationValue `json:"options,omitempty"`
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
	// not both. If CACertificateRefs is empty or unspecified, the configuration for
	// WellKnownCACertificates MUST be honored instead if supported by the implementation.
	//
	// A CACertificateRef is invalid if:
	//
	// * It refers to a resource that cannot be resolved (e.g., the referenced resource
	//   does not exist) or is misconfigured (e.g., a ConfigMap does not contain a key
	//   named `ca.crt`). In this case, the Reason must be set to `InvalidCACertificateRef`
	//   and the Message of the Condition must indicate which reference is invalid and why.
	//
	// * It refers to an unknown or unsupported kind of resource. In this case, the Reason
	//   must be set to `InvalidKind` and the Message of the Condition must explain which
	//   kind of resource is unknown or unsupported.
	//
	// * It refers to a resource in another namespace. This may change in future
	//   spec updates.
	//
	// Implementations MAY choose to perform further validation of the certificate
	// content (e.g., checking expiry or enforcing specific formats). In such cases,
	// an implementation-specific Reason and Message must be set for the invalid reference.
	//
	// In all cases, the implementation MUST ensure the `ResolvedRefs` Condition on
	// the BackendTLSPolicy is set to `status: False`, with a Reason and Message
	// that indicate the cause of the error. Connections using an invalid
	// CACertificateRef MUST fail, and the client MUST receive an HTTP 5xx error
	// response. If ALL CACertificateRefs are invalid, the implementation MUST also
	// ensure the `Accepted` Condition on the BackendTLSPolicy is set to
	// `status: False`, with a Reason `NoValidCACertificate`.
	//
	//
	// A single CACertificateRef to a Kubernetes ConfigMap kind has "Core" support.
	// Implementations MAY choose to support attaching multiple certificates to
	// a backend, but this behavior is implementation-specific.
	//
	// Support: Core - An optional single reference to a Kubernetes ConfigMap,
	// with the CA certificate in a key named `ca.crt`.
	//
	// Support: Implementation-specific - More than one reference, other kinds
	// of resources, or a single reference that includes multiple certificates.
	//
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	CACertificateRefs []LocalObjectReference `json:"caCertificateRefs,omitempty"`

	// WellKnownCACertificates specifies whether system CA certificates may be used in
	// the TLS handshake between the gateway and backend pod.
	//
	// If WellKnownCACertificates is unspecified or empty (""), then CACertificateRefs
	// must be specified with at least one entry for a valid configuration. Only one of
	// CACertificateRefs or WellKnownCACertificates may be specified, not both.
	// If an implementation does not support the WellKnownCACertificates field, or
	// the supplied value is not recognized, the implementation MUST ensure the
	// `Accepted` Condition on the BackendTLSPolicy is set to `status: False`, with
	// a Reason `Invalid`.
	//
	// Support: Implementation-specific
	//
	// +optional
	// +listType=atomic
	WellKnownCACertificates *WellKnownCACertificatesType `json:"wellKnownCACertificates,omitempty"`

	// Hostname is used for two purposes in the connection between Gateways and
	// backends:
	//
	// 1. Hostname MUST be used as the SNI to connect to the backend (RFC 6066).
	// 2. Hostname MUST be used for authentication and MUST match the certificate
	//    served by the matching backend, unless SubjectAltNames is specified.
	// 3. If SubjectAltNames are specified, Hostname can be used for certificate selection
	//    but MUST NOT be used for authentication. If you want to use the value
	//    of the Hostname field for authentication, you MUST add it to the SubjectAltNames list.
	//
	// Support: Core
	//
	// +required
	Hostname PreciseHostname `json:"hostname"`

	// SubjectAltNames contains one or more Subject Alternative Names.
	// When specified the certificate served from the backend MUST
	// have at least one Subject Alternate Name matching one of the specified SubjectAltNames.
	//
	// Support: Extended
	//
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=5
	SubjectAltNames []SubjectAltName `json:"subjectAltNames,omitempty"`
}

// SubjectAltName represents Subject Alternative Name.
// +kubebuilder:validation:XValidation:message="SubjectAltName element must contain Hostname, if Type is set to Hostname",rule="!(self.type == \"Hostname\" && (!has(self.hostname) || self.hostname == \"\"))"
// +kubebuilder:validation:XValidation:message="SubjectAltName element must not contain Hostname, if Type is not set to Hostname",rule="!(self.type != \"Hostname\" && has(self.hostname) && self.hostname != \"\")"
// +kubebuilder:validation:XValidation:message="SubjectAltName element must contain URI, if Type is set to URI",rule="!(self.type == \"URI\" && (!has(self.uri) || self.uri == \"\"))"
// +kubebuilder:validation:XValidation:message="SubjectAltName element must not contain URI, if Type is not set to URI",rule="!(self.type != \"URI\" && has(self.uri) && self.uri != \"\")"
type SubjectAltName struct {
	// Type determines the format of the Subject Alternative Name. Always required.
	//
	// Support: Core
	//
	// +required
	Type SubjectAltNameType `json:"type"`

	// Hostname contains Subject Alternative Name specified in DNS name format.
	// Required when Type is set to Hostname, ignored otherwise.
	//
	// Support: Core
	//
	// +optional
	Hostname Hostname `json:"hostname,omitempty"`

	// URI contains Subject Alternative Name specified in a full URI format.
	// It MUST include both a scheme (e.g., "http" or "ftp") and a scheme-specific-part.
	// Common values include SPIFFE IDs like "spiffe://mycluster.example.com/ns/myns/sa/svc1sa".
	// Required when Type is set to URI, ignored otherwise.
	//
	// Support: Core
	//
	// +optional
	URI AbsoluteURI `json:"uri,omitempty"`
}

// WellKnownCACertificatesType is the type of CA certificate that will be used
// when the caCertificateRefs field is unspecified.
// +kubebuilder:validation:Enum=System
type WellKnownCACertificatesType string

const (
	// WellKnownCACertificatesSystem indicates that well known system CA certificates should be used.
	WellKnownCACertificatesSystem WellKnownCACertificatesType = "System"
)

// SubjectAltNameType is the type of the Subject Alternative Name.
// +kubebuilder:validation:Enum=Hostname;URI
type SubjectAltNameType string

const (
	// HostnameSubjectAltNameType specifies hostname-based SAN.
	//
	// Support: Core
	HostnameSubjectAltNameType SubjectAltNameType = "Hostname"

	// URISubjectAltNameType specifies URI-based SAN, e.g. SPIFFE id.
	//
	// Support: Core
	URISubjectAltNameType SubjectAltNameType = "URI"
)

const (
	// This reason is used with the "Accepted" condition when it is
	// set to false because all CACertificateRefs of the
	// BackendTLSPolicy are invalid.
	BackendTLSPolicyReasonNoValidCACertificate PolicyConditionReason = "NoValidCACertificate"
)

const (
	// This condition indicates whether the controller was able to resolve all
	// object references for the BackendTLSPolicy.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "ResolvedRefs"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "InvalidCACertificateRef"
	// * "InvalidKind"
	//
	// Controllers may raise this condition with other reasons, but should
	// prefer to use the reasons listed above to improve interoperability.
	BackendTLSPolicyConditionResolvedRefs PolicyConditionType = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when the condition
	// is true.
	BackendTLSPolicyReasonResolvedRefs PolicyConditionReason = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when one of the
	// BackendTLSPolicy's CACertificateRefs is invalid.
	// A CACertificateRef is considered invalid when it refers to a nonexistent
	// resource or when the data within that resource is malformed.
	BackendTLSPolicyReasonInvalidCACertificateRef PolicyConditionReason = "InvalidCACertificateRef"

	// This reason is used with the "ResolvedRefs" condition when one of the
	// BackendTLSPolicy's CACertificateRefs references an unknown or unsupported
	// Group and/or Kind.
	BackendTLSPolicyReasonInvalidKind PolicyConditionReason = "InvalidKind"
)
