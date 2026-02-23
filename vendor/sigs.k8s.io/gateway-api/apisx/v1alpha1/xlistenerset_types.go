/*
Copyright 2025 The Kubernetes Authors.

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

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,shortName=lset
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Accepted",type=string,JSONPath=`.status.conditions[?(@.type=="Accepted")].status`
// +kubebuilder:printcolumn:name="Programmed",type=string,JSONPath=`.status.conditions[?(@.type=="Programmed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// XListenerSet defines a set of additional listeners to attach to an existing Gateway.
// This resource provides a mechanism to merge multiple listeners into a single Gateway.
//
// The parent Gateway must explicitly allow ListenerSet attachment through its
// AllowedListeners configuration. By default, Gateways do not allow ListenerSet
// attachment.
//
// Routes can attach to a ListenerSet by specifying it as a parentRef, and can
// optionally target specific listeners using the sectionName field.
//
// Policy Attachment:
// - Policies that attach to a ListenerSet apply to all listeners defined in that resource
// - Policies do not impact listeners in the parent Gateway
// - Different ListenerSets attached to the same Gateway can have different policies
// - If an implementation cannot apply a policy to specific listeners, it should reject the policy
//
// ReferenceGrant Semantics:
// - ReferenceGrants applied to a Gateway are not inherited by child ListenerSets
// - ReferenceGrants applied to a ListenerSet do not grant permission to the parent Gateway's listeners
// - A ListenerSet can reference secrets/backends in its own namespace without a ReferenceGrant
//
// Gateway Integration:
// - The parent Gateway's status will include an "AttachedListenerSets" condition
// - This condition will be:
//   - True: when AllowedListeners is set and at least one child ListenerSet is attached
//   - False: when AllowedListeners is set but no valid listeners are attached, or when AllowedListeners is not set or false
//   - Unknown: when no AllowedListeners config is present
type XListenerSet struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of ListenerSet.
	// +required
	Spec ListenerSetSpec `json:"spec"`

	// Status defines the current state of ListenerSet.
	//
	// +kubebuilder:default={conditions: {{type: "Accepted", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"},{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	// +optional
	Status ListenerSetStatus `json:"status,omitempty"`
}

// ListenerSetSpec defines the desired state of a ListenerSet.
type ListenerSetSpec struct {
	// ParentRef references the Gateway that the listeners are attached to.
	// +required
	ParentRef ParentGatewayReference `json:"parentRef"`

	// Listeners associated with this ListenerSet. Listeners define
	// logical endpoints that are bound on this referenced parent Gateway's addresses.
	//
	// Listeners in a `Gateway` and their attached `ListenerSets` are concatenated
	// as a list when programming the underlying infrastructure. Each listener
	// name does not need to be unique across the Gateway and ListenerSets.
	// See ListenerEntry.Name for more details.
	//
	// Implementations MUST treat the parent Gateway as having the merged
	// list of all listeners from itself and attached ListenerSets using
	// the following precedence:
	//
	// 1. "parent" Gateway
	// 2. ListenerSet ordered by creation time (oldest first)
	// 3. ListenerSet ordered alphabetically by "{namespace}/{name}".
	//
	// An implementation MAY reject listeners by setting the ListenerEntryStatus
	// `Accepted` condition to False with the Reason `TooManyListeners`
	//
	// If a listener has a conflict, this will be reported in the
	// Status.ListenerEntryStatus setting the `Conflicted` condition to True.
	//
	// Implementations SHOULD be cautious about what information from the
	// parent or siblings are reported to avoid accidentally leaking
	// sensitive information that the child would not otherwise have access
	// to. This can include contents of secrets etc.
	//
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:message="tls must not be specified for protocols ['HTTP', 'TCP', 'UDP']",rule="self.all(l, l.protocol in ['HTTP', 'TCP', 'UDP'] ? !has(l.tls) : true)"
	// +kubebuilder:validation:XValidation:message="tls mode must be Terminate for protocol HTTPS",rule="self.all(l, (l.protocol == 'HTTPS' && has(l.tls)) ? (l.tls.mode == '' || l.tls.mode == 'Terminate') : true)"
	// +kubebuilder:validation:XValidation:message="hostname must not be specified for protocols ['TCP', 'UDP']",rule="self.all(l, l.protocol in ['TCP', 'UDP']  ? (!has(l.hostname) || l.hostname == '') : true)"
	// +kubebuilder:validation:XValidation:message="Listener name must be unique within the Gateway",rule="self.all(l1, self.exists_one(l2, l1.name == l2.name))"
	// +kubebuilder:validation:XValidation:message="Combination of port, protocol and hostname must be unique for each listener",rule="self.all(l1, !has(l1.port) || self.exists_one(l2, has(l2.port) && l1.port == l2.port && l1.protocol == l2.protocol && (has(l1.hostname) && has(l2.hostname) ? l1.hostname == l2.hostname : !has(l1.hostname) && !has(l2.hostname))))"
	// +required
	Listeners []ListenerEntry `json:"listeners"`
}

type ListenerEntry struct {
	// Name is the name of the Listener. This name MUST be unique within a
	// ListenerSet.
	//
	// Name is not required to be unique across a Gateway and ListenerSets.
	// Routes can attach to a Listener by having a ListenerSet as a parentRef
	// and setting the SectionName
	// +required
	Name SectionName `json:"name"`

	// Hostname specifies the virtual hostname to match for protocol types that
	// define this concept. When unspecified, all hostnames are matched. This
	// field is ignored for protocols that don't require hostname based
	// matching.
	//
	// Implementations MUST apply Hostname matching appropriately for each of
	// the following protocols:
	//
	// * TLS: The Listener Hostname MUST match the SNI.
	// * HTTP: The Listener Hostname MUST match the Host header of the request.
	// * HTTPS: The Listener Hostname SHOULD match at both the TLS and HTTP
	//   protocol layers as described above. If an implementation does not
	//   ensure that both the SNI and Host header match the Listener hostname,
	//   it MUST clearly document that.
	//
	// For HTTPRoute and TLSRoute resources, there is an interaction with the
	// `spec.hostnames` array. When both listener and route specify hostnames,
	// there MUST be an intersection between the values for a Route to be
	// accepted. For more information, refer to the Route specific Hostnames
	// documentation.
	//
	// Hostnames that are prefixed with a wildcard label (`*.`) are interpreted
	// as a suffix match. That means that a match for `*.example.com` would match
	// both `test.example.com`, and `foo.test.example.com`, but not `example.com`.
	//
	// +optional
	Hostname *Hostname `json:"hostname,omitempty"`

	// Port is the network port. Multiple listeners may use the
	// same port, subject to the Listener compatibility rules.
	//
	// If the port is not set or specified as zero, the implementation will assign
	// a unique port. If the implementation does not support dynamic port
	// assignment, it MUST set `Accepted` condition to `False` with the
	// `UnsupportedPort` reason.
	//
	// +optional
	//
	// +kubebuilder:default=0
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=65535
	Port PortNumber `json:"port,omitempty"`

	// Protocol specifies the network protocol this listener expects to receive.
	// +required
	Protocol ProtocolType `json:"protocol"`

	// TLS is the TLS configuration for the Listener. This field is required if
	// the Protocol field is "HTTPS" or "TLS". It is invalid to set this field
	// if the Protocol field is "HTTP", "TCP", or "UDP".
	//
	// The association of SNIs to Certificate defined in ListenerTLSConfig is
	// defined based on the Hostname field for this listener.
	//
	// The GatewayClass MUST use the longest matching SNI out of all
	// available certificates for any TLS handshake.
	//
	// +optional
	TLS *ListenerTLSConfig `json:"tls,omitempty"`

	// AllowedRoutes defines the types of routes that MAY be attached to a
	// Listener and the trusted namespaces where those Route resources MAY be
	// present.
	//
	// Although a client request may match multiple route rules, only one rule
	// may ultimately receive the request. Matching precedence MUST be
	// determined in order of the following criteria:
	//
	// * The most specific match as defined by the Route type.
	// * The oldest Route based on creation timestamp. For example, a Route with
	//   a creation timestamp of "2020-09-08 01:02:03" is given precedence over
	//   a Route with a creation timestamp of "2020-09-08 01:02:04".
	// * If everything else is equivalent, the Route appearing first in
	//   alphabetical order (namespace/name) should be given precedence. For
	//   example, foo/bar is given precedence over foo/baz.
	//
	// All valid rules within a Route attached to this Listener should be
	// implemented. Invalid Route rules can be ignored (sometimes that will mean
	// the full Route). If a Route rule transitions from valid to invalid,
	// support for that Route rule should be dropped to ensure consistency. For
	// example, even if a filter specified by a Route rule is invalid, the rest
	// of the rules within that Route should still be supported.
	//
	// +kubebuilder:default={namespaces:{from: Same}}
	// +optional
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty"`
}

type ListenerSetStatus struct {
	// Conditions describe the current conditions of the ListenerSet.
	//
	// Implementations MUST express ListenerSet conditions using the
	// `ListenerSetConditionType` and `ListenerSetConditionReason`
	// constants so that operators and tools can converge on a common
	// vocabulary to describe ListenerSet state.
	//
	// Known condition types are:
	//
	// * "Accepted"
	// * "Programmed"
	//
	// +optional
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:default={{type: "Accepted", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"},{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Listeners provide status for each unique listener port defined in the Spec.
	//
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=64
	Listeners []ListenerEntryStatus `json:"listeners,omitempty"`
}

// ListenerStatus is the status associated with a Listener.
type ListenerEntryStatus struct {
	// Name is the name of the Listener that this status corresponds to.
	// +required
	Name SectionName `json:"name"`

	// Port is the network port the listener is configured to listen on.
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	//
	// +required
	Port PortNumber `json:"port"`

	// SupportedKinds is the list indicating the Kinds supported by this
	// listener. This MUST represent the kinds an implementation supports for
	// that Listener configuration.
	//
	// If kinds are specified in Spec that are not supported, they MUST NOT
	// appear in this list and an implementation MUST set the "ResolvedRefs"
	// condition to "False" with the "InvalidRouteKinds" reason. If both valid
	// and invalid Route kinds are specified, the implementation MUST
	// reference the valid Route kinds that have been specified.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	SupportedKinds []RouteGroupKind `json:"supportedKinds"`

	// AttachedRoutes represents the total number of Routes that have been
	// successfully attached to this Listener.
	//
	// Successful attachment of a Route to a Listener is based solely on the
	// combination of the AllowedRoutes field on the corresponding Listener
	// and the Route's ParentRefs field. A Route is successfully attached to
	// a Listener when it is selected by the Listener's AllowedRoutes field
	// AND the Route has a valid ParentRef selecting the whole Gateway
	// resource or a specific Listener as a parent resource (more detail on
	// attachment semantics can be found in the documentation on the various
	// Route kinds ParentRefs fields). Listener or Route status does not impact
	// successful attachment, i.e. the AttachedRoutes field count MUST be set
	// for Listeners with condition Accepted: false and MUST count successfully
	// attached Routes that may themselves have Accepted: false conditions.
	//
	// Uses for this field include troubleshooting Route attachment and
	// measuring blast radius/impact of changes to a Listener.
	// +required
	AttachedRoutes int32 `json:"attachedRoutes"`

	// Conditions describe the current condition of this listener.
	//
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +required
	Conditions []metav1.Condition `json:"conditions"`
}

// ListenerSetConditionType is a type of condition associated with a
// ListenerSet. This type should be used with the ListenerSetStatus.Conditions
// field.
type ListenerSetConditionType string

// ListenerSetConditionReason defines the set of reasons that explain why a
// particular ListenerSet condition type has been raised.
type ListenerSetConditionReason string

const (
	// This condition indicates whether a ListenerSet has generated some
	// configuration that is assumed to be ready soon in the underlying data
	// plane.
	//
	// It is a positive-polarity summary condition, and so should always be
	// present on the resource with ObservedGeneration set.
	//
	// It should be set to Unknown if the controller performs updates to the
	// status before it has all the information it needs to be able to determine
	// if the condition is true.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Programmed"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Invalid"
	// * "ParentNotProgrammed"
	//
	// Additional reasons for this condition to be False are influenced by
	// child ListenerEntry conditions:
	//
	// * "PortUnavailable"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerSetConditionProgrammed ListenerSetConditionType = "Programmed"

	// This reason is used with the "Programmed" condition when the condition is
	// true.
	ListenerSetReasonProgrammed ListenerSetConditionReason = "Programmed"
)

const (
	// This condition is true when the controller managing the ListenerSet is
	// syntactically and semantically valid enough to produce some configuration
	// in the underlying data plane. This does not indicate whether or not the
	// configuration has been propagated to the data plane.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Invalid"
	// * "NotAllowed"
	// * "ParentNotAccepted"
	// * "ListenersNotValid"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerSetConditionAccepted ListenerSetConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the condition is
	// True.
	ListenerSetReasonAccepted ListenerSetConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when the
	// ListenerSet is not allowed to be attached to the Gateway.
	ListenerSetReasonNotAllowed ListenerSetConditionReason = "NotAllowed"

	// This reason is used with the "Accepted" condition when the
	// parent Gateway is not accepted.
	ListenerSetReasonParentNotAccepted ListenerSetConditionReason = "ParentNotAccepted"

	// This reason is used with the "Accepted" condition when one or
	// more Listeners have an invalid or unsupported configuration
	// and cannot be configured on the Gateway.
	// This can be the reason when "Accepted" is "True" or "False", depending on whether
	// the listener being invalid causes the entire Gateway to not be accepted.
	ListenerSetReasonListenersNotValid ListenerSetConditionReason = "ListenersNotValid"
)

// Shared ListenerSet Reasons
const (
	// This reason is used with the "Programmed" and "Accepted" conditions when
	// the ListenerSet is syntactically or semantically invalid. For example, this
	// could include unspecified TLS configuration, or some unrecognized or
	// invalid values in the TLS configuration.
	ListenerSetReasonInvalid ListenerSetConditionReason = "Invalid"

	// This reason is used with the "Accepted" and "Programmed"
	// conditions when the status is "Unknown" and no controller has reconciled
	// the Gateway.
	ListenerSetReasonPending ListenerSetConditionReason = "Pending"
)

// ListenerEntryConditionType is a type of condition associated with the
// listener. This type should be used with the ListenerEntryStatus.Conditions
// field.
type ListenerEntryConditionType string

// ListenerEntryConditionReason defines the set of reasons that explain
// why a particular ListenerEntry condition type has been raised.
type ListenerEntryConditionReason string

const (
	// This condition indicates that the controller was unable to resolve
	// conflicting specification requirements for this Listener. If a
	// Listener is conflicted, its network port should not be configured
	// on any network elements.
	//
	// Possible reasons for this condition to be true are:
	//
	// * "HostnameConflict"
	// * "ProtocolConflict"
	// * "ListenerConflict"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "NoConflicts"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerEntryConditionConflicted ListenerEntryConditionType = "Conflicted"

	// This reason is used with the "Conflicted" condition when
	// the Listener conflicts with hostnames in other Listeners. For
	// example, this reason would be used when multiple Listeners on
	// the same port use `example.com` in the hostname field.
	ListenerEntryReasonHostnameConflict ListenerEntryConditionReason = "HostnameConflict"

	// This reason is used with the "Conflicted" condition when
	// multiple Listeners are specified with the same Listener port
	// number, but have conflicting protocol specifications.
	ListenerEntryReasonProtocolConflict ListenerEntryConditionReason = "ProtocolConflict"

	// This reason is used with the "Conflicted" condition when the condition
	// is True.
	//
	// Implementations should prioritize surfacing the most specific conflict
	// reason. For example, if a Listener is conflicted because it has the same
	// port as another Listener, and it also has the same hostname as another
	// Listener, the reason should be "ListenerConflict" and not
	// "HostnameConflict" or "ProtocolConflict".
	ListenerEntryReasonListenerConflict ListenerEntryConditionReason = "ListenerConflict"
)

const (
	// This condition indicates that the listener is syntactically and
	// semantically valid, and that all features used in the listener's spec are
	// supported.
	//
	// In general, a Listener will be marked as Accepted when the supplied
	// configuration will generate at least some data plane configuration.
	//
	// For example, a Listener with an unsupported protocol will never generate
	// any data plane config, and so will have Accepted set to `false.`
	// Conversely, a Listener that does not have any Routes will be able to
	// generate data plane config, and so will have Accepted set to `true`.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "PortUnavailable"
	// * "UnsupportedProtocol"
	// * "TooManyListeners"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerEntryConditionAccepted ListenerEntryConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the condition is
	// True.
	ListenerEntryReasonAccepted ListenerEntryConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when the
	// Listener could not be attached to be Gateway because its
	// protocol type is not supported.
	ListenerEntryReasonUnsupportedProtocol ListenerEntryConditionReason = "UnsupportedProtocol"

	// This reason is used with the "Accepted" condition when the
	// Listener could not be attached to be Gateway because the Gateway
	// has too many Listeners.
	ListenerEntryReasonTooManyListeners ListenerEntryConditionReason = "TooManyListeners"
)

const (
	// This condition indicates whether the controller was able to
	// resolve all the object references for the Listener.
	//
	// Possible reasons for this condition to be true are:
	//
	// * "ResolvedRefs"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "InvalidCertificateRef"
	// * "InvalidRouteKinds"
	// * "RefNotPermitted"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerEntryConditionResolvedRefs ListenerEntryConditionType = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when the condition
	// is true.
	ListenerEntryReasonResolvedRefs ListenerEntryConditionReason = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when the
	// Listener has a TLS configuration with at least one TLS CertificateRef
	// that is invalid or does not exist.
	// A CertificateRef is considered invalid when it refers to a nonexistent
	// or unsupported resource or kind, or when the data within that resource
	// is malformed.
	// This reason must be used only when the reference is allowed, either by
	// referencing an object in the same namespace as the Gateway, or when
	// a cross-namespace reference has been explicitly allowed by a ReferenceGrant.
	// If the reference is not allowed, the reason RefNotPermitted must be used
	// instead.
	ListenerEntryReasonInvalidCertificateRef ListenerEntryConditionReason = "InvalidCertificateRef"

	// This reason is used with the "ResolvedRefs" condition when an invalid or
	// unsupported Route kind is specified by the Listener.
	ListenerEntryReasonInvalidRouteKinds ListenerEntryConditionReason = "InvalidRouteKinds"

	// This reason is used with the "ResolvedRefs" condition when the
	// Listener has a TLS configuration that references an object in another
	// namespace, where the object in the other namespace does not have a
	// ReferenceGrant explicitly allowing the reference.
	ListenerEntryReasonRefNotPermitted ListenerEntryConditionReason = "RefNotPermitted"
)

const (
	// This condition indicates whether a Listener has generated some
	// configuration that will soon be ready in the underlying data plane.
	//
	// It is a positive-polarity summary condition, and so should always be
	// present on the resource with ObservedGeneration set.
	//
	// It should be set to Unknown if the controller performs updates to the
	// status before it has all the information it needs to be able to determine
	// if the condition is true.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Programmed"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Invalid"
	// * "PortUnavailable"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerEntryConditionProgrammed ListenerEntryConditionType = "Programmed"

	// This reason is used with the "Programmed" condition when the condition is
	// true.
	ListenerEntryReasonProgrammed ListenerEntryConditionReason = "Programmed"
)

// Shared ListenerEntry "Accepted" & "Programmed" Reasons
const (
	// This reason is used with the "Accepted" condition when the Listener
	// requests a port that cannot be used on the Gateway. This reason could be
	// used in a number of instances, including:
	//
	// * The port is already in use.
	// * The port is not supported by the implementation.
	// * The implementation is unable to assign the port to the Listener.
	ListenerEntryReasonPortUnavailable ListenerEntryConditionReason = "PortUnavailable"

	// This reason is used with the "Accepted" and "Programmed"
	// conditions when the Listener is either not yet reconciled or not yet not
	// online and ready to accept client traffic.
	ListenerEntryReasonPending ListenerEntryConditionReason = "Pending"

	// This reason is used with the "Accepted" and "Programmed" conditions when the
	// Listener is syntactically or semantically invalid.
	ListenerEntryReasonInvalid ListenerEntryConditionReason = "Invalid"
)

const (
	// "Ready" is a condition type reserved for future use. It should not be used by implementations.
	// Note: This condition is not really "deprecated", but rather "reserved"; however, deprecated triggers Go linters
	// to alert about usage.
	//
	// If used in the future, "Ready" will represent the final state where all configuration is confirmed good
	// _and has completely propagated to the data plane_. That is, it is a _guarantee_ that, as soon as something
	// sees the Condition as `true`, then connections will be correctly routed _immediately_.
	//
	// This is a very strong guarantee, and to date no implementation has satisfied it enough to implement it.
	// This reservation can be discussed in the future if necessary.
	//
	// Deprecated: Ready is reserved for future use
	ListenerEntryConditionReady ListenerEntryConditionType = "Ready"

	// Deprecated: Ready is reserved for future use
	ListenerEntryReasonReady ListenerEntryConditionReason = "Ready"
)

// +kubebuilder:object:root=true
type XListenerSetList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []XListenerSet `json:"items"`
}
