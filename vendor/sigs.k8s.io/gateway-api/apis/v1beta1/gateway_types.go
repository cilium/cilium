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

package v1beta1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,shortName=gtw
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.gatewayClassName`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.addresses[*].value`
// +kubebuilder:printcolumn:name="Programmed",type=string,JSONPath=`.status.conditions[?(@.type=="Programmed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Gateway represents an instance of a service-traffic handling infrastructure
// by binding Listeners to a set of IP addresses.
type Gateway struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of Gateway.
	Spec GatewaySpec `json:"spec"`

	// Status defines the current state of Gateway.
	//
	// +kubebuilder:default={conditions: {{type: "Accepted", status: "Unknown", reason:"NotReconciled", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	Status GatewayStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GatewayList contains a list of Gateways.
type GatewayList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Gateway `json:"items"`
}

// GatewaySpec defines the desired state of Gateway.
//
// Not all possible combinations of options specified in the Spec are
// valid. Some invalid configurations can be caught synchronously via a
// webhook, but there are many cases that will require asynchronous
// signaling via the GatewayStatus block.
type GatewaySpec struct {
	// GatewayClassName used for this Gateway. This is the name of a
	// GatewayClass resource.
	GatewayClassName ObjectName `json:"gatewayClassName"`

	// Listeners associated with this Gateway. Listeners define
	// logical endpoints that are bound on this Gateway's addresses.
	// At least one Listener MUST be specified.
	//
	// Each listener in a Gateway must have a unique combination of Hostname,
	// Port, and Protocol.
	//
	// An implementation MAY group Listeners by Port and then collapse each
	// group of Listeners into a single Listener if the implementation
	// determines that the Listeners in the group are "compatible". An
	// implementation MAY also group together and collapse compatible
	// Listeners belonging to different Gateways.
	//
	// For example, an implementation might consider Listeners to be
	// compatible with each other if all of the following conditions are
	// met:
	//
	// 1. Either each Listener within the group specifies the "HTTP"
	//    Protocol or each Listener within the group specifies either
	//    the "HTTPS" or "TLS" Protocol.
	//
	// 2. Each Listener within the group specifies a Hostname that is unique
	//    within the group.
	//
	// 3. As a special case, one Listener within a group may omit Hostname,
	//    in which case this Listener matches when no other Listener
	//    matches.
	//
	// If the implementation does collapse compatible Listeners, the
	// hostname provided in the incoming client request MUST be
	// matched to a Listener to find the correct set of Routes.
	// The incoming hostname MUST be matched using the Hostname
	// field for each Listener in order of most to least specific.
	// That is, exact matches must be processed before wildcard
	// matches.
	//
	// If this field specifies multiple Listeners that have the same
	// Port value but are not compatible, the implementation must raise
	// a "Conflicted" condition in the Listener status.
	//
	// Support: Core
	//
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	Listeners []Listener `json:"listeners"`

	// Addresses requested for this Gateway. This is optional and behavior can
	// depend on the implementation. If a value is set in the spec and the
	// requested address is invalid or unavailable, the implementation MUST
	// indicate this in the associated entry in GatewayStatus.Addresses.
	//
	// The Addresses field represents a request for the address(es) on the
	// "outside of the Gateway", that traffic bound for this Gateway will use.
	// This could be the IP address or hostname of an external load balancer or
	// other networking infrastructure, or some other address that traffic will
	// be sent to.
	//
	// The .listener.hostname field is used to route traffic that has already
	// arrived at the Gateway to the correct in-cluster destination.
	//
	// If no Addresses are specified, the implementation MAY schedule the
	// Gateway in an implementation-specific manner, assigning an appropriate
	// set of Addresses.
	//
	// The implementation MUST bind all Listeners to every GatewayAddress that
	// it assigns to the Gateway and add a corresponding entry in
	// GatewayStatus.Addresses.
	//
	// Support: Extended
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Addresses []GatewayAddress `json:"addresses,omitempty"`
}

// Listener embodies the concept of a logical endpoint where a Gateway accepts
// network connections.
type Listener struct {
	// Name is the name of the Listener. This name MUST be unique within a
	// Gateway.
	//
	// Support: Core
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
	// Support: Core
	//
	// +optional
	Hostname *Hostname `json:"hostname,omitempty"`

	// Port is the network port. Multiple listeners may use the
	// same port, subject to the Listener compatibility rules.
	//
	// Support: Core
	Port PortNumber `json:"port"`

	// Protocol specifies the network protocol this listener expects to receive.
	//
	// Support: Core
	Protocol ProtocolType `json:"protocol"`

	// TLS is the TLS configuration for the Listener. This field is required if
	// the Protocol field is "HTTPS" or "TLS". It is invalid to set this field
	// if the Protocol field is "HTTP", "TCP", or "UDP".
	//
	// The association of SNIs to Certificate defined in GatewayTLSConfig is
	// defined based on the Hostname field for this listener.
	//
	// The GatewayClass MUST use the longest matching SNI out of all
	// available certificates for any TLS handshake.
	//
	// Support: Core
	//
	// +optional
	TLS *GatewayTLSConfig `json:"tls,omitempty"`

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
	// Support: Core
	// +kubebuilder:default={namespaces:{from: Same}}
	// +optional
	AllowedRoutes *AllowedRoutes `json:"allowedRoutes,omitempty"`
}

// ProtocolType defines the application protocol accepted by a Listener.
// Implementations are not required to accept all the defined protocols. If an
// implementation does not support a specified protocol, it MUST set the
// "Accepted" condition to False for the affected Listener with a reason of
// "UnsupportedProtocol".
//
// Core ProtocolType values are listed in the table below.
//
// Implementations can define their own protocols if a core ProtocolType does not
// exist. Such definitions must use prefixed name, such as
// `mycompany.com/my-custom-protocol`. Un-prefixed names are reserved for core
// protocols. Any protocol defined by implementations will fall under
// Implementation-specific conformance.
//
// Valid values include:
//
// * "HTTP" - Core support
// * "example.com/bar" - Implementation-specific support
//
// Invalid values include:
//
// * "example.com" - must include path if domain is used
// * "foo.example.com" - must include path if domain is used
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=255
// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zSA-Z0-9]*[a-zA-Z0-9])?$|[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\/[A-Za-z0-9]+$`
type ProtocolType string

const (
	// Accepts cleartext HTTP/1.1 sessions over TCP. Implementations MAY also
	// support HTTP/2 over cleartext. If implementations support HTTP/2 over
	// cleartext on "HTTP" listeners, that MUST be clearly documented by the
	// implementation.
	HTTPProtocolType ProtocolType = "HTTP"

	// Accepts HTTP/1.1 or HTTP/2 sessions over TLS.
	HTTPSProtocolType ProtocolType = "HTTPS"

	// Accepts TLS sessions over TCP.
	TLSProtocolType ProtocolType = "TLS"

	// Accepts TCP sessions.
	TCPProtocolType ProtocolType = "TCP"

	// Accepts UDP packets.
	UDPProtocolType ProtocolType = "UDP"
)

// GatewayTLSConfig describes a TLS configuration.
type GatewayTLSConfig struct {
	// Mode defines the TLS behavior for the TLS session initiated by the client.
	// There are two possible modes:
	//
	// - Terminate: The TLS session between the downstream client
	//   and the Gateway is terminated at the Gateway. This mode requires
	//   certificateRefs to be set and contain at least one element.
	// - Passthrough: The TLS session is NOT terminated by the Gateway. This
	//   implies that the Gateway can't decipher the TLS stream except for
	//   the ClientHello message of the TLS protocol.
	//   CertificateRefs field is ignored in this mode.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:default=Terminate
	Mode *TLSModeType `json:"mode,omitempty"`

	// CertificateRefs contains a series of references to Kubernetes objects that
	// contains TLS certificates and private keys. These certificates are used to
	// establish a TLS handshake for requests that match the hostname of the
	// associated listener.
	//
	// A single CertificateRef to a Kubernetes Secret has "Core" support.
	// Implementations MAY choose to support attaching multiple certificates to
	// a Listener, but this behavior is implementation-specific.
	//
	// References to a resource in different namespace are invalid UNLESS there
	// is a ReferenceGrant in the target namespace that allows the certificate
	// to be attached. If a ReferenceGrant does not allow this reference, the
	// "ResolvedRefs" condition MUST be set to False for this listener with the
	// "RefNotPermitted" reason.
	//
	// This field is required to have at least one element when the mode is set
	// to "Terminate" (default) and is optional otherwise.
	//
	// CertificateRefs can reference to standard Kubernetes resources, i.e.
	// Secret, or implementation-specific custom resources.
	//
	// Support: Core - A single reference to a Kubernetes Secret of type kubernetes.io/tls
	//
	// Support: Implementation-specific (More than one reference or other resource types)
	//
	// +optional
	// +kubebuilder:validation:MaxItems=64
	CertificateRefs []SecretObjectReference `json:"certificateRefs,omitempty"`

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

// TLSModeType type defines how a Gateway handles TLS sessions.
//
// +kubebuilder:validation:Enum=Terminate;Passthrough
type TLSModeType string

const (
	// In this mode, TLS session between the downstream client
	// and the Gateway is terminated at the Gateway.
	TLSModeTerminate TLSModeType = "Terminate"

	// In this mode, the TLS session is NOT terminated by the Gateway. This
	// implies that the Gateway can't decipher the TLS stream except for
	// the ClientHello message of the TLS protocol.
	//
	// Note that SSL passthrough is only supported by TLSRoute.
	TLSModePassthrough TLSModeType = "Passthrough"
)

// AllowedRoutes defines which Routes may be attached to this Listener.
type AllowedRoutes struct {
	// Namespaces indicates namespaces from which Routes may be attached to this
	// Listener. This is restricted to the namespace of this Gateway by default.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:default={from: Same}
	Namespaces *RouteNamespaces `json:"namespaces,omitempty"`

	// Kinds specifies the groups and kinds of Routes that are allowed to bind
	// to this Gateway Listener. When unspecified or empty, the kinds of Routes
	// selected are determined using the Listener protocol.
	//
	// A RouteGroupKind MUST correspond to kinds of Routes that are compatible
	// with the application protocol specified in the Listener's Protocol field.
	// If an implementation does not support or recognize this resource type, it
	// MUST set the "ResolvedRefs" condition to False for this Listener with the
	// "InvalidRouteKinds" reason.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Kinds []RouteGroupKind `json:"kinds,omitempty"`
}

// FromNamespaces specifies namespace from which Routes may be attached to a
// Gateway.
//
// +kubebuilder:validation:Enum=All;Selector;Same
type FromNamespaces string

const (
	// Routes in all namespaces may be attached to this Gateway.
	NamespacesFromAll FromNamespaces = "All"
	// Only Routes in namespaces selected by the selector may be attached to
	// this Gateway.
	NamespacesFromSelector FromNamespaces = "Selector"
	// Only Routes in the same namespace as the Gateway may be attached to this
	// Gateway.
	NamespacesFromSame FromNamespaces = "Same"
)

// RouteNamespaces indicate which namespaces Routes should be selected from.
type RouteNamespaces struct {
	// From indicates where Routes will be selected for this Gateway. Possible
	// values are:
	// * All: Routes in all namespaces may be used by this Gateway.
	// * Selector: Routes in namespaces selected by the selector may be used by
	//   this Gateway.
	// * Same: Only Routes in the same namespace may be used by this Gateway.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:default=Same
	From *FromNamespaces `json:"from,omitempty"`

	// Selector must be specified when From is set to "Selector". In that case,
	// only Routes in Namespaces matching this Selector will be selected by this
	// Gateway. This field is ignored for other values of "From".
	//
	// Support: Core
	//
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// RouteGroupKind indicates the group and kind of a Route resource.
type RouteGroupKind struct {
	// Group is the group of the Route.
	//
	// +optional
	// +kubebuilder:default=gateway.networking.k8s.io
	Group *Group `json:"group,omitempty"`

	// Kind is the kind of the Route.
	Kind Kind `json:"kind"`
}

// GatewayAddress describes an address that can be bound to a Gateway.
type GatewayAddress struct {
	// Type of the address.
	//
	// +optional
	// +kubebuilder:default=IPAddress
	Type *AddressType `json:"type,omitempty"`

	// Value of the address. The validity of the values will depend
	// on the type and support by the controller.
	//
	// Examples: `1.2.3.4`, `128::1`, `my-ip-address`.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Value string `json:"value"`
}

// GatewayStatus defines the observed state of Gateway.
type GatewayStatus struct {
	// Addresses lists the IP addresses that have actually been
	// bound to the Gateway. These addresses may differ from the
	// addresses in the Spec, e.g. if the Gateway automatically
	// assigns an address from a reserved pool.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Addresses []GatewayAddress `json:"addresses,omitempty"`

	// Conditions describe the current conditions of the Gateway.
	//
	// Implementations should prefer to express Gateway conditions
	// using the `GatewayConditionType` and `GatewayConditionReason`
	// constants so that operators and tools can converge on a common
	// vocabulary to describe Gateway state.
	//
	// Known condition types are:
	//
	// * "Accepted"
	// * "Ready"
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
	Listeners []ListenerStatus `json:"listeners,omitempty"`
}

// GatewayConditionType is a type of condition associated with a
// Gateway. This type should be used with the GatewayStatus.Conditions
// field.
type GatewayConditionType string

// GatewayConditionReason defines the set of reasons that explain why a
// particular Gateway condition type has been raised.
type GatewayConditionReason string

const (
	// This condition indicates whether a Gateway has generated some
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
	// * "Pending"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	GatewayConditionProgrammed GatewayConditionType = "Programmed"

	// This reason is used with the "Programmed" condition when the condition is
	// true.
	GatewayReasonProgrammed GatewayConditionReason = "Programmed"

	// This reason is used with the "Programmed" condition when the Listener is
	// syntactically or semantically invalid.
	GatewayReasonInvalid GatewayConditionReason = "Invalid"
)

const (
	// This condition is true when the controller managing the Gateway is
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
	// * "NotReconciled"
	// * "NoResources"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	GatewayConditionAccepted GatewayConditionType = "Accepted"

	// Deprecated: use "Accepted" instead.
	GatewayConditionScheduled GatewayConditionType = "Scheduled"

	// This reason is used with the "Accepted" condition when the condition is
	// True.
	GatewayReasonAccepted GatewayConditionReason = "Accepted"

	// This reason is used with the "Scheduled" condition when the condition is
	// True.
	//
	// Deprecated: use the "Accepted" condition with reason "Accepted" instead.
	GatewayReasonScheduled GatewayConditionReason = "Scheduled"

	// This reason is used with the "Accepted", "Programmed" and "Ready"
	// conditions when the status is "Unknown" and no controller has reconciled
	// the Gateway.
	GatewayReasonPending GatewayConditionReason = "Pending"

	// Deprecated: Use "Pending" instead.
	GatewayReasonNotReconciled GatewayConditionReason = "NotReconciled"

	// This reason is used with the "Accepted" condition when the
	// Gateway is not scheduled because insufficient infrastructure
	// resources are available.
	GatewayReasonNoResources GatewayConditionReason = "NoResources"
)

const (
	// Ready is an optional Condition that has Extended support. When it's set,
	// the condition indicates whether the Gateway has been completely configured
	// and traffic is ready to flow through the data plane immediately.
	//
	// If both the "ListenersNotValid" and "ListenersNotReady"
	// reasons are true, the Gateway controller should prefer the
	// "ListenersNotValid" reason.
	//
	// Possible reasons for this condition to be true are:
	//
	// * "Ready"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "ListenersNotValid"
	// * "ListenersNotReady"
	// * "AddressNotAssigned"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	GatewayConditionReady GatewayConditionType = "Ready"

	// This reason is used with the "Ready" condition when the condition is
	// true.
	GatewayReasonReady GatewayConditionReason = "Ready"

	// This reason is used with the "Ready" condition when one or
	// more Listeners have an invalid or unsupported configuration
	// and cannot be configured on the Gateway.
	GatewayReasonListenersNotValid GatewayConditionReason = "ListenersNotValid"

	// This reason is used with the "Ready" condition when one or
	// more Listeners are not ready to serve traffic.
	GatewayReasonListenersNotReady GatewayConditionReason = "ListenersNotReady"

	// This reason is used with the "Ready" condition when none of the requested
	// addresses have been assigned to the Gateway. This reason can be used to
	// express a range of circumstances, including (but not limited to) IPAM
	// address exhaustion, invalid or unsupported address requests, or a named
	// address not being found.
	GatewayReasonAddressNotAssigned GatewayConditionReason = "AddressNotAssigned"
)

// ListenerStatus is the status associated with a Listener.
type ListenerStatus struct {
	// Name is the name of the Listener that this status corresponds to.
	Name SectionName `json:"name"`

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
	// +kubebuilder:validation:MaxItems=8
	SupportedKinds []RouteGroupKind `json:"supportedKinds"`

	// AttachedRoutes represents the total number of Routes that have been
	// successfully attached to this Listener.
	AttachedRoutes int32 `json:"attachedRoutes"`

	// Conditions describe the current condition of this listener.
	//
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	Conditions []metav1.Condition `json:"conditions"`
}

// ListenerConditionType is a type of condition associated with the
// listener. This type should be used with the ListenerStatus.Conditions
// field.
type ListenerConditionType string

// ListenerConditionReason defines the set of reasons that explain
// why a particular Listener condition type has been raised.
type ListenerConditionReason string

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
	//
	// Possible reasons for this condition to be False are:
	//
	// * "NoConflicts"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerConditionConflicted ListenerConditionType = "Conflicted"

	// This reason is used with the "Conflicted" condition when
	// the Listener conflicts with hostnames in other Listeners. For
	// example, this reason would be used when multiple Listeners on
	// the same port use `example.com` in the hostname field.
	ListenerReasonHostnameConflict ListenerConditionReason = "HostnameConflict"

	// This reason is used with the "Conflicted" condition when
	// multiple Listeners are specified with the same Listener port
	// number, but have conflicting protocol specifications.
	ListenerReasonProtocolConflict ListenerConditionReason = "ProtocolConflict"

	// This reason is used with the "Conflicted" condition when the condition
	// is False.
	ListenerReasonNoConflicts ListenerConditionReason = "NoConflicts"
)

const (
	// This condition indicates that, even though the listener is
	// syntactically and semantically valid, the controller is not able
	// to configure it on the underlying Gateway infrastructure.
	//
	// A Listener is specified as a logical requirement, but needs to be
	// configured on a network endpoint (i.e. address and port) by a
	// controller. The controller may be unable to attach the Listener
	// if it specifies an unsupported requirement, or prerequisite
	// resources are not available.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Accepted"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "PortUnavailable"
	// * "UnsupportedProtocol"
	// * "UnsupportedAddress"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerConditionAccepted ListenerConditionType = "Accepted"

	// Deprecated: use "Accepted" instead.
	ListenerConditionDetached ListenerConditionType = "Detached"

	// This reason is used with the "Accepted" condition when the condition is
	// True.
	ListenerReasonAccepted ListenerConditionReason = "Accepted"

	// This reason is used with the "Detached" condition when the condition is
	// False.
	//
	// Deprecated: use the "Accepted" condition with reason "Accepted" instead.
	ListenerReasonAttached ListenerConditionReason = "Attached"

	// This reason is used with the "Accepted" condition when the Listener
	// requests a port that cannot be used on the Gateway. This reason could be
	// used in a number of instances, including:
	//
	// * The port is already in use.
	// * The port is not supported by the implementation.
	ListenerReasonPortUnavailable ListenerConditionReason = "PortUnavailable"

	// This reason is used with the "Accepted" condition when the
	// Listener could not be attached to be Gateway because its
	// protocol type is not supported.
	ListenerReasonUnsupportedProtocol ListenerConditionReason = "UnsupportedProtocol"

	// This reason is used with the "Accepted" condition when the Listener could
	// not be attached to the Gateway because the requested address is not
	// supported. This reason could be used in a number of instances, including:
	//
	// * The address is already in use.
	// * The type of address is not supported by the implementation.
	ListenerReasonUnsupportedAddress ListenerConditionReason = "UnsupportedAddress"
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
	ListenerConditionResolvedRefs ListenerConditionType = "ResolvedRefs"

	// This reason is used with the "ResolvedRefs" condition when the condition
	// is true.
	ListenerReasonResolvedRefs ListenerConditionReason = "ResolvedRefs"

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
	ListenerReasonInvalidCertificateRef ListenerConditionReason = "InvalidCertificateRef"

	// This reason is used with the "ResolvedRefs" condition when an invalid or
	// unsupported Route kind is specified by the Listener.
	ListenerReasonInvalidRouteKinds ListenerConditionReason = "InvalidRouteKinds"

	// This reason is used with the "ResolvedRefs" condition when the
	// Listener has a TLS configuration that references an object in another
	// namespace, where the object in the other namespace does not have a
	// ReferenceGrant explicitly allowing the reference.
	ListenerReasonRefNotPermitted ListenerConditionReason = "RefNotPermitted"
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
	// * "Pending"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerConditionProgrammed ListenerConditionType = "Programmed"

	// This reason is used with the "Programmed" condition when the condition is
	// true.
	ListenerReasonProgrammed ListenerConditionReason = "Programmed"
)

const (
	// Ready is an optional Condition that has Extended support. When it's set,
	// the condition indicates whether the Listener has been configured on the
	// Gateway and traffic is ready to flow through the data plane immediately.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "Ready"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Invalid"
	// * "Pending"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	ListenerConditionReady ListenerConditionType = "Ready"

	// This reason is used with the "Ready" condition when the condition is
	// true.
	ListenerReasonReady ListenerConditionReason = "Ready"

	// This reason is used with the "Ready" and "Programmed" conditions when the
	// Listener is syntactically or semantically invalid.
	ListenerReasonInvalid ListenerConditionReason = "Invalid"

	// This reason is used with the "Accepted", "Ready" and "Programmed"
	// conditions when the Listener is either not yet reconciled or not yet not
	// online and ready to accept client traffic.
	ListenerReasonPending ListenerConditionReason = "Pending"
)
