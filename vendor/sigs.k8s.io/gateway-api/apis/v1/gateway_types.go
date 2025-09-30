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

package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api,shortName=gtw
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Class",type=string,JSONPath=`.spec.gatewayClassName`
// +kubebuilder:printcolumn:name="Address",type=string,JSONPath=`.status.addresses[*].value`
// +kubebuilder:printcolumn:name="Programmed",type=string,JSONPath=`.status.conditions[?(@.type=="Programmed")].status`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// Gateway represents an instance of a service-traffic handling infrastructure
// by binding Listeners to a set of IP addresses.
type Gateway struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of Gateway.
	// +required
	Spec GatewaySpec `json:"spec"`

	// Status defines the current state of Gateway.
	//
	// +kubebuilder:default={conditions: {{type: "Accepted", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"},{type: "Programmed", status: "Unknown", reason:"Pending", message:"Waiting for controller", lastTransitionTime: "1970-01-01T00:00:00Z"}}}
	// +optional
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
// valid. Some invalid configurations can be caught synchronously via CRD
// validation, but there are many cases that will require asynchronous
// signaling via the GatewayStatus block.
type GatewaySpec struct {
	// GatewayClassName used for this Gateway. This is the name of a
	// GatewayClass resource.
	// +required
	GatewayClassName ObjectName `json:"gatewayClassName"`

	// Listeners associated with this Gateway. Listeners define
	// logical endpoints that are bound on this Gateway's addresses.
	// At least one Listener MUST be specified.
	//
	// ## Distinct Listeners
	//
	// Each Listener in a set of Listeners (for example, in a single Gateway)
	// MUST be _distinct_, in that a traffic flow MUST be able to be assigned to
	// exactly one listener. (This section uses "set of Listeners" rather than
	// "Listeners in a single Gateway" because implementations MAY merge configuration
	// from multiple Gateways onto a single data plane, and these rules _also_
	// apply in that case).
	//
	// Practically, this means that each listener in a set MUST have a unique
	// combination of Port, Protocol, and, if supported by the protocol, Hostname.
	//
	// Some combinations of port, protocol, and TLS settings are considered
	// Core support and MUST be supported by implementations based on the objects
	// they support:
	//
	// HTTPRoute
	//
	// 1. HTTPRoute, Port: 80, Protocol: HTTP
	// 2. HTTPRoute, Port: 443, Protocol: HTTPS, TLS Mode: Terminate, TLS keypair provided
	//
	// TLSRoute
	//
	// 1. TLSRoute, Port: 443, Protocol: TLS, TLS Mode: Passthrough
	//
	// "Distinct" Listeners have the following property:
	//
	// **The implementation can match inbound requests to a single distinct
	// Listener**.
	//
	// When multiple Listeners share values for fields (for
	// example, two Listeners with the same Port value), the implementation
	// can match requests to only one of the Listeners using other
	// Listener fields.
	//
	// When multiple listeners have the same value for the Protocol field, then
	// each of the Listeners with matching Protocol values MUST have different
	// values for other fields.
	//
	// The set of fields that MUST be different for a Listener differs per protocol.
	// The following rules define the rules for what fields MUST be considered for
	// Listeners to be distinct with each protocol currently defined in the
	// Gateway API spec.
	//
	// The set of listeners that all share a protocol value MUST have _different_
	// values for _at least one_ of these fields to be distinct:
	//
	// * **HTTP, HTTPS, TLS**: Port, Hostname
	// * **TCP, UDP**: Port
	//
	// One **very** important rule to call out involves what happens when an
	// implementation:
	//
	// * Supports TCP protocol Listeners, as well as HTTP, HTTPS, or TLS protocol
	//   Listeners, and
	// * sees HTTP, HTTPS, or TLS protocols with the same `port` as one with TCP
	//   Protocol.
	//
	// In this case all the Listeners that share a port with the
	// TCP Listener are not distinct and so MUST NOT be accepted.
	//
	// If an implementation does not support TCP Protocol Listeners, then the
	// previous rule does not apply, and the TCP Listeners SHOULD NOT be
	// accepted.
	//
	// Note that the `tls` field is not used for determining if a listener is distinct, because
	// Listeners that _only_ differ on TLS config will still conflict in all cases.
	//
	// ### Listeners that are distinct only by Hostname
	//
	// When the Listeners are distinct based only on Hostname, inbound request
	// hostnames MUST match from the most specific to least specific Hostname
	// values to choose the correct Listener and its associated set of Routes.
	//
	// Exact matches MUST be processed before wildcard matches, and wildcard
	// matches MUST be processed before fallback (empty Hostname value)
	// matches. For example, `"foo.example.com"` takes precedence over
	// `"*.example.com"`, and `"*.example.com"` takes precedence over `""`.
	//
	// Additionally, if there are multiple wildcard entries, more specific
	// wildcard entries must be processed before less specific wildcard entries.
	// For example, `"*.foo.example.com"` takes precedence over `"*.example.com"`.
	//
	// The precise definition here is that the higher the number of dots in the
	// hostname to the right of the wildcard character, the higher the precedence.
	//
	// The wildcard character will match any number of characters _and dots_ to
	// the left, however, so `"*.example.com"` will match both
	// `"foo.bar.example.com"` _and_ `"bar.example.com"`.
	//
	// ## Handling indistinct Listeners
	//
	// If a set of Listeners contains Listeners that are not distinct, then those
	// Listeners are _Conflicted_, and the implementation MUST set the "Conflicted"
	// condition in the Listener Status to "True".
	//
	// The words "indistinct" and "conflicted" are considered equivalent for the
	// purpose of this documentation.
	//
	// Implementations MAY choose to accept a Gateway with some Conflicted
	// Listeners only if they only accept the partial Listener set that contains
	// no Conflicted Listeners.
	//
	// Specifically, an implementation MAY accept a partial Listener set subject to
	// the following rules:
	//
	// * The implementation MUST NOT pick one conflicting Listener as the winner.
	//   ALL indistinct Listeners must not be accepted for processing.
	// * At least one distinct Listener MUST be present, or else the Gateway effectively
	//   contains _no_ Listeners, and must be rejected from processing as a whole.
	//
	// The implementation MUST set a "ListenersNotValid" condition on the
	// Gateway Status when the Gateway contains Conflicted Listeners whether or
	// not they accept the Gateway. That Condition SHOULD clearly
	// indicate in the Message which Listeners are conflicted, and which are
	// Accepted. Additionally, the Listener status for those listeners SHOULD
	// indicate which Listeners are conflicted and not Accepted.
	//
	// ## General Listener behavior
	//
	// Note that, for all distinct Listeners, requests SHOULD match at most one Listener.
	// For example, if Listeners are defined for "foo.example.com" and "*.example.com", a
	// request to "foo.example.com" SHOULD only be routed using routes attached
	// to the "foo.example.com" Listener (and not the "*.example.com" Listener).
	//
	// This concept is known as "Listener Isolation", and it is an Extended feature
	// of Gateway API. Implementations that do not support Listener Isolation MUST
	// clearly document this, and MUST NOT claim support for the
	// `GatewayHTTPListenerIsolation` feature.
	//
	// Implementations that _do_ support Listener Isolation SHOULD claim support
	// for the Extended `GatewayHTTPListenerIsolation` feature and pass the associated
	// conformance tests.
	//
	// ## Compatible Listeners
	//
	// A Gateway's Listeners are considered _compatible_ if:
	//
	// 1. They are distinct.
	// 2. The implementation can serve them in compliance with the Addresses
	//    requirement that all Listeners are available on all assigned
	//    addresses.
	//
	// Compatible combinations in Extended support are expected to vary across
	// implementations. A combination that is compatible for one implementation
	// may not be compatible for another.
	//
	// For example, an implementation that cannot serve both TCP and UDP listeners
	// on the same address, or cannot mix HTTPS and generic TLS listens on the same port
	// would not consider those cases compatible, even though they are distinct.
	//
	// Implementations MAY merge separate Gateways onto a single set of
	// Addresses if all Listeners across all Gateways are compatible.
	//
	// In a future release the MinItems=1 requirement MAY be dropped.
	//
	// Support: Core
	//
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:message="tls must not be specified for protocols ['HTTP', 'TCP', 'UDP']",rule="self.all(l, l.protocol in ['HTTP', 'TCP', 'UDP'] ? !has(l.tls) : true)"
	// +kubebuilder:validation:XValidation:message="tls mode must be Terminate for protocol HTTPS",rule="self.all(l, (l.protocol == 'HTTPS' && has(l.tls)) ? (l.tls.mode == '' || l.tls.mode == 'Terminate') : true)"
	// +kubebuilder:validation:XValidation:message="hostname must not be specified for protocols ['TCP', 'UDP']",rule="self.all(l, l.protocol in ['TCP', 'UDP']  ? (!has(l.hostname) || l.hostname == '') : true)"
	// +kubebuilder:validation:XValidation:message="Listener name must be unique within the Gateway",rule="self.all(l1, self.exists_one(l2, l1.name == l2.name))"
	// +kubebuilder:validation:XValidation:message="Combination of port, protocol and hostname must be unique for each listener",rule="self.all(l1, self.exists_one(l2, l1.port == l2.port && l1.protocol == l2.protocol && (has(l1.hostname) && has(l2.hostname) ? l1.hostname == l2.hostname : !has(l1.hostname) && !has(l2.hostname))))"
	// +required
	Listeners []Listener `json:"listeners"`

	// Addresses requested for this Gateway. This is optional and behavior can
	// depend on the implementation. If a value is set in the spec and the
	// requested address is invalid or unavailable, the implementation MUST
	// indicate this in an associated entry in GatewayStatus.Conditions.
	//
	// The Addresses field represents a request for the address(es) on the
	// "outside of the Gateway", that traffic bound for this Gateway will use.
	// This could be the IP address or hostname of an external load balancer or
	// other networking infrastructure, or some other address that traffic will
	// be sent to.
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
	// +listType=atomic
	// <gateway:validateIPAddress>
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="IPAddress values must be unique",rule="self.all(a1, a1.type == 'IPAddress' && has(a1.value) ? self.exists_one(a2, a2.type == a1.type && has(a2.value) && a2.value == a1.value) : true )"
	// +kubebuilder:validation:XValidation:message="Hostname values must be unique",rule="self.all(a1, a1.type == 'Hostname'  && has(a1.value) ? self.exists_one(a2, a2.type == a1.type && has(a2.value) && a2.value == a1.value) : true )"
	Addresses []GatewaySpecAddress `json:"addresses,omitempty"`

	// Infrastructure defines infrastructure level attributes about this Gateway instance.
	//
	// Support: Extended
	//
	// +optional
	Infrastructure *GatewayInfrastructure `json:"infrastructure,omitempty"`

	// AllowedListeners defines which ListenerSets can be attached to this Gateway.
	// While this feature is experimental, the default value is to allow no ListenerSets.
	//
	// <gateway:experimental>
	//
	// +optional
	AllowedListeners *AllowedListeners `json:"allowedListeners,omitempty"`
	//
	// TLS specifies frontend and backend tls configuration for entire gateway.
	//
	// Support: Extended
	//
	// +optional
	// <gateway:experimental>
	TLS *GatewayTLSConfig `json:"tls,omitempty"`

	// DefaultScope, when set, configures the Gateway as a default Gateway,
	// meaning it will dynamically and implicitly have Routes (e.g. HTTPRoute)
	// attached to it, according to the scope configured here.
	//
	// If unset (the default) or set to None, the Gateway will not act as a
	// default Gateway; if set, the Gateway will claim any Route with a
	// matching scope set in its UseDefaultGateway field, subject to the usual
	// rules about which routes the Gateway can attach to.
	//
	// Think carefully before using this functionality! While the normal rules
	// about which Route can apply are still enforced, it is simply easier for
	// the wrong Route to be accidentally attached to this Gateway in this
	// configuration. If the Gateway operator is not also the operator in
	// control of the scope (e.g. namespace) with tight controls and checks on
	// what kind of workloads and Routes get added in that scope, we strongly
	// recommend not using this just because it seems convenient, and instead
	// stick to direct Route attachment.
	//
	// +optional
	// <gateway:experimental>
	DefaultScope GatewayDefaultScope `json:"defaultScope,omitempty"`
}

// AllowedListeners defines which ListenerSets can be attached to this Gateway.
type AllowedListeners struct {
	// Namespaces defines which namespaces ListenerSets can be attached to this Gateway.
	// While this feature is experimental, the default value is to allow no ListenerSets.
	//
	// +optional
	// +kubebuilder:default={from: None}
	Namespaces *ListenerNamespaces `json:"namespaces,omitempty"`
}

// ListenerNamespaces indicate which namespaces ListenerSets should be selected from.
type ListenerNamespaces struct {
	// From indicates where ListenerSets can attach to this Gateway. Possible
	// values are:
	//
	// * Same: Only ListenerSets in the same namespace may be attached to this Gateway.
	// * Selector: ListenerSets in namespaces selected by the selector may be attached to this Gateway.
	// * All: ListenerSets in all namespaces may be attached to this Gateway.
	// * None: Only listeners defined in the Gateway's spec are allowed
	//
	// While this feature is experimental, the default value None
	//
	// +optional
	// +kubebuilder:default=None
	// +kubebuilder:validation:Enum=All;Selector;Same;None
	From *FromNamespaces `json:"from,omitempty"`

	// Selector must be specified when From is set to "Selector". In that case,
	// only ListenerSets in Namespaces matching this Selector will be selected by this
	// Gateway. This field is ignored for other values of "From".
	//
	// +optional
	Selector *metav1.LabelSelector `json:"selector,omitempty"`
}

// Listener embodies the concept of a logical endpoint where a Gateway accepts
// network connections.
type Listener struct {
	// Name is the name of the Listener. This name MUST be unique within a
	// Gateway.
	//
	// Support: Core
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
	// * HTTPS: The Listener Hostname SHOULD match both the SNI and Host header.
	//   Note that this does not require the SNI and Host header to be the same.
	//   The semantics of this are described in more detail below.
	//
	// To ensure security, Section 11.1 of RFC-6066 emphasizes that server
	// implementations that rely on SNI hostname matching MUST also verify
	// hostnames within the application protocol.
	//
	// Section 9.1.2 of RFC-7540 provides a mechanism for servers to reject the
	// reuse of a connection by responding with the HTTP 421 Misdirected Request
	// status code. This indicates that the origin server has rejected the
	// request because it appears to have been misdirected.
	//
	// To detect misdirected requests, Gateways SHOULD match the authority of
	// the requests with all the SNI hostname(s) configured across all the
	// Gateway Listeners on the same port and protocol:
	//
	// * If another Listener has an exact match or more specific wildcard entry,
	//   the Gateway SHOULD return a 421.
	// * If the current Listener (selected by SNI matching during ClientHello)
	//   does not match the Host:
	//     * If another Listener does match the Host the Gateway SHOULD return a
	//       421.
	//     * If no other Listener matches the Host, the Gateway MUST return a
	//       404.
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
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	//
	// +required
	Port PortNumber `json:"port"`

	// Protocol specifies the network protocol this listener expects to receive.
	//
	// Support: Core
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
	// Support: Core
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
// +kubebuilder:validation:Pattern=`^[a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?$|[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*\/[A-Za-z0-9]+$`
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

// GatewayBackendTLS describes backend TLS configuration for gateway.
type GatewayBackendTLS struct {
	// ClientCertificateRef is a reference to an object that contains a Client
	// Certificate and the associated private key.
	//
	// References to a resource in different namespace are invalid UNLESS there
	// is a ReferenceGrant in the target namespace that allows the certificate
	// to be attached. If a ReferenceGrant does not allow this reference, the
	// "ResolvedRefs" condition MUST be set to False for this listener with the
	// "RefNotPermitted" reason.
	//
	// ClientCertificateRef can reference to standard Kubernetes resources, i.e.
	// Secret, or implementation-specific custom resources.
	//
	// Support: Core
	//
	// +optional
	// <gateway:experimental>
	ClientCertificateRef *SecretObjectReference `json:"clientCertificateRef,omitempty"`
}

// ListenerTLSConfig describes a TLS configuration for a listener.
//
// +kubebuilder:validation:XValidation:message="certificateRefs or options must be specified when mode is Terminate",rule="self.mode == 'Terminate' ? size(self.certificateRefs) > 0 || size(self.options) > 0 : true"
type ListenerTLSConfig struct {
	// Mode defines the TLS behavior for the TLS session initiated by the client.
	// There are two possible modes:
	//
	// - Terminate: The TLS session between the downstream client and the
	//   Gateway is terminated at the Gateway. This mode requires certificates
	//   to be specified in some way, such as populating the certificateRefs
	//   field.
	// - Passthrough: The TLS session is NOT terminated by the Gateway. This
	//   implies that the Gateway can't decipher the TLS stream except for
	//   the ClientHello message of the TLS protocol. The certificateRefs field
	//   is ignored in this mode.
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
	// +listType=atomic
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

// GatewayTLSConfig specifies frontend and backend tls configuration for gateway.
type GatewayTLSConfig struct {
	// Backend describes TLS configuration for gateway when connecting
	// to backends.
	//
	// Note that this contains only details for the Gateway as a TLS client,
	// and does _not_ imply behavior about how to choose which backend should
	// get a TLS connection. That is determined by the presence of a BackendTLSPolicy.
	//
	// Support: Core
	//
	// +optional
	// <gateway:experimental>
	Backend *GatewayBackendTLS `json:"backend,omitempty"`

	// Frontend describes TLS config when client connects to Gateway.
	// Support: Core
	//
	// +optional
	// <gateway:experimental>
	Frontend *FrontendTLSConfig `json:"frontend,omitempty"`
}

// FrontendTLSConfig specifies frontend tls configuration for gateway.
type FrontendTLSConfig struct {
	// Default specifies the default client certificate validation configuration
	// for all Listeners handling HTTPS traffic, unless a per-port configuration
	// is defined.
	//
	// support: Core
	//
	// +required
	// <gateway:experimental>
	Default TLSConfig `json:"default"`

	// PerPort specifies tls configuration assigned per port.
	// Per port configuration is optional. Once set this configuration overrides
	// the default configuration for all Listeners handling HTTPS traffic
	// that match this port.
	// Each override port requires a unique TLS configuration.
	//
	// support: Core
	//
	// +optional
	// +listType=map
	// +listMapKey=port
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:message="Port for TLS configuration must be unique within the Gateway",rule="self.all(t1, self.exists_one(t2, t1.port == t2.port))"
	// <gateway:experimental>
	PerPort []TLSPortConfig `json:"perPort,omitempty"`
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

// TLSConfig describes TLS configuration that can apply to multiple Listeners
// within this Gateway. Currently, it stores only the client certificate validation
// configuration, but this may be extended in the future.
type TLSConfig struct {
	// Validation holds configuration information for validating the frontend (client).
	// Setting this field will result in mutual authentication when connecting to the gateway.
	// In browsers this may result in a dialog appearing
	// that requests a user to specify the client certificate.
	// The maximum depth of a certificate chain accepted in verification is Implementation specific.
	//
	// Support: Core
	//
	// +optional
	// <gateway:experimental>
	Validation *FrontendTLSValidation `json:"validation,omitempty"`
}

type TLSPortConfig struct {
	// The Port indicates the Port Number to which the TLS configuration will be
	// applied. This configuration will be applied to all Listeners handling HTTPS
	// traffic that match this port.
	//
	// Support: Core
	//
	// +required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	// <gateway:experimental>
	Port PortNumber `json:"port"`

	// TLS store the configuration that will be applied to all Listeners handling
	// HTTPS traffic and matching given port.
	//
	// Support: Core
	//
	// +required
	// <gateway:experimental>
	TLS TLSConfig `json:"tls"`
}

// FrontendTLSValidation holds configuration information that can be used to validate
// the frontend initiating the TLS connection
type FrontendTLSValidation struct {
	// CACertificateRefs contains one or more references to
	// Kubernetes objects that contain TLS certificates of
	// the Certificate Authorities that can be used
	// as a trust anchor to validate the certificates presented by the client.
	//
	// A single CA certificate reference to a Kubernetes ConfigMap
	// has "Core" support.
	// Implementations MAY choose to support attaching multiple CA certificates to
	// a Listener, but this behavior is implementation-specific.
	//
	// Support: Core - A single reference to a Kubernetes ConfigMap
	// with the CA certificate in a key named `ca.crt`.
	//
	// Support: Implementation-specific (More than one certificate in a ConfigMap
	// with different keys or more than one reference, or other kinds of resources).
	//
	// References to a resource in a different namespace are invalid UNLESS there
	// is a ReferenceGrant in the target namespace that allows the certificate
	// to be attached. If a ReferenceGrant does not allow this reference, the
	// "ResolvedRefs" condition MUST be set to False for this listener with the
	// "RefNotPermitted" reason.
	//
	// +required
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:validation:MinItems=1
	CACertificateRefs []ObjectReference `json:"caCertificateRefs"`

	// FrontendValidationMode defines the mode for validating the client certificate.
	// There are two possible modes:
	//
	// - AllowValidOnly: In this mode, the gateway will accept connections only if
	//   the client presents a valid certificate. This certificate must successfully
	//   pass validation against the CA certificates specified in `CACertificateRefs`.
	// - AllowInsecureFallback: In this mode, the gateway will accept connections
	//   even if the client certificate is not presented or fails verification.
	//
	//   This approach delegates client authorization to the backend and introduce
	//   a significant security risk. It should be used in testing environments or
	//   on a temporary basis in non-testing environments.
	//
	// Defaults to AllowValidOnly.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:default=AllowValidOnly
	Mode FrontendValidationModeType `json:"mode,omitempty"`
}

// FrontendValidationModeType type defines how a Gateway validates client certificates.
//
// +kubebuilder:validation:Enum=AllowValidOnly;AllowInsecureFallback
type FrontendValidationModeType string

const (
	// AllowValidOnly indicates that a client certificate is required
	// during the TLS handshake and MUST pass validation.
	//
	// Support: Core
	AllowValidOnly FrontendValidationModeType = "AllowValidOnly"

	// AllowInsecureFallback indicates that a client certificate may not be
	// presented during the handshake or the validation against CA certificates may fail.
	//
	// Support: Extended
	AllowInsecureFallback FrontendValidationModeType = "AllowInsecureFallback"
)

// AllowedRoutes defines which Routes may be attached to this Listener.
type AllowedRoutes struct {
	// Namespaces indicates namespaces from which Routes may be attached to this
	// Listener. This is restricted to the namespace of this Gateway by default.
	//
	// Support: Core
	//
	// +optional
	// +listType=atomic
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
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=8
	Kinds []RouteGroupKind `json:"kinds,omitempty"`
}

// FromNamespaces specifies namespace from which Routes/ListenerSets may be attached to a
// Gateway.
type FromNamespaces string

const (
	// Routes/ListenerSets in all namespaces may be attached to this Gateway.
	NamespacesFromAll FromNamespaces = "All"
	// Only Routes/ListenerSets in namespaces selected by the selector may be attached to
	// this Gateway.
	NamespacesFromSelector FromNamespaces = "Selector"
	// Only Routes/ListenerSets in the same namespace as the Gateway may be attached to this
	// Gateway.
	NamespacesFromSame FromNamespaces = "Same"
	// No Routes/ListenerSets may be attached to this Gateway.
	NamespacesFromNone FromNamespaces = "None"
)

// RouteNamespaces indicate which namespaces Routes should be selected from.
type RouteNamespaces struct {
	// From indicates where Routes will be selected for this Gateway. Possible
	// values are:
	//
	// * All: Routes in all namespaces may be used by this Gateway.
	// * Selector: Routes in namespaces selected by the selector may be used by
	//   this Gateway.
	// * Same: Only Routes in the same namespace may be used by this Gateway.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:default=Same
	// +kubebuilder:validation:Enum=All;Selector;Same
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
	// +required
	Kind Kind `json:"kind"`
}

// GatewaySpecAddress describes an address that can be bound to a Gateway.
//
// +kubebuilder:validation:XValidation:message="Hostname value must be empty or contain only valid characters (matching ^(\\*\\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$)",rule="self.type == 'Hostname' ? (!has(self.value) || self.value.matches(r\"\"\"^(\\*\\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$\"\"\")): true"
type GatewaySpecAddress struct {
	// Type of the address.
	//
	// +optional
	// +kubebuilder:default=IPAddress
	Type *AddressType `json:"type,omitempty"`

	// When a value is unspecified, an implementation SHOULD automatically
	// assign an address matching the requested type if possible.
	//
	// If an implementation does not support an empty value, they MUST set the
	// "Programmed" condition in status to False with a reason of "AddressNotAssigned".
	//
	// Examples: `1.2.3.4`, `128::1`, `my-ip-address`.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=253
	Value string `json:"value,omitempty"`
}

// GatewayStatusAddress describes a network address that is bound to a Gateway.
//
// +kubebuilder:validation:XValidation:message="Hostname value must only contain valid characters (matching ^(\\*\\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$)",rule="self.type == 'Hostname' ? self.value.matches(r\"\"\"^(\\*\\.)?[a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$\"\"\"): true"
type GatewayStatusAddress struct {
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
	// +required
	Value string `json:"value"`
}

// GatewayStatus defines the observed state of Gateway.
type GatewayStatus struct {
	// Addresses lists the network addresses that have been bound to the
	// Gateway.
	//
	// This list may differ from the addresses provided in the spec under some
	// conditions:
	//
	//   * no addresses are specified, all addresses are dynamically assigned
	//   * a combination of specified and dynamic addresses are assigned
	//   * a specified address was unusable (e.g. already in use)
	//
	// +optional
	// +listType=atomic
	// <gateway:validateIPAddress>
	// +kubebuilder:validation:MaxItems=16
	Addresses []GatewayStatusAddress `json:"addresses,omitempty"`

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
	// * "Programmed"
	// * "Ready"
	//
	// <gateway:util:excludeFromCRD>
	// Notes for implementors:
	//
	// Conditions are a listType `map`, which means that they function like a
	// map with a key of the `type` field _in the k8s apiserver_.
	//
	// This means that implementations must obey some rules when updating this
	// section.
	//
	// * Implementations MUST perform a read-modify-write cycle on this field
	//   before modifying it. That is, when modifying this field, implementations
	//   must be confident they have fetched the most recent version of this field,
	//   and ensure that changes they make are on that recent version.
	// * Implementations MUST NOT remove or reorder Conditions that they are not
	//   directly responsible for. For example, if an implementation sees a Condition
	//   with type `special.io/SomeField`, it MUST NOT remove, change or update that
	//   Condition.
	// * Implementations MUST always _merge_ changes into Conditions of the same Type,
	//   rather than creating more than one Condition of the same Type.
	// * Implementations MUST always update the `observedGeneration` field of the
	//   Condition to the `metadata.generation` of the Gateway at the time of update creation.
	// * If the `observedGeneration` of a Condition is _greater than_ the value the
	//   implementation knows about, then it MUST NOT perform the update on that Condition,
	//   but must wait for a future reconciliation and status update. (The assumption is that
	//   the implementation's copy of the object is stale and an update will be re-triggered
	//   if relevant.)
	// </gateway:util:excludeFromCRD>
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

// GatewayInfrastructure defines infrastructure level attributes about a Gateway instance.
type GatewayInfrastructure struct {
	// Labels that SHOULD be applied to any resources created in response to this Gateway.
	//
	// For implementations creating other Kubernetes objects, this should be the `metadata.labels` field on resources.
	// For other implementations, this refers to any relevant (implementation specific) "labels" concepts.
	//
	// An implementation may chose to add additional implementation-specific labels as they see fit.
	//
	// If an implementation maps these labels to Pods, or any other resource that would need to be recreated when labels
	// change, it SHOULD clearly warn about this behavior in documentation.
	//
	// Support: Extended
	//
	// +optional
	// +kubebuilder:validation:MaxProperties=8
	// +kubebuilder:validation:XValidation:message="Label keys must be in the form of an optional DNS subdomain prefix followed by a required name segment of up to 63 characters.",rule="self.all(key, key.matches(r\"\"\"^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?([A-Za-z0-9][-A-Za-z0-9_.]{0,61})?[A-Za-z0-9]$\"\"\"))"
	// +kubebuilder:validation:XValidation:message="If specified, the label key's prefix must be a DNS subdomain not longer than 253 characters in total.",rule="self.all(key, key.split(\"/\")[0].size() < 253)"
	Labels map[LabelKey]LabelValue `json:"labels,omitempty"`

	// Annotations that SHOULD be applied to any resources created in response to this Gateway.
	//
	// For implementations creating other Kubernetes objects, this should be the `metadata.annotations` field on resources.
	// For other implementations, this refers to any relevant (implementation specific) "annotations" concepts.
	//
	// An implementation may chose to add additional implementation-specific annotations as they see fit.
	//
	// Support: Extended
	//
	// +optional
	// +kubebuilder:validation:MaxProperties=8
	// +kubebuilder:validation:XValidation:message="Annotation keys must be in the form of an optional DNS subdomain prefix followed by a required name segment of up to 63 characters.",rule="self.all(key, key.matches(r\"\"\"^([a-z0-9]([-a-z0-9]*[a-z0-9])?(\\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*/)?([A-Za-z0-9][-A-Za-z0-9_.]{0,61})?[A-Za-z0-9]$\"\"\"))"
	// +kubebuilder:validation:XValidation:message="If specified, the annotation key's prefix must be a DNS subdomain not longer than 253 characters in total.",rule="self.all(key, key.split(\"/\")[0].size() < 253)"
	Annotations map[AnnotationKey]AnnotationValue `json:"annotations,omitempty"`

	// ParametersRef is a reference to a resource that contains the configuration
	// parameters corresponding to the Gateway. This is optional if the
	// controller does not require any additional configuration.
	//
	// This follows the same semantics as GatewayClass's `parametersRef`, but on a per-Gateway basis
	//
	// The Gateway's GatewayClass may provide its own `parametersRef`. When both are specified,
	// the merging behavior is implementation specific.
	// It is generally recommended that GatewayClass provides defaults that can be overridden by a Gateway.
	//
	// If the referent cannot be found, refers to an unsupported kind, or when
	// the data within that resource is malformed, the Gateway SHOULD be
	// rejected with the "Accepted" status condition set to "False" and an
	// "InvalidParameters" reason.
	//
	// Support: Implementation-specific
	//
	// +optional
	ParametersRef *LocalParametersReference `json:"parametersRef,omitempty"`
}

// LocalParametersReference identifies an API object containing controller-specific
// configuration resource within the namespace.
type LocalParametersReference struct {
	// Group is the group of the referent.
	// +required
	Group Group `json:"group"`

	// Kind is kind of the referent.
	// +required
	Kind Kind `json:"kind"`

	// Name is the name of the referent.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +required
	Name string `json:"name"`
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
	// * "NoResources"
	// * "AddressNotAssigned"
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

	// This reason is used with the "Programmed" and "Accepted" conditions when
	// the Gateway is syntactically or semantically invalid. For example, this
	// could include unspecified TLS configuration, or some unrecognized or
	// invalid values in the TLS configuration.
	GatewayReasonInvalid GatewayConditionReason = "Invalid"

	// This reason is used with the "Programmed" condition when the
	// Gateway is not scheduled because insufficient infrastructure
	// resources are available.
	GatewayReasonNoResources GatewayConditionReason = "NoResources"

	// This reason is used with the "Programmed" condition when the underlying
	// implementation and network have yet to dynamically assign addresses for a
	// Gateway.
	//
	// Some example situations where this reason can be used:
	//
	//   * IPAM address exhaustion
	//   * Address not yet allocated
	//
	// When this reason is used the implementation SHOULD provide a clear
	// message explaining the underlying problem, ideally with some hints as to
	// what actions can be taken that might resolve the problem.
	GatewayReasonAddressNotAssigned GatewayConditionReason = "AddressNotAssigned"

	// This reason is used with the "Programmed" condition when the underlying
	// implementation (and possibly, network) are unable to use an address that
	// was provided in the Gateway specification.
	//
	// Some example situations where this reason can be used:
	//
	//   * a named address not being found
	//   * a provided static address can't be used
	//   * the address is already in use
	//
	// When this reason is used the implementation SHOULD provide prescriptive
	// information on which address is causing the problem and how to resolve it
	// in the condition message.
	GatewayReasonAddressNotUsable GatewayConditionReason = "AddressNotUsable"
	// This condition indicates `FrontendValidationModeType` changed from
	// `AllowValidOnly` to `AllowInsecureFallback`.
	GatewayConditionInsecureFrontendValidationMode GatewayConditionReason = "InsecureFrontendValidationMode"
	// This reason MUST be set for GatewayConditionInsecureFrontendValidationMode
	// when client change FrontendValidationModeType for a Gateway or per port override
	// to `AllowInsecureFallback`.
	GatewayReasonConfigurationChanged GatewayConditionReason = "ConfigurationChanged"
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
	// * "ListenersNotValid"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "Invalid"
	// * "InvalidParameters"
	// * "NotReconciled"
	// * "UnsupportedAddress"
	// * "ListenersNotValid"
	//
	// Possible reasons for this condition to be Unknown are:
	//
	// * "Pending"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	GatewayConditionAccepted GatewayConditionType = "Accepted"

	// This reason is used with the "Accepted" condition when the condition is
	// True.
	GatewayReasonAccepted GatewayConditionReason = "Accepted"

	// This reason is used with the "Accepted" condition when one or
	// more Listeners have an invalid or unsupported configuration
	// and cannot be configured on the Gateway.
	// This can be the reason when "Accepted" is "True" or "False", depending on whether
	// the listener being invalid causes the entire Gateway to not be accepted.
	GatewayReasonListenersNotValid GatewayConditionReason = "ListenersNotValid"

	// This reason is used with the "Accepted" and "Programmed"
	// conditions when the status is "Unknown" and no controller has reconciled
	// the Gateway.
	GatewayReasonPending GatewayConditionReason = "Pending"

	// This reason is used with the "Accepted" condition to indicate that the
	// Gateway could not be accepted because an address that was provided is a
	// type which is not supported by the implementation.
	GatewayReasonUnsupportedAddress GatewayConditionReason = "UnsupportedAddress"

	// This reason is used with the "Accepted" condition when the
	// Gateway was not accepted because the parametersRef field
	// was invalid, with more detail in the message.
	GatewayReasonInvalidParameters GatewayConditionReason = "InvalidParameters"
)

const (
	// Deprecated: use "Accepted" instead.
	GatewayConditionScheduled GatewayConditionType = "Scheduled"

	// This reason is used with the "Scheduled" condition when the condition is
	// True.
	//
	// Deprecated: use the "Accepted" condition with reason "Accepted" instead.
	GatewayReasonScheduled GatewayConditionReason = "Scheduled"

	// Deprecated: Use "Pending" instead.
	GatewayReasonNotReconciled GatewayConditionReason = "NotReconciled"
)

const (
	// "Ready" is a condition type reserved for future use. It should not be used by implementations.
	//
	// If used in the future, "Ready" will represent the final state where all configuration is confirmed good
	// _and has completely propagated to the data plane_. That is, it is a _guarantee_ that, as soon as something
	// sees the Condition as `true`, then connections will be correctly routed _immediately_.
	//
	// This is a very strong guarantee, and to date no implementation has satisfied it enough to implement it.
	// This reservation can be discussed in the future if necessary.
	//
	// Note: This condition is not really "deprecated", but rather "reserved"; however, deprecated triggers Go linters
	// to alert about usage.
	// Deprecated: Ready is reserved for future use
	GatewayConditionReady GatewayConditionType = "Ready"

	// Deprecated: Ready is reserved for future use
	GatewayReasonReady GatewayConditionReason = "Ready"

	// Deprecated: Ready is reserved for future use
	GatewayReasonListenersNotReady GatewayConditionReason = "ListenersNotReady"
)

const (
	// AttachedListenerSets is a condition that is true when the Gateway has
	// at least one ListenerSet attached to it.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "ListenerSetsAttached"
	//
	// Possible reasons for this condition to be False are:
	//
	// * "NoListenerSetsAttached"
	// * "ListenerSetsNotAllowed"
	//
	// Controllers may raise this condition with other reasons,
	// but should prefer to use the reasons listed above to improve
	// interoperability.
	GatewayConditionAttachedListenerSets GatewayConditionType = "AttachedListenerSets"

	// This reason is used with the "AttachedListenerSets" condition when the
	// Gateway has at least one ListenerSet attached to it.
	GatewayReasonListenerSetsAttached GatewayConditionReason = "ListenerSetsAttached"

	// This reason is used with the "AttachedListenerSets" condition when the
	// Gateway has no ListenerSets attached to it.
	GatewayReasonNoListenerSetsAttached GatewayConditionReason = "NoListenerSetsAttached"

	// This reason is used with the "AttachedListenerSets" condition when the
	// Gateway has ListenerSets attached to it, but the ListenerSets are not allowed.
	GatewayReasonListenerSetsNotAllowed GatewayConditionReason = "ListenerSetsNotAllowed"
)

// ListenerStatus is the status associated with a Listener.
type ListenerStatus struct {
	// Name is the name of the Listener that this status corresponds to.
	// +required
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
	//
	// <gateway:util:excludeFromCRD>
	// Notes for implementors:
	//
	// Conditions are a listType `map`, which means that they function like a
	// map with a key of the `type` field _in the k8s apiserver_.
	//
	// This means that implementations must obey some rules when updating this
	// section.
	//
	// * Implementations MUST perform a read-modify-write cycle on this field
	//   before modifying it. That is, when modifying this field, implementations
	//   must be confident they have fetched the most recent version of this field,
	//   and ensure that changes they make are on that recent version.
	// * Implementations MUST NOT remove or reorder Conditions that they are not
	//   directly responsible for. For example, if an implementation sees a Condition
	//   with type `special.io/SomeField`, it MUST NOT remove, change or update that
	//   Condition.
	// * Implementations MUST always _merge_ changes into Conditions of the same Type,
	//   rather than creating more than one Condition of the same Type.
	// * Implementations MUST always update the `observedGeneration` field of the
	//   Condition to the `metadata.generation` of the Gateway at the time of update creation.
	// * If the `observedGeneration` of a Condition is _greater than_ the value the
	//   implementation knows about, then it MUST NOT perform the update on that Condition,
	//   but must wait for a future reconciliation and status update. (The assumption is that
	//   the implementation's copy of the object is stale and an update will be re-triggered
	//   if relevant.)
	//
	// </gateway:util:excludeFromCRD>
	//
	// +listType=map
	// +listMapKey=type
	// +kubebuilder:validation:MaxItems=8
	// +required
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

	// This reason is used with the "Ready" and "Programmed" conditions when the
	// Listener is syntactically or semantically invalid.
	ListenerReasonInvalid ListenerConditionReason = "Invalid"

	// This reason is used with the "Accepted", "Ready" and "Programmed"
	// conditions when the Listener is either not yet reconciled or not yet not
	// online and ready to accept client traffic.
	ListenerReasonPending ListenerConditionReason = "Pending"
)

const (
	// This condition indicates that TLS configuration within this Listener
	// conflicts with TLS configuration in another Listener on the same port.
	// This could happen for two reasons:
	//
	// 1) Overlapping Hostnames: Listener A matches *.example.com while Listener
	//    B matches foo.example.com.
	// B) Overlapping Certificates: Listener A contains a certificate with a
	//    SAN for *.example.com, while Listener B contains a certificate with a
	//    SAN for foo.example.com.
	//
	// This overlapping TLS configuration can be particularly problematic when
	// combined with HTTP connection coalescing. When clients reuse connections
	// using this technique, it can have confusing interactions with Gateway
	// API, such as TLS configuration for one Listener getting used for a
	// request reusing an existing connection that would not be used if the same
	// request was initiating a new connection.
	//
	// Controllers MUST detect the presence of overlapping hostnames and MAY
	// detect the presence of overlapping certificates.
	//
	// This condition MUST be set on all Listeners with overlapping TLS config.
	// For example, consider the following listener - hostname mapping:
	//
	// A: foo.example.com
	// B: foo.example.org
	// C: *.example.com
	//
	// In the above example, Listeners A and C would have overlapping hostnames
	// and therefore this condition should be set for Listeners A and C, but not
	// B.
	//
	// Possible reasons for this condition to be True are:
	//
	// * "OverlappingHostnames"
	// * "OverlappingCertificates"
	//
	// If a controller supports checking for both possible reasons and finds
	// that both are true, it SHOULD set the "OverlappingCertificates" Reason.
	//
	// This is a negative polarity condition and MUST NOT be set when it is
	// False.
	//
	// Controllers may raise this condition with other reasons, but should
	// prefer to use the reasons listed above to improve interoperability.
	ListenerConditionOverlappingTLSConfig ListenerConditionType = "OverlappingTLSConfig"

	// This reason is used with the "OverlappingTLSConfig" condition when the
	// condition is true.
	ListenerReasonOverlappingHostnames ListenerConditionReason = "OverlappingHostnames"

	// This reason is used with the "OverlappingTLSConfig" condition when the
	// condition is true.
	ListenerReasonOverlappingCertificates ListenerConditionReason = "OverlappingCertificates"
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
	ListenerConditionReady ListenerConditionType = "Ready"

	// Deprecated: Ready is reserved for future use
	ListenerReasonReady ListenerConditionReason = "Ready"
)
