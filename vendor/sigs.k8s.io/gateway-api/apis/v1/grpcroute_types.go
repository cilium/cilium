/*
Copyright 2022 The Kubernetes Authors.

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
// +kubebuilder:printcolumn:name="Hostnames",type=string,JSONPath=`.spec.hostnames`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// GRPCRoute provides a way to route gRPC requests. This includes the capability
// to match requests by hostname, gRPC service, gRPC method, or HTTP/2 header.
// Filters can be used to specify additional processing steps. Backends specify
// where matching requests will be routed.
//
// GRPCRoute falls under extended support within the Gateway API. Within the
// following specification, the word "MUST" indicates that an implementation
// supporting GRPCRoute must conform to the indicated requirement, but an
// implementation not supporting this route type need not follow the requirement
// unless explicitly indicated.
//
// Implementations supporting `GRPCRoute` with the `HTTPS` `ProtocolType` MUST
// accept HTTP/2 connections without an initial upgrade from HTTP/1.1, i.e. via
// ALPN. If the implementation does not support this, then it MUST set the
// "Accepted" condition to "False" for the affected listener with a reason of
// "UnsupportedProtocol".  Implementations MAY also accept HTTP/2 connections
// with an upgrade from HTTP/1.
//
// Implementations supporting `GRPCRoute` with the `HTTP` `ProtocolType` MUST
// support HTTP/2 over cleartext TCP (h2c,
// https://www.rfc-editor.org/rfc/rfc7540#section-3.1) without an initial
// upgrade from HTTP/1.1, i.e. with prior knowledge
// (https://www.rfc-editor.org/rfc/rfc7540#section-3.4). If the implementation
// does not support this, then it MUST set the "Accepted" condition to "False"
// for the affected listener with a reason of "UnsupportedProtocol".
// Implementations MAY also accept HTTP/2 connections with an upgrade from
// HTTP/1, i.e. without prior knowledge.
type GRPCRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of GRPCRoute.
	Spec GRPCRouteSpec `json:"spec,omitempty"`

	// Status defines the current state of GRPCRoute.
	Status GRPCRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// GRPCRouteList contains a list of GRPCRoute.
type GRPCRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []GRPCRoute `json:"items"`
}

// GRPCRouteStatus defines the observed state of GRPCRoute.
type GRPCRouteStatus struct {
	RouteStatus `json:",inline"`
}

// GRPCRouteSpec defines the desired state of GRPCRoute
type GRPCRouteSpec struct {
	CommonRouteSpec `json:",inline"`

	// Hostnames defines a set of hostnames to match against the GRPC
	// Host header to select a GRPCRoute to process the request. This matches
	// the RFC 1123 definition of a hostname with 2 notable exceptions:
	//
	// 1. IPs are not allowed.
	// 2. A hostname may be prefixed with a wildcard label (`*.`). The wildcard
	//    label MUST appear by itself as the first label.
	//
	// If a hostname is specified by both the Listener and GRPCRoute, there
	// MUST be at least one intersecting hostname for the GRPCRoute to be
	// attached to the Listener. For example:
	//
	// * A Listener with `test.example.com` as the hostname matches GRPCRoutes
	//   that have either not specified any hostnames, or have specified at
	//   least one of `test.example.com` or `*.example.com`.
	// * A Listener with `*.example.com` as the hostname matches GRPCRoutes
	//   that have either not specified any hostnames or have specified at least
	//   one hostname that matches the Listener hostname. For example,
	//   `test.example.com` and `*.example.com` would both match. On the other
	//   hand, `example.com` and `test.example.net` would not match.
	//
	// Hostnames that are prefixed with a wildcard label (`*.`) are interpreted
	// as a suffix match. That means that a match for `*.example.com` would match
	// both `test.example.com`, and `foo.test.example.com`, but not `example.com`.
	//
	// If both the Listener and GRPCRoute have specified hostnames, any
	// GRPCRoute hostnames that do not match the Listener hostname MUST be
	// ignored. For example, if a Listener specified `*.example.com`, and the
	// GRPCRoute specified `test.example.com` and `test.example.net`,
	// `test.example.net` MUST NOT be considered for a match.
	//
	// If both the Listener and GRPCRoute have specified hostnames, and none
	// match with the criteria above, then the GRPCRoute MUST NOT be accepted by
	// the implementation. The implementation MUST raise an 'Accepted' Condition
	// with a status of `False` in the corresponding RouteParentStatus.
	//
	// If a Route (A) of type HTTPRoute or GRPCRoute is attached to a
	// Listener and that listener already has another Route (B) of the other
	// type attached and the intersection of the hostnames of A and B is
	// non-empty, then the implementation MUST accept exactly one of these two
	// routes, determined by the following criteria, in order:
	//
	// * The oldest Route based on creation timestamp.
	// * The Route appearing first in alphabetical order by
	//   "{namespace}/{name}".
	//
	// The rejected Route MUST raise an 'Accepted' condition with a status of
	// 'False' in the corresponding RouteParentStatus.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of GRPC matchers, filters and actions.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="While 16 rules and 64 matches per rule are allowed, the total number of matches across all rules in a route must be less than 128",rule="(self.size() > 0 ? (has(self[0].matches) ? self[0].matches.size() : 0) : 0) + (self.size() > 1 ? (has(self[1].matches) ? self[1].matches.size() : 0) : 0) + (self.size() > 2 ? (has(self[2].matches) ? self[2].matches.size() : 0) : 0) + (self.size() > 3 ? (has(self[3].matches) ? self[3].matches.size() : 0) : 0) + (self.size() > 4 ? (has(self[4].matches) ? self[4].matches.size() : 0) : 0) + (self.size() > 5 ? (has(self[5].matches) ? self[5].matches.size() : 0) : 0) + (self.size() > 6 ? (has(self[6].matches) ? self[6].matches.size() : 0) : 0) + (self.size() > 7 ? (has(self[7].matches) ? self[7].matches.size() : 0) : 0) + (self.size() > 8 ? (has(self[8].matches) ? self[8].matches.size() : 0) : 0) + (self.size() > 9 ? (has(self[9].matches) ? self[9].matches.size() : 0) : 0) + (self.size() > 10 ? (has(self[10].matches) ? self[10].matches.size() : 0) : 0) + (self.size() > 11 ? (has(self[11].matches) ? self[11].matches.size() : 0) : 0) + (self.size() > 12 ? (has(self[12].matches) ? self[12].matches.size() : 0) : 0) + (self.size() > 13 ? (has(self[13].matches) ? self[13].matches.size() : 0) : 0) + (self.size() > 14 ? (has(self[14].matches) ? self[14].matches.size() : 0) : 0) + (self.size() > 15 ? (has(self[15].matches) ? self[15].matches.size() : 0) : 0) <= 128"
	// <gateway:experimental:validation:XValidation:message="Rule name must be unique within the route",rule="self.all(l1, !has(l1.name) || self.exists_one(l2, has(l2.name) && l1.name == l2.name))">
	Rules []GRPCRouteRule `json:"rules,omitempty"`
}

// GRPCRouteRule defines the semantics for matching a gRPC request based on
// conditions (matches), processing it (filters), and forwarding the request to
// an API object (backendRefs).
type GRPCRouteRule struct {
	// Name is the name of the route rule. This name MUST be unique within a Route if it is set.
	//
	// Support: Extended
	// +optional
	// <gateway:experimental>
	Name *SectionName `json:"name,omitempty"`

	// Matches define conditions used for matching the rule against incoming
	// gRPC requests. Each match is independent, i.e. this rule will be matched
	// if **any** one of the matches is satisfied.
	//
	// For example, take the following matches configuration:
	//
	// ```
	// matches:
	// - method:
	//     service: foo.bar
	//   headers:
	//     values:
	//       version: 2
	// - method:
	//     service: foo.bar.v2
	// ```
	//
	// For a request to match against this rule, it MUST satisfy
	// EITHER of the two conditions:
	//
	// - service of foo.bar AND contains the header `version: 2`
	// - service of foo.bar.v2
	//
	// See the documentation for GRPCRouteMatch on how to specify multiple
	// match conditions to be ANDed together.
	//
	// If no matches are specified, the implementation MUST match every gRPC request.
	//
	// Proxy or Load Balancer routing configuration generated from GRPCRoutes
	// MUST prioritize rules based on the following criteria, continuing on
	// ties. Merging MUST not be done between GRPCRoutes and HTTPRoutes.
	// Precedence MUST be given to the rule with the largest number of:
	//
	// * Characters in a matching non-wildcard hostname.
	// * Characters in a matching hostname.
	// * Characters in a matching service.
	// * Characters in a matching method.
	// * Header matches.
	//
	// If ties still exist across multiple Routes, matching precedence MUST be
	// determined in order of the following criteria, continuing on ties:
	//
	// * The oldest Route based on creation timestamp.
	// * The Route appearing first in alphabetical order by
	//   "{namespace}/{name}".
	//
	// If ties still exist within the Route that has been given precedence,
	// matching precedence MUST be granted to the first matching rule meeting
	// the above criteria.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=8
	Matches []GRPCRouteMatch `json:"matches,omitempty"`

	// Filters define the filters that are applied to requests that match
	// this rule.
	//
	// The effects of ordering of multiple behaviors are currently unspecified.
	// This can change in the future based on feedback during the alpha stage.
	//
	// Conformance-levels at this level are defined based on the type of filter:
	//
	// - ALL core filters MUST be supported by all implementations that support
	//   GRPCRoute.
	// - Implementers are encouraged to support extended filters.
	// - Implementation-specific custom filters have no API guarantees across
	//   implementations.
	//
	// Specifying the same filter multiple times is not supported unless explicitly
	// indicated in the filter.
	//
	// If an implementation can not support a combination of filters, it must clearly
	// document that limitation. In cases where incompatible or unsupported
	// filters are specified and cause the `Accepted` condition to be set to status
	// `False`, implementations may use the `IncompatibleFilters` reason to specify
	// this configuration error.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="RequestHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
	// +kubebuilder:validation:XValidation:message="ResponseHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
	Filters []GRPCRouteFilter `json:"filters,omitempty"`

	// BackendRefs defines the backend(s) where matching requests should be
	// sent.
	//
	// Failure behavior here depends on how many BackendRefs are specified and
	// how many are invalid.
	//
	// If *all* entries in BackendRefs are invalid, and there are also no filters
	// specified in this route rule, *all* traffic which matches this rule MUST
	// receive an `UNAVAILABLE` status.
	//
	// See the GRPCBackendRef definition for the rules about what makes a single
	// GRPCBackendRef invalid.
	//
	// When a GRPCBackendRef is invalid, `UNAVAILABLE` statuses MUST be returned for
	// requests that would have otherwise been routed to an invalid backend. If
	// multiple backends are specified, and some are invalid, the proportion of
	// requests that would otherwise have been routed to an invalid backend
	// MUST receive an `UNAVAILABLE` status.
	//
	// For example, if two backends are specified with equal weights, and one is
	// invalid, 50 percent of traffic MUST receive an `UNAVAILABLE` status.
	// Implementations may choose how that 50 percent is determined.
	//
	// Support: Core for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	//
	// Support for weight: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	BackendRefs []GRPCBackendRef `json:"backendRefs,omitempty"`

	// SessionPersistence defines and configures session persistence
	// for the route rule.
	//
	// Support: Extended
	//
	// +optional
	// <gateway:experimental>
	SessionPersistence *SessionPersistence `json:"sessionPersistence,omitempty"`
}

// GRPCRouteMatch defines the predicate used to match requests to a given
// action. Multiple match types are ANDed together, i.e. the match will
// evaluate to true only if all conditions are satisfied.
//
// For example, the match below will match a gRPC request only if its service
// is `foo` AND it contains the `version: v1` header:
//
// ```
// matches:
//   - method:
//     type: Exact
//     service: "foo"
//     headers:
//   - name: "version"
//     value "v1"
//
// ```
type GRPCRouteMatch struct {
	// Method specifies a gRPC request service/method matcher. If this field is
	// not specified, all services and methods will match.
	//
	// +optional
	Method *GRPCMethodMatch `json:"method,omitempty"`

	// Headers specifies gRPC request header matchers. Multiple match values are
	// ANDed together, meaning, a request MUST match all the specified headers
	// to select the route.
	//
	// +listType=map
	// +listMapKey=name
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Headers []GRPCHeaderMatch `json:"headers,omitempty"`
}

// GRPCMethodMatch describes how to select a gRPC route by matching the gRPC
// request service and/or method.
//
// At least one of Service and Method MUST be a non-empty string.
//
// +kubebuilder:validation:XValidation:message="One or both of 'service' or 'method' must be specified",rule="has(self.type) ? has(self.service) || has(self.method) : true"
// +kubebuilder:validation:XValidation:message="service must only contain valid characters (matching ^(?i)\\.?[a-z_][a-z_0-9]*(\\.[a-z_][a-z_0-9]*)*$)",rule="(!has(self.type) || self.type == 'Exact') && has(self.service) ? self.service.matches(r\"\"\"^(?i)\\.?[a-z_][a-z_0-9]*(\\.[a-z_][a-z_0-9]*)*$\"\"\"): true"
// +kubebuilder:validation:XValidation:message="method must only contain valid characters (matching ^[A-Za-z_][A-Za-z_0-9]*$)",rule="(!has(self.type) || self.type == 'Exact') && has(self.method) ? self.method.matches(r\"\"\"^[A-Za-z_][A-Za-z_0-9]*$\"\"\"): true"
type GRPCMethodMatch struct {
	// Type specifies how to match against the service and/or method.
	// Support: Core (Exact with service and method specified)
	//
	// Support: Implementation-specific (Exact with method specified but no service specified)
	//
	// Support: Implementation-specific (RegularExpression)
	//
	// +optional
	// +kubebuilder:default=Exact
	Type *GRPCMethodMatchType `json:"type,omitempty"`

	// Value of the service to match against. If left empty or omitted, will
	// match any service.
	//
	// At least one of Service and Method MUST be a non-empty string.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Service *string `json:"service,omitempty"`

	// Value of the method to match against. If left empty or omitted, will
	// match all services.
	//
	// At least one of Service and Method MUST be a non-empty string.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Method *string `json:"method,omitempty"`
}

// MethodMatchType specifies the semantics of how gRPC methods and services are compared.
// Valid MethodMatchType values, along with their conformance levels, are:
//
// * "Exact" - Core
// * "RegularExpression" - Implementation Specific
//
// Exact methods MUST be syntactically valid:
//
// - Must not contain `/` character
//
// +kubebuilder:validation:Enum=Exact;RegularExpression
type GRPCMethodMatchType string

const (
	// Matches the method or service exactly and with case sensitivity.
	GRPCMethodMatchExact GRPCMethodMatchType = "Exact"

	// Matches if the method or service matches the given regular expression with
	// case sensitivity.
	//
	// Since `"RegularExpression"` has implementation-specific conformance,
	// implementations can support POSIX, PCRE, RE2 or any other regular expression
	// dialect.
	// Please read the implementation's documentation to determine the supported
	// dialect.
	GRPCMethodMatchRegularExpression GRPCMethodMatchType = "RegularExpression"
)

// GRPCHeaderMatch describes how to select a gRPC route by matching gRPC request
// headers.
type GRPCHeaderMatch struct {
	// Type specifies how to match against the value of the header.
	//
	// +optional
	// +kubebuilder:default=Exact
	Type *GRPCHeaderMatchType `json:"type,omitempty"`

	// Name is the name of the gRPC Header to be matched.
	//
	// If multiple entries specify equivalent header names, only the first
	// entry with an equivalent name MUST be considered for a match. Subsequent
	// entries with an equivalent header name MUST be ignored. Due to the
	// case-insensitivity of header names, "foo" and "Foo" are considered
	// equivalent.
	Name GRPCHeaderName `json:"name"`

	// Value is the value of the gRPC Header to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

// GRPCHeaderMatchType specifies the semantics of how GRPC header values should
// be compared. Valid GRPCHeaderMatchType values, along with their conformance
// levels, are:
//
// * "Exact" - Core
// * "RegularExpression" - Implementation Specific
//
// Note that new values may be added to this enum in future releases of the API,
// implementations MUST ensure that unknown values will not cause a crash.
//
// Unknown values here MUST result in the implementation setting the Accepted
// Condition for the Route to `status: False`, with a Reason of
// `UnsupportedValue`.
//
// +kubebuilder:validation:Enum=Exact;RegularExpression
type GRPCHeaderMatchType string

// GRPCHeaderMatchType constants.
const (
	GRPCHeaderMatchExact             GRPCHeaderMatchType = "Exact"
	GRPCHeaderMatchRegularExpression GRPCHeaderMatchType = "RegularExpression"
)

type GRPCHeaderName HeaderName

// GRPCRouteFilterType identifies a type of GRPCRoute filter.
type GRPCRouteFilterType string

const (
	// GRPCRouteFilterRequestHeaderModifier can be used to add or remove a gRPC
	// header from a gRPC request before it is sent to the upstream target.
	//
	// Support in GRPCRouteRule: Core
	//
	// Support in GRPCBackendRef: Extended
	GRPCRouteFilterRequestHeaderModifier GRPCRouteFilterType = "RequestHeaderModifier"

	// GRPCRouteFilterRequestHeaderModifier can be used to add or remove a gRPC
	// header from a gRPC response before it is sent to the client.
	//
	// Support in GRPCRouteRule: Core
	//
	// Support in GRPCBackendRef: Extended
	GRPCRouteFilterResponseHeaderModifier GRPCRouteFilterType = "ResponseHeaderModifier"

	// GRPCRouteFilterRequestMirror can be used to mirror gRPC requests to a
	// different backend. The responses from this backend MUST be ignored by
	// the Gateway.
	//
	// Support in GRPCRouteRule: Extended
	//
	// Support in GRPCBackendRef: Extended
	GRPCRouteFilterRequestMirror GRPCRouteFilterType = "RequestMirror"

	// GRPCRouteFilterExtensionRef should be used for configuring custom
	// gRPC filters.
	//
	// Support in GRPCRouteRule: Implementation-specific
	//
	// Support in GRPCBackendRef: Implementation-specific
	GRPCRouteFilterExtensionRef GRPCRouteFilterType = "ExtensionRef"
)

// GRPCRouteFilter defines processing steps that must be completed during the
// request or response lifecycle. GRPCRouteFilters are meant as an extension
// point to express processing that may be done in Gateway implementations. Some
// examples include request or response modification, implementing
// authentication strategies, rate-limiting, and traffic shaping. API
// guarantee/conformance is defined based on the type of the filter.
//
// +kubebuilder:validation:XValidation:message="filter.requestHeaderModifier must be nil if the filter.type is not RequestHeaderModifier",rule="!(has(self.requestHeaderModifier) && self.type != 'RequestHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.requestHeaderModifier must be specified for RequestHeaderModifier filter.type",rule="!(!has(self.requestHeaderModifier) && self.type == 'RequestHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.responseHeaderModifier must be nil if the filter.type is not ResponseHeaderModifier",rule="!(has(self.responseHeaderModifier) && self.type != 'ResponseHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.responseHeaderModifier must be specified for ResponseHeaderModifier filter.type",rule="!(!has(self.responseHeaderModifier) && self.type == 'ResponseHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.requestMirror must be nil if the filter.type is not RequestMirror",rule="!(has(self.requestMirror) && self.type != 'RequestMirror')"
// +kubebuilder:validation:XValidation:message="filter.requestMirror must be specified for RequestMirror filter.type",rule="!(!has(self.requestMirror) && self.type == 'RequestMirror')"
// +kubebuilder:validation:XValidation:message="filter.extensionRef must be nil if the filter.type is not ExtensionRef",rule="!(has(self.extensionRef) && self.type != 'ExtensionRef')"
// +kubebuilder:validation:XValidation:message="filter.extensionRef must be specified for ExtensionRef filter.type",rule="!(!has(self.extensionRef) && self.type == 'ExtensionRef')"
type GRPCRouteFilter struct {
	// Type identifies the type of filter to apply. As with other API fields,
	// types are classified into three conformance levels:
	//
	// - Core: Filter types and their corresponding configuration defined by
	//   "Support: Core" in this package, e.g. "RequestHeaderModifier". All
	//   implementations supporting GRPCRoute MUST support core filters.
	//
	// - Extended: Filter types and their corresponding configuration defined by
	//   "Support: Extended" in this package, e.g. "RequestMirror". Implementers
	//   are encouraged to support extended filters.
	//
	// - Implementation-specific: Filters that are defined and supported by specific vendors.
	//   In the future, filters showing convergence in behavior across multiple
	//   implementations will be considered for inclusion in extended or core
	//   conformance levels. Filter-specific configuration for such filters
	//   is specified using the ExtensionRef field. `Type` MUST be set to
	//   "ExtensionRef" for custom filters.
	//
	// Implementers are encouraged to define custom implementation types to
	// extend the core API with implementation-specific behavior.
	//
	// If a reference to a custom filter type cannot be resolved, the filter
	// MUST NOT be skipped. Instead, requests that would have been processed by
	// that filter MUST receive a HTTP error response.
	//
	// +unionDiscriminator
	// +kubebuilder:validation:Enum=ResponseHeaderModifier;RequestHeaderModifier;RequestMirror;ExtensionRef
	// <gateway:experimental:validation:Enum=ResponseHeaderModifier;RequestHeaderModifier;RequestMirror;ExtensionRef>
	Type GRPCRouteFilterType `json:"type"`

	// RequestHeaderModifier defines a schema for a filter that modifies request
	// headers.
	//
	// Support: Core
	//
	// +optional
	RequestHeaderModifier *HTTPHeaderFilter `json:"requestHeaderModifier,omitempty"`

	// ResponseHeaderModifier defines a schema for a filter that modifies response
	// headers.
	//
	// Support: Extended
	//
	// +optional
	ResponseHeaderModifier *HTTPHeaderFilter `json:"responseHeaderModifier,omitempty"`

	// RequestMirror defines a schema for a filter that mirrors requests.
	// Requests are sent to the specified destination, but responses from
	// that destination are ignored.
	//
	// This filter can be used multiple times within the same rule. Note that
	// not all implementations will be able to support mirroring to multiple
	// backends.
	//
	// Support: Extended
	//
	// +optional
	//
	// <gateway:experimental:validation:XValidation:message="Only one of percent or fraction may be specified in HTTPRequestMirrorFilter",rule="!(has(self.percent) && has(self.fraction))">
	RequestMirror *HTTPRequestMirrorFilter `json:"requestMirror,omitempty"`

	// ExtensionRef is an optional, implementation-specific extension to the
	// "filter" behavior.  For example, resource "myroutefilter" in group
	// "networking.example.net"). ExtensionRef MUST NOT be used for core and
	// extended filters.
	//
	// Support: Implementation-specific
	//
	// This filter can be used multiple times within the same rule.
	// +optional
	ExtensionRef *LocalObjectReference `json:"extensionRef,omitempty"`
}

// GRPCBackendRef defines how a GRPCRoute forwards a gRPC request.
//
// Note that when a namespace different than the local namespace is specified, a
// ReferenceGrant object is required in the referent namespace to allow that
// namespace's owner to accept the reference. See the ReferenceGrant
// documentation for details.
//
// <gateway:experimental:description>
//
// When the BackendRef points to a Kubernetes Service, implementations SHOULD
// honor the appProtocol field if it is set for the target Service Port.
//
// Implementations supporting appProtocol SHOULD recognize the Kubernetes
// Standard Application Protocols defined in KEP-3726.
//
// If a Service appProtocol isn't specified, an implementation MAY infer the
// backend protocol through its own means. Implementations MAY infer the
// protocol from the Route type referring to the backend Service.
//
// If a Route is not able to send traffic to the backend using the specified
// protocol then the backend is considered invalid. Implementations MUST set the
// "ResolvedRefs" condition to "False" with the "UnsupportedProtocol" reason.
//
// </gateway:experimental:description>
type GRPCBackendRef struct {
	// BackendRef is a reference to a backend to forward matched requests to.
	//
	// A BackendRef can be invalid for the following reasons. In all cases, the
	// implementation MUST ensure the `ResolvedRefs` Condition on the Route
	// is set to `status: False`, with a Reason and Message that indicate
	// what is the cause of the error.
	//
	// A BackendRef is invalid if:
	//
	// * It refers to an unknown or unsupported kind of resource. In this
	//   case, the Reason MUST be set to `InvalidKind` and Message of the
	//   Condition MUST explain which kind of resource is unknown or unsupported.
	//
	// * It refers to a resource that does not exist. In this case, the Reason MUST
	//   be set to `BackendNotFound` and the Message of the Condition MUST explain
	//   which resource does not exist.
	//
	// * It refers a resource in another namespace when the reference has not been
	//   explicitly allowed by a ReferenceGrant (or equivalent concept). In this
	//   case, the Reason MUST be set to `RefNotPermitted` and the Message of the
	//   Condition MUST explain which cross-namespace reference is not allowed.
	//
	// Support: Core for Kubernetes Service
	//
	// Support: Extended for Kubernetes ServiceImport
	//
	// Support: Implementation-specific for any other resource
	//
	// Support for weight: Core
	//
	// +optional
	BackendRef `json:",inline"`

	// Filters defined at this level MUST be executed if and only if the
	// request is being forwarded to the backend defined here.
	//
	// Support: Implementation-specific (For broader support of filters, use the
	// Filters field in GRPCRouteRule.)
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="RequestHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
	// +kubebuilder:validation:XValidation:message="ResponseHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
	Filters []GRPCRouteFilter `json:"filters,omitempty"`
}
