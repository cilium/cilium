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

	v1 "sigs.k8s.io/gateway-api/apis/v1"
)

// +genclient
// +kubebuilder:object:root=true
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Hostnames",type=string,JSONPath=`.spec.hostnames`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HTTPRoute provides a way to route HTTP requests. This includes the capability
// to match requests by hostname, path, header, or query param. Filters can be
// used to specify additional processing steps. Backends specify where matching
// requests should be routed.
type HTTPRoute v1.HTTPRoute

// +kubebuilder:object:root=true

// HTTPRouteList contains a list of HTTPRoute.
type HTTPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRoute `json:"items"`
}

// HTTPRouteSpec defines the desired state of HTTPRoute
// +k8s:deepcopy-gen=false
type HTTPRouteSpec = v1.HTTPRouteSpec

// HTTPRouteRule defines semantics for matching an HTTP request based on
// conditions (matches), processing it (filters), and forwarding the request to
// an API object (backendRefs).
// +k8s:deepcopy-gen=false
type HTTPRouteRule = v1.HTTPRouteRule

// PathMatchType specifies the semantics of how HTTP paths should be compared.
// Valid PathMatchType values, along with their conformance level, are:
//
// * "Exact" - Core
// * "PathPrefix" - Core
// * "RegularExpression" - Implementation Specific
//
// PathPrefix and Exact paths must be syntactically valid:
//
// - Must begin with the `/` character
// - Must not contain consecutive `/` characters (e.g. `/foo///`, `//`).
//
// Note that values may be added to this enum, implementations
// must ensure that unknown values will not cause a crash.
//
// Unknown values here must result in the implementation setting the
// Accepted Condition for the Route to `status: False`, with a
// Reason of `UnsupportedValue`.
//
// +kubebuilder:validation:Enum=Exact;PathPrefix;RegularExpression
// +k8s:deepcopy-gen=false
type PathMatchType = v1.PathMatchType

// HTTPPathMatch describes how to select a HTTP route by matching the HTTP request path.
// +k8s:deepcopy-gen=false
type HTTPPathMatch = v1.HTTPPathMatch

// HeaderMatchType specifies the semantics of how HTTP header values should be
// compared. Valid HeaderMatchType values, along with their conformance levels, are:
//
// * "Exact" - Core
// * "RegularExpression" - Implementation Specific
//
// Note that values may be added to this enum, implementations
// must ensure that unknown values will not cause a crash.
//
// Unknown values here must result in the implementation setting the
// Accepted Condition for the Route to `status: False`, with a
// Reason of `UnsupportedValue`.
//
// +kubebuilder:validation:Enum=Exact;RegularExpression
// +k8s:deepcopy-gen=false
type HeaderMatchType = v1.HeaderMatchType

// HTTPHeaderName is the name of an HTTP header.
//
// Valid values include:
// * "Authorization"
// * "Set-Cookie"
//
// Invalid values include:
//
//   - ":method" - ":" is an invalid character. This means that HTTP/2 pseudo
//     headers are not currently supported by this type.
//
// * "/invalid" - "/" is an invalid character
// +k8s:deepcopy-gen=false
type HTTPHeaderName = v1.HeaderName

// HTTPHeaderMatch describes how to select a HTTP route by matching HTTP request
// headers.
// +k8s:deepcopy-gen=false
type HTTPHeaderMatch = v1.HTTPHeaderMatch

// QueryParamMatchType specifies the semantics of how HTTP query parameter
// values should be compared. Valid QueryParamMatchType values, along with their
// conformance levels, are:
//
// * "Exact" - Core
// * "RegularExpression" - Implementation Specific
//
// Note that values may be added to this enum, implementations
// must ensure that unknown values will not cause a crash.
//
// Unknown values here must result in the implementation setting the
// Accepted Condition for the Route to `status: False`, with a
// Reason of `UnsupportedValue`.
//
// +kubebuilder:validation:Enum=Exact;RegularExpression
// +k8s:deepcopy-gen=false
type QueryParamMatchType = v1.QueryParamMatchType

// HTTPQueryParamMatch describes how to select a HTTP route by matching HTTP
// query parameters.
// +k8s:deepcopy-gen=false
type HTTPQueryParamMatch = v1.HTTPQueryParamMatch

// HTTPMethod describes how to select a HTTP route by matching the HTTP
// method as defined by
// [RFC 7231](https://datatracker.ietf.org/doc/html/rfc7231#section-4) and
// [RFC 5789](https://datatracker.ietf.org/doc/html/rfc5789#section-2).
// The value is expected in upper case.
//
// Note that values may be added to this enum, implementations
// must ensure that unknown values will not cause a crash.
//
// Unknown values here must result in the implementation setting the
// Accepted Condition for the Route to `status: False`, with a
// Reason of `UnsupportedValue`.
//
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH
// +k8s:deepcopy-gen=false
type HTTPMethod = v1.HTTPMethod

// HTTPRouteMatch defines the predicate used to match requests to a given
// action. Multiple match types are ANDed together, i.e. the match will
// evaluate to true only if all conditions are satisfied.
//
// For example, the match below will match a HTTP request only if its path
// starts with `/foo` AND it contains the `version: v1` header:
//
// ```
// match:
//
//	path:
//	  value: "/foo"
//	headers:
//	- name: "version"
//	  value "v1"
//
// ```
// +k8s:deepcopy-gen=false
type HTTPRouteMatch = v1.HTTPRouteMatch

// HTTPRouteFilter defines processing steps that must be completed during the
// request or response lifecycle. HTTPRouteFilters are meant as an extension
// point to express processing that may be done in Gateway implementations. Some
// examples include request or response modification, implementing
// authentication strategies, rate-limiting, and traffic shaping. API
// guarantee/conformance is defined based on the type of the filter.
// +k8s:deepcopy-gen=false
type HTTPRouteFilter = v1.HTTPRouteFilter

// HTTPRouteFilterType identifies a type of HTTPRoute filter.
// +k8s:deepcopy-gen=false
type HTTPRouteFilterType = v1.HTTPRouteFilterType

// HTTPRouteTimeouts defines timeouts that can be configured for an HTTPRoute.
// +k8s:deepcopy-gen=false
type HTTPRouteTimeouts = v1.HTTPRouteTimeouts

// HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.
// +k8s:deepcopy-gen=false
type HTTPHeader = v1.HTTPHeader

// HTTPHeaderFilter defines a filter that modifies the headers of an HTTP request
// or response.
// +k8s:deepcopy-gen=false
type HTTPHeaderFilter = v1.HTTPHeaderFilter

// HTTPPathModifierType defines the type of path redirect or rewrite.
// +k8s:deepcopy-gen=false
type HTTPPathModifierType = v1.HTTPPathModifierType

// HTTPPathModifier defines configuration for path modifiers.
// <gateway:experimental>
// +k8s:deepcopy-gen=false
type HTTPPathModifier = v1.HTTPPathModifier

// HTTPRequestRedirect defines a filter that redirects a request. This filter
// MUST NOT be used on the same Route rule as a HTTPURLRewrite filter.
// +k8s:deepcopy-gen=false
type HTTPRequestRedirectFilter = v1.HTTPRequestRedirectFilter

// HTTPURLRewriteFilter defines a filter that modifies a request during
// forwarding. At most one of these filters may be used on a Route rule. This
// MUST NOT be used on the same Route rule as a HTTPRequestRedirect filter.
//
// Support: Extended
//
// <gateway:experimental>
// +k8s:deepcopy-gen=false
type HTTPURLRewriteFilter = v1.HTTPURLRewriteFilter

// HTTPRequestMirrorFilter defines configuration for the RequestMirror filter.
// +k8s:deepcopy-gen=false
type HTTPRequestMirrorFilter = v1.HTTPRequestMirrorFilter

// HTTPBackendRef defines how a HTTPRoute should forward an HTTP request.
// +k8s:deepcopy-gen=false
type HTTPBackendRef = v1.HTTPBackendRef

// HTTPRouteStatus defines the observed state of HTTPRoute.
// +k8s:deepcopy-gen=false
type HTTPRouteStatus = v1.HTTPRouteStatus
