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
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:storageversion
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Hostnames",type=string,JSONPath=`.spec.hostnames`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HTTPRoute provides a way to route HTTP requests. This includes the capability
// to match requests by hostname, path, header, or query param. Filters can be
// used to specify additional processing steps. Backends specify where matching
// requests should be routed.
type HTTPRoute struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of HTTPRoute.
	Spec HTTPRouteSpec `json:"spec"`

	// Status defines the current state of HTTPRoute.
	Status HTTPRouteStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// HTTPRouteList contains a list of HTTPRoute.
type HTTPRouteList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []HTTPRoute `json:"items"`
}

// HTTPRouteSpec defines the desired state of HTTPRoute
type HTTPRouteSpec struct {
	CommonRouteSpec `json:",inline"`

	// Hostnames defines a set of hostname that should match against the HTTP
	// Host header to select a HTTPRoute to process the request. This matches
	// the RFC 1123 definition of a hostname with 2 notable exceptions:
	//
	// 1. IPs are not allowed.
	// 2. A hostname may be prefixed with a wildcard label (`*.`). The wildcard
	//    label must appear by itself as the first label.
	//
	// If a hostname is specified by both the Listener and HTTPRoute, there
	// must be at least one intersecting hostname for the HTTPRoute to be
	// attached to the Listener. For example:
	//
	// * A Listener with `test.example.com` as the hostname matches HTTPRoutes
	//   that have either not specified any hostnames, or have specified at
	//   least one of `test.example.com` or `*.example.com`.
	// * A Listener with `*.example.com` as the hostname matches HTTPRoutes
	//   that have either not specified any hostnames or have specified at least
	//   one hostname that matches the Listener hostname. For example,
	//   `*.example.com`, `test.example.com`, and `foo.test.example.com` would
	//   all match. On the other hand, `example.com` and `test.example.net` would
	//   not match.
	//
	// Hostnames that are prefixed with a wildcard label (`*.`) are interpreted
	// as a suffix match. That means that a match for `*.example.com` would match
	// both `test.example.com`, and `foo.test.example.com`, but not `example.com`.
	//
	// If both the Listener and HTTPRoute have specified hostnames, any
	// HTTPRoute hostnames that do not match the Listener hostname MUST be
	// ignored. For example, if a Listener specified `*.example.com`, and the
	// HTTPRoute specified `test.example.com` and `test.example.net`,
	// `test.example.net` must not be considered for a match.
	//
	// If both the Listener and HTTPRoute have specified hostnames, and none
	// match with the criteria above, then the HTTPRoute is not accepted. The
	// implementation must raise an 'Accepted' Condition with a status of
	// `False` in the corresponding RouteParentStatus.
	//
	// In the event that multiple HTTPRoutes specify intersecting hostnames (e.g.
	// overlapping wildcard matching and exact matching hostnames), precedence must
	// be given to rules from the HTTPRoute with the largest number of:
	//
	// * Characters in a matching non-wildcard hostname.
	// * Characters in a matching hostname.
	//
	// If ties exist across multiple Routes, the matching precedence rules for
	// HTTPRouteMatches takes over.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of HTTP matchers, filters and actions.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:default={{matches: {{path: {type: "PathPrefix", value: "/"}}}}}
	Rules []HTTPRouteRule `json:"rules,omitempty"`
}

// HTTPRouteRule defines semantics for matching an HTTP request based on
// conditions (matches), processing it (filters), and forwarding the request to
// an API object (backendRefs).
type HTTPRouteRule struct {
	// Matches define conditions used for matching the rule against incoming
	// HTTP requests. Each match is independent, i.e. this rule will be matched
	// if **any** one of the matches is satisfied.
	//
	// For example, take the following matches configuration:
	//
	// ```
	// matches:
	// - path:
	//     value: "/foo"
	//   headers:
	//   - name: "version"
	//     value: "v2"
	// - path:
	//     value: "/v2/foo"
	// ```
	//
	// For a request to match against this rule, a request must satisfy
	// EITHER of the two conditions:
	//
	// - path prefixed with `/foo` AND contains the header `version: v2`
	// - path prefix of `/v2/foo`
	//
	// See the documentation for HTTPRouteMatch on how to specify multiple
	// match conditions that should be ANDed together.
	//
	// If no matches are specified, the default is a prefix
	// path match on "/", which has the effect of matching every
	// HTTP request.
	//
	// Proxy or Load Balancer routing configuration generated from HTTPRoutes
	// MUST prioritize matches based on the following criteria, continuing on
	// ties. Across all rules specified on applicable Routes, precedence must be
	// given to the match with the largest number of:
	//
	// * Characters in a matching path.
	// * Header matches.
	// * Query param matches.
	//
	// If ties still exist across multiple Routes, matching precedence MUST be
	// determined in order of the following criteria, continuing on ties:
	//
	// * The oldest Route based on creation timestamp.
	// * The Route appearing first in alphabetical order by
	//   "{namespace}/{name}".
	//
	// If ties still exist within an HTTPRoute, matching precedence MUST be granted
	// to the FIRST matching rule (in list order) with a match meeting the above
	// criteria.
	//
	// When no rules matching a request have been successfully attached to the
	// parent a request is coming from, a HTTP 404 status code MUST be returned.
	//
	// +optional
	// +kubebuilder:validation:MaxItems=8
	// +kubebuilder:default={{path:{ type: "PathPrefix", value: "/"}}}
	Matches []HTTPRouteMatch `json:"matches,omitempty"`

	// Filters define the filters that are applied to requests that match
	// this rule.
	//
	// The effects of ordering of multiple behaviors are currently unspecified.
	// This can change in the future based on feedback during the alpha stage.
	//
	// Conformance-levels at this level are defined based on the type of filter:
	//
	// - ALL core filters MUST be supported by all implementations.
	// - Implementers are encouraged to support extended filters.
	// - Implementation-specific custom filters have no API guarantees across
	//   implementations.
	//
	// Specifying a core filter multiple times has unspecified or
	// implementation-specific conformance.
	//
	// All filters are expected to be compatible with each other except for the
	// URLRewrite and RequestRedirect filters, which may not be combined. If an
	// implementation can not support other combinations of filters, they must clearly
	// document that limitation. In all cases where incompatible or unsupported
	// filters are specified, implementations MUST add a warning condition to status.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Filters []HTTPRouteFilter `json:"filters,omitempty"`

	// BackendRefs defines the backend(s) where matching requests should be
	// sent.
	//
	// Failure behavior here depends on how many BackendRefs are specified and
	// how many are invalid.
	//
	// If *all* entries in BackendRefs are invalid, and there are also no filters
	// specified in this route rule, *all* traffic which matches this rule MUST
	// receive a 500 status code.
	//
	// See the HTTPBackendRef definition for the rules about what makes a single
	// HTTPBackendRef invalid.
	//
	// When a HTTPBackendRef is invalid, 500 status codes MUST be returned for
	// requests that would have otherwise been routed to an invalid backend. If
	// multiple backends are specified, and some are invalid, the proportion of
	// requests that would otherwise have been routed to an invalid backend
	// MUST receive a 500 status code.
	//
	// For example, if two backends are specified with equal weights, and one is
	// invalid, 50 percent of traffic must receive a 500. Implementations may
	// choose how that 50 percent is determined.
	//
	// Support: Core for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	//
	// Support for weight: Core
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	BackendRefs []HTTPBackendRef `json:"backendRefs,omitempty"`
}

// PathMatchType specifies the semantics of how HTTP paths should be compared.
// Valid PathMatchType values, along with their support levels, are:
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
type PathMatchType string

const (
	// Matches the URL path exactly and with case sensitivity.
	PathMatchExact PathMatchType = "Exact"

	// Matches based on a URL path prefix split by `/`. Matching is
	// case sensitive and done on a path element by element basis. A
	// path element refers to the list of labels in the path split by
	// the `/` separator. When specified, a trailing `/` is ignored.
	//
	// For example, the paths `/abc`, `/abc/`, and `/abc/def` would all match
	// the prefix `/abc`, but the path `/abcd` would not.
	//
	// "PathPrefix" is semantically equivalent to the "Prefix" path type in the
	// Kubernetes Ingress API.
	PathMatchPathPrefix PathMatchType = "PathPrefix"

	// Matches if the URL path matches the given regular expression with
	// case sensitivity.
	//
	// Since `"RegularExpression"` has implementation-specific conformance,
	// implementations can support POSIX, PCRE, RE2 or any other regular expression
	// dialect.
	// Please read the implementation's documentation to determine the supported
	// dialect.
	PathMatchRegularExpression PathMatchType = "RegularExpression"
)

// HTTPPathMatch describes how to select a HTTP route by matching the HTTP request path.
type HTTPPathMatch struct {
	// Type specifies how to match against the path Value.
	//
	// Support: Core (Exact, PathPrefix)
	//
	// Support: Implementation-specific (RegularExpression)
	//
	// +optional
	// +kubebuilder:default=PathPrefix
	Type *PathMatchType `json:"type,omitempty"`

	// Value of the HTTP path to match against.
	//
	// +optional
	// +kubebuilder:default="/"
	// +kubebuilder:validation:MaxLength=1024
	Value *string `json:"value,omitempty"`
}

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
type HeaderMatchType string

// HeaderMatchType constants.
const (
	HeaderMatchExact             HeaderMatchType = "Exact"
	HeaderMatchRegularExpression HeaderMatchType = "RegularExpression"
)

// HTTPHeaderName is the name of an HTTP header.
//
// Valid values include:
//
// * "Authorization"
// * "Set-Cookie"
//
// Invalid values include:
//
//   - ":method" - ":" is an invalid character. This means that HTTP/2 pseudo
//     headers are not currently supported by this type.
//   - "/invalid" - "/" is an invalid character
//
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=256
// +kubebuilder:validation:Pattern=`^[A-Za-z0-9!#$%&'*+\-.^_\x60|~]+$`
type HTTPHeaderName string

// HTTPHeaderMatch describes how to select a HTTP route by matching HTTP request
// headers.
type HTTPHeaderMatch struct {
	// Type specifies how to match against the value of the header.
	//
	// Support: Core (Exact)
	//
	// Support: Implementation-specific (RegularExpression)
	//
	// Since RegularExpression HeaderMatchType has implementation-specific
	// conformance, implementations can support POSIX, PCRE or any other dialects
	// of regular expressions. Please read the implementation's documentation to
	// determine the supported dialect.
	//
	// +optional
	// +kubebuilder:default=Exact
	Type *HeaderMatchType `json:"type,omitempty"`

	// Name is the name of the HTTP Header to be matched. Name matching MUST be
	// case insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).
	//
	// If multiple entries specify equivalent header names, only the first
	// entry with an equivalent name MUST be considered for a match. Subsequent
	// entries with an equivalent header name MUST be ignored. Due to the
	// case-insensitivity of header names, "foo" and "Foo" are considered
	// equivalent.
	//
	// When a header is repeated in an HTTP request, it is
	// implementation-specific behavior as to how this is represented.
	// Generally, proxies should follow the guidance from the RFC:
	// https://www.rfc-editor.org/rfc/rfc7230.html#section-3.2.2 regarding
	// processing a repeated header, with special handling for "Set-Cookie".
	Name HTTPHeaderName `json:"name"`

	// Value is the value of HTTP Header to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

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
type QueryParamMatchType string

// QueryParamMatchType constants.
const (
	QueryParamMatchExact             QueryParamMatchType = "Exact"
	QueryParamMatchRegularExpression QueryParamMatchType = "RegularExpression"
)

// HTTPQueryParamMatch describes how to select a HTTP route by matching HTTP
// query parameters.
type HTTPQueryParamMatch struct {
	// Type specifies how to match against the value of the query parameter.
	//
	// Support: Extended (Exact)
	//
	// Support: Implementation-specific (RegularExpression)
	//
	// Since RegularExpression QueryParamMatchType has Implementation-specific
	// conformance, implementations can support POSIX, PCRE or any other
	// dialects of regular expressions. Please read the implementation's
	// documentation to determine the supported dialect.
	//
	// +optional
	// +kubebuilder:default=Exact
	Type *QueryParamMatchType `json:"type,omitempty"`

	// Name is the name of the HTTP query param to be matched. This must be an
	// exact string match. (See
	// https://tools.ietf.org/html/rfc7230#section-2.7.3).
	//
	// If multiple entries specify equivalent query param names, only the first
	// entry with an equivalent name MUST be considered for a match. Subsequent
	// entries with an equivalent query param name MUST be ignored.
	//
	// If a query param is repeated in an HTTP request, the behavior is
	// purposely left undefined, since different data planes have different
	// capabilities. However, it is *recommended* that implementations should
	// match against the first value of the param if the data plane supports it,
	// as this behavior is expected in other load balancing contexts outside of
	// the Gateway API.
	//
	// Users SHOULD NOT route traffic based on repeated query params to guard
	// themselves against potential differences in the implementations.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Name string `json:"name"`

	// Value is the value of HTTP query param to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	Value string `json:"value"`
}

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
type HTTPMethod string

const (
	HTTPMethodGet     HTTPMethod = "GET"
	HTTPMethodHead    HTTPMethod = "HEAD"
	HTTPMethodPost    HTTPMethod = "POST"
	HTTPMethodPut     HTTPMethod = "PUT"
	HTTPMethodDelete  HTTPMethod = "DELETE"
	HTTPMethodConnect HTTPMethod = "CONNECT"
	HTTPMethodOptions HTTPMethod = "OPTIONS"
	HTTPMethodTrace   HTTPMethod = "TRACE"
	HTTPMethodPatch   HTTPMethod = "PATCH"
)

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
type HTTPRouteMatch struct {
	// Path specifies a HTTP request path matcher. If this field is not
	// specified, a default prefix match on the "/" path is provided.
	//
	// +optional
	// +kubebuilder:default={type: "PathPrefix", value: "/"}
	Path *HTTPPathMatch `json:"path,omitempty"`

	// Headers specifies HTTP request header matchers. Multiple match values are
	// ANDed together, meaning, a request must match all the specified headers
	// to select the route.
	//
	// +listType=map
	// +listMapKey=name
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Headers []HTTPHeaderMatch `json:"headers,omitempty"`

	// QueryParams specifies HTTP query parameter matchers. Multiple match
	// values are ANDed together, meaning, a request must match all the
	// specified query parameters to select the route.
	//
	// Support: Extended
	//
	// +listType=map
	// +listMapKey=name
	// +optional
	// +kubebuilder:validation:MaxItems=16
	QueryParams []HTTPQueryParamMatch `json:"queryParams,omitempty"`

	// Method specifies HTTP method matcher.
	// When specified, this route will be matched only if the request has the
	// specified method.
	//
	// Support: Extended
	//
	// +optional
	Method *HTTPMethod `json:"method,omitempty"`
}

// HTTPRouteFilter defines processing steps that must be completed during the
// request or response lifecycle. HTTPRouteFilters are meant as an extension
// point to express processing that may be done in Gateway implementations. Some
// examples include request or response modification, implementing
// authentication strategies, rate-limiting, and traffic shaping. API
// guarantee/conformance is defined based on the type of the filter.
type HTTPRouteFilter struct {
	// Type identifies the type of filter to apply. As with other API fields,
	// types are classified into three conformance levels:
	//
	// - Core: Filter types and their corresponding configuration defined by
	//   "Support: Core" in this package, e.g. "RequestHeaderModifier". All
	//   implementations must support core filters.
	//
	// - Extended: Filter types and their corresponding configuration defined by
	//   "Support: Extended" in this package, e.g. "RequestMirror". Implementers
	//   are encouraged to support extended filters.
	//
	// - Implementation-specific: Filters that are defined and supported by
	//   specific vendors.
	//   In the future, filters showing convergence in behavior across multiple
	//   implementations will be considered for inclusion in extended or core
	//   conformance levels. Filter-specific configuration for such filters
	//   is specified using the ExtensionRef field. `Type` should be set to
	//   "ExtensionRef" for custom filters.
	//
	// Implementers are encouraged to define custom implementation types to
	// extend the core API with implementation-specific behavior.
	//
	// If a reference to a custom filter type cannot be resolved, the filter
	// MUST NOT be skipped. Instead, requests that would have been processed by
	// that filter MUST receive a HTTP error response.
	//
	// Note that values may be added to this enum, implementations
	// must ensure that unknown values will not cause a crash.
	//
	// Unknown values here must result in the implementation setting the
	// Accepted Condition for the Route to `status: False`, with a
	// Reason of `UnsupportedValue`.
	//
	// +unionDiscriminator
	// +kubebuilder:validation:Enum=RequestHeaderModifier;RequestMirror;RequestRedirect;ExtensionRef
	// <gateway:experimental:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;RequestRedirect;URLRewrite;ExtensionRef>
	Type HTTPRouteFilterType `json:"type"`

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
	// <gateway:experimental>
	ResponseHeaderModifier *HTTPHeaderFilter `json:"responseHeaderModifier,omitempty"`

	// RequestMirror defines a schema for a filter that mirrors requests.
	// Requests are sent to the specified destination, but responses from
	// that destination are ignored.
	//
	// Support: Extended
	//
	// +optional
	RequestMirror *HTTPRequestMirrorFilter `json:"requestMirror,omitempty"`

	// RequestRedirect defines a schema for a filter that responds to the
	// request with an HTTP redirection.
	//
	// Support: Core
	//
	// +optional
	RequestRedirect *HTTPRequestRedirectFilter `json:"requestRedirect,omitempty"`

	// URLRewrite defines a schema for a filter that modifies a request during forwarding.
	//
	// Support: Extended
	//
	// <gateway:experimental>
	// +optional
	URLRewrite *HTTPURLRewriteFilter `json:"urlRewrite,omitempty"`

	// ExtensionRef is an optional, implementation-specific extension to the
	// "filter" behavior.  For example, resource "myroutefilter" in group
	// "networking.example.net"). ExtensionRef MUST NOT be used for core and
	// extended filters.
	//
	// Support: Implementation-specific
	//
	// +optional
	ExtensionRef *LocalObjectReference `json:"extensionRef,omitempty"`
}

// HTTPRouteFilterType identifies a type of HTTPRoute filter.
type HTTPRouteFilterType string

const (
	// HTTPRouteFilterRequestHeaderModifier can be used to add or remove an HTTP
	// header from an HTTP request before it is sent to the upstream target.
	//
	// Support in HTTPRouteRule: Core
	//
	// Support in HTTPBackendRef: Extended
	HTTPRouteFilterRequestHeaderModifier HTTPRouteFilterType = "RequestHeaderModifier"

	// HTTPRouteFilterResponseHeaderModifier can be used to add or remove an HTTP
	// header from an HTTP response before it is sent to the client.
	//
	// Support in HTTPRouteRule: Extended
	//
	// Support in HTTPBackendRef: Extended
	// <gateway:experimental>
	HTTPRouteFilterResponseHeaderModifier HTTPRouteFilterType = "ResponseHeaderModifier"

	// HTTPRouteFilterRequestRedirect can be used to redirect a request to
	// another location. This filter can also be used for HTTP to HTTPS
	// redirects. This may not be used on the same Route rule or BackendRef as a
	// URLRewrite filter.
	//
	// Support in HTTPRouteRule: Core
	//
	// Support in HTTPBackendRef: Extended
	HTTPRouteFilterRequestRedirect HTTPRouteFilterType = "RequestRedirect"

	// HTTPRouteFilterURLRewrite can be used to modify a request during
	// forwarding. At most one of these filters may be used on a Route rule.
	// This may not be used on the same Route rule or BackendRef as a
	// RequestRedirect filter.
	//
	// Support in HTTPRouteRule: Extended
	//
	// Support in HTTPBackendRef: Extended
	//
	// <gateway:experimental>
	HTTPRouteFilterURLRewrite HTTPRouteFilterType = "URLRewrite"

	// HTTPRouteFilterRequestMirror can be used to mirror HTTP requests to a
	// different backend. The responses from this backend MUST be ignored by
	// the Gateway.
	//
	// Support in HTTPRouteRule: Extended
	//
	// Support in HTTPBackendRef: Extended
	HTTPRouteFilterRequestMirror HTTPRouteFilterType = "RequestMirror"

	// HTTPRouteFilterExtensionRef should be used for configuring custom
	// HTTP filters.
	//
	// Support in HTTPRouteRule: Implementation-specific
	//
	// Support in HTTPBackendRef: Implementation-specific
	HTTPRouteFilterExtensionRef HTTPRouteFilterType = "ExtensionRef"
)

// HTTPHeader represents an HTTP Header name and value as defined by RFC 7230.
type HTTPHeader struct {
	// Name is the name of the HTTP Header to be matched. Name matching MUST be
	// case insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).
	//
	// If multiple entries specify equivalent header names, the first entry with
	// an equivalent name MUST be considered for a match. Subsequent entries
	// with an equivalent header name MUST be ignored. Due to the
	// case-insensitivity of header names, "foo" and "Foo" are considered
	// equivalent.
	Name HTTPHeaderName `json:"name"`

	// Value is the value of HTTP Header to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	Value string `json:"value"`
}

// HTTPHeaderFilter defines a filter that modifies the headers of an HTTP
// request or response. Only one action for a given header name is permitted.
// Filters specifying multiple actions of the same or different type for any one
// header name are invalid and will be rejected by the webhook if installed.
// Configuration to set or add multiple values for a header must use RFC 7230
// header value formatting, separating each value with a comma.
type HTTPHeaderFilter struct {
	// Set overwrites the request with the given header (name, value)
	// before the action.
	//
	// Input:
	//   GET /foo HTTP/1.1
	//   my-header: foo
	//
	// Config:
	//   set:
	//   - name: "my-header"
	//     value: "bar"
	//
	// Output:
	//   GET /foo HTTP/1.1
	//   my-header: bar
	//
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Set []HTTPHeader `json:"set,omitempty"`

	// Add adds the given header(s) (name, value) to the request
	// before the action. It appends to any existing values associated
	// with the header name.
	//
	// Input:
	//   GET /foo HTTP/1.1
	//   my-header: foo
	//
	// Config:
	//   add:
	//   - name: "my-header"
	//     value: "bar,baz"
	//
	// Output:
	//   GET /foo HTTP/1.1
	//   my-header: foo,bar,baz
	//
	// +optional
	// +listType=map
	// +listMapKey=name
	// +kubebuilder:validation:MaxItems=16
	Add []HTTPHeader `json:"add,omitempty"`

	// Remove the given header(s) from the HTTP request before the action. The
	// value of Remove is a list of HTTP header names. Note that the header
	// names are case-insensitive (see
	// https://datatracker.ietf.org/doc/html/rfc2616#section-4.2).
	//
	// Input:
	//   GET /foo HTTP/1.1
	//   my-header1: foo
	//   my-header2: bar
	//   my-header3: baz
	//
	// Config:
	//   remove: ["my-header1", "my-header3"]
	//
	// Output:
	//   GET /foo HTTP/1.1
	//   my-header2: bar
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Remove []string `json:"remove,omitempty"`
}

// HTTPPathModifierType defines the type of path redirect or rewrite.
type HTTPPathModifierType string

const (
	// This type of modifier indicates that the full path will be replaced
	// by the specified value.
	FullPathHTTPPathModifier HTTPPathModifierType = "ReplaceFullPath"

	// This type of modifier indicates that any prefix path matches will be
	// replaced by the substitution value. For example, a path with a prefix
	// match of "/foo" and a ReplacePrefixMatch substitution of "/bar" will have
	// the "/foo" prefix replaced with "/bar" in matching requests.
	//
	// Note that this matches the behavior of the PathPrefix match type. This
	// matches full path elements. A path element refers to the list of labels
	// in the path split by the `/` separator. When specified, a trailing `/` is
	// ignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all
	// match the prefix `/abc`, but the path `/abcd` would not.
	PrefixMatchHTTPPathModifier HTTPPathModifierType = "ReplacePrefixMatch"
)

// HTTPPathModifier defines configuration for path modifiers.
// <gateway:experimental>
type HTTPPathModifier struct {
	// Type defines the type of path modifier. Additional types may be
	// added in a future release of the API.
	//
	// Note that values may be added to this enum, implementations
	// must ensure that unknown values will not cause a crash.
	//
	// Unknown values here must result in the implementation setting the
	// Accepted Condition for the Route to `status: False`, with a
	// Reason of `UnsupportedValue`.
	//
	// <gateway:experimental>
	// +kubebuilder:validation:Enum=ReplaceFullPath;ReplacePrefixMatch
	Type HTTPPathModifierType `json:"type"`

	// ReplaceFullPath specifies the value with which to replace the full path
	// of a request during a rewrite or redirect.
	//
	// <gateway:experimental>
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	ReplaceFullPath *string `json:"replaceFullPath,omitempty"`

	// ReplacePrefixMatch specifies the value with which to replace the prefix
	// match of a request during a rewrite or redirect. For example, a request
	// to "/foo/bar" with a prefix match of "/foo" would be modified to "/bar".
	//
	// Note that this matches the behavior of the PathPrefix match type. This
	// matches full path elements. A path element refers to the list of labels
	// in the path split by the `/` separator. When specified, a trailing `/` is
	// ignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all
	// match the prefix `/abc`, but the path `/abcd` would not.
	//
	// <gateway:experimental>
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	ReplacePrefixMatch *string `json:"replacePrefixMatch,omitempty"`
}

// HTTPRequestRedirect defines a filter that redirects a request. This filter
// MUST NOT be used on the same Route rule as a HTTPURLRewrite filter.
type HTTPRequestRedirectFilter struct {
	// Scheme is the scheme to be used in the value of the `Location` header in
	// the response. When empty, the scheme of the request is used.
	//
	// Note that values may be added to this enum, implementations
	// must ensure that unknown values will not cause a crash.
	//
	// Unknown values here must result in the implementation setting the
	// Accepted Condition for the Route to `status: False`, with a
	// Reason of `UnsupportedValue`.
	//
	// Support: Extended
	//
	// +optional
	// +kubebuilder:validation:Enum=http;https
	Scheme *string `json:"scheme,omitempty"`

	// Hostname is the hostname to be used in the value of the `Location`
	// header in the response.
	// When empty, the hostname of the request is used.
	//
	// Support: Core
	//
	// +optional
	Hostname *PreciseHostname `json:"hostname,omitempty"`

	// Path defines parameters used to modify the path of the incoming request.
	// The modified path is then used to construct the `Location` header. When
	// empty, the request path is used as-is.
	//
	// Support: Extended
	//
	// <gateway:experimental>
	// +optional
	Path *HTTPPathModifier `json:"path,omitempty"`

	// Port is the port to be used in the value of the `Location`
	// header in the response.
	// When empty, port (if specified) of the request is used.
	//
	// Support: Extended
	//
	// +optional
	Port *PortNumber `json:"port,omitempty"`

	// StatusCode is the HTTP status code to be used in response.
	//
	// Note that values may be added to this enum, implementations
	// must ensure that unknown values will not cause a crash.
	//
	// Unknown values here must result in the implementation setting the
	// Accepted Condition for the Route to `status: False`, with a
	// Reason of `UnsupportedValue`.
	//
	// Support: Core
	//
	// +optional
	// +kubebuilder:default=302
	// +kubebuilder:validation:Enum=301;302
	StatusCode *int `json:"statusCode,omitempty"`
}

// HTTPURLRewriteFilter defines a filter that modifies a request during
// forwarding. At most one of these filters may be used on a Route rule. This
// MUST NOT be used on the same Route rule as a HTTPRequestRedirect filter.
//
// Support: Extended
//
// <gateway:experimental>
type HTTPURLRewriteFilter struct {
	// Hostname is the value to be used to replace the Host header value during
	// forwarding.
	//
	// Support: Extended
	//
	// <gateway:experimental>
	// +optional
	Hostname *PreciseHostname `json:"hostname,omitempty"`

	// Path defines a path rewrite.
	//
	// Support: Extended
	//
	// <gateway:experimental>
	// +optional
	Path *HTTPPathModifier `json:"path,omitempty"`
}

// HTTPRequestMirrorFilter defines configuration for the RequestMirror filter.
type HTTPRequestMirrorFilter struct {
	// BackendRef references a resource where mirrored requests are sent.
	//
	// If the referent cannot be found, this BackendRef is invalid and must be
	// dropped from the Gateway. The controller must ensure the "ResolvedRefs"
	// condition on the Route status is set to `status: False` and not configure
	// this backend in the underlying implementation.
	//
	// If there is a cross-namespace reference to an *existing* object
	// that is not allowed by a ReferenceGrant, the controller must ensure the
	// "ResolvedRefs"  condition on the Route is set to `status: False`,
	// with the "RefNotPermitted" reason and not configure this backend in the
	// underlying implementation.
	//
	// In either error case, the Message of the `ResolvedRefs` Condition
	// should be used to provide more detail about the problem.
	//
	// Support: Extended for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	BackendRef BackendObjectReference `json:"backendRef"`
}

// HTTPBackendRef defines how a HTTPRoute should forward an HTTP request.
type HTTPBackendRef struct {
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
	//   case, the Reason must be set to `InvalidKind` and Message of the
	//   Condition must explain which kind of resource is unknown or unsupported.
	//
	// * It refers to a resource that does not exist. In this case, the Reason must
	//   be set to `BackendNotFound` and the Message of the Condition must explain
	//   which resource does not exist.
	//
	// * It refers a resource in another namespace when the reference has not been
	//   explicitly allowed by a ReferenceGrant (or equivalent concept). In this
	//   case, the Reason must be set to `RefNotPermitted` and the Message of the
	//   Condition must explain which cross-namespace reference is not allowed.
	//
	// Support: Core for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	//
	// Support for weight: Core
	//
	// +optional
	BackendRef `json:",inline"`

	// Filters defined at this level should be executed if and only if the
	// request is being forwarded to the backend defined here.
	//
	// Support: Implementation-specific (For broader support of filters, use the
	// Filters field in HTTPRouteRule.)
	//
	// +optional
	// +kubebuilder:validation:MaxItems=16
	Filters []HTTPRouteFilter `json:"filters,omitempty"`
}

// HTTPRouteStatus defines the observed state of HTTPRoute.
type HTTPRouteStatus struct {
	RouteStatus `json:",inline"`
}
