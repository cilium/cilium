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
// +kubebuilder:resource:categories=gateway-api
// +kubebuilder:subresource:status
// +kubebuilder:storageversion
// +kubebuilder:printcolumn:name="Hostnames",type=string,JSONPath=`.spec.hostnames`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// HTTPRoute provides a way to route HTTP requests. This includes the capability
// to match requests by hostname, path, header, or query param. Filters can be
// used to specify additional processing steps. Backends specify where matching
// requests should be routed.
type HTTPRoute struct {
	metav1.TypeMeta `json:",inline"`
	// +optional
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec defines the desired state of HTTPRoute.
	// +required
	Spec HTTPRouteSpec `json:"spec"`

	// Status defines the current state of HTTPRoute.
	// +optional
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

	// Hostnames defines a set of hostnames that should match against the HTTP Host
	// header to select a HTTPRoute used to process the request. Implementations
	// MUST ignore any port value specified in the HTTP Host header while
	// performing a match and (absent of any applicable header modification
	// configuration) MUST forward this header unmodified to the backend.
	//
	// Valid values for Hostnames are determined by RFC 1123 definition of a
	// hostname with 2 notable exceptions:
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
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	Hostnames []Hostname `json:"hostnames,omitempty"`

	// Rules are a list of HTTP matchers, filters and actions.
	//
	// +optional
	// +listType=atomic
	// <gateway:experimental:validation:XValidation:message="Rule name must be unique within the route",rule="self.all(l1, !has(l1.name) || self.exists_one(l2, has(l2.name) && l1.name == l2.name))">
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:default={{matches: {{path: {type: "PathPrefix", value: "/"}}}}}
	// +kubebuilder:validation:XValidation:message="While 16 rules and 64 matches per rule are allowed, the total number of matches across all rules in a route must be less than 128",rule="(self.size() > 0 ? self[0].matches.size() : 0) + (self.size() > 1 ? self[1].matches.size() : 0) + (self.size() > 2 ? self[2].matches.size() : 0) + (self.size() > 3 ? self[3].matches.size() : 0) + (self.size() > 4 ? self[4].matches.size() : 0) + (self.size() > 5 ? self[5].matches.size() : 0) + (self.size() > 6 ? self[6].matches.size() : 0) + (self.size() > 7 ? self[7].matches.size() : 0) + (self.size() > 8 ? self[8].matches.size() : 0) + (self.size() > 9 ? self[9].matches.size() : 0) + (self.size() > 10 ? self[10].matches.size() : 0) + (self.size() > 11 ? self[11].matches.size() : 0) + (self.size() > 12 ? self[12].matches.size() : 0) + (self.size() > 13 ? self[13].matches.size() : 0) + (self.size() > 14 ? self[14].matches.size() : 0) + (self.size() > 15 ? self[15].matches.size() : 0) <= 128"
	Rules []HTTPRouteRule `json:"rules,omitempty"`
}

// HTTPRouteRule defines semantics for matching an HTTP request based on
// conditions (matches), processing it (filters), and forwarding the request to
// an API object (backendRefs).
//
// +kubebuilder:validation:XValidation:message="RequestRedirect filter must not be used together with backendRefs",rule="(has(self.backendRefs) && size(self.backendRefs) > 0) ? (!has(self.filters) || self.filters.all(f, !has(f.requestRedirect))): true"
// +kubebuilder:validation:XValidation:message="When using RequestRedirect filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",rule="(has(self.filters) && self.filters.exists_one(f, has(f.requestRedirect) && has(f.requestRedirect.path) && f.requestRedirect.path.type == 'ReplacePrefixMatch' && has(f.requestRedirect.path.replacePrefixMatch))) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
// +kubebuilder:validation:XValidation:message="When using URLRewrite filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",rule="(has(self.filters) && self.filters.exists_one(f, has(f.urlRewrite) && has(f.urlRewrite.path) && f.urlRewrite.path.type == 'ReplacePrefixMatch' && has(f.urlRewrite.path.replacePrefixMatch))) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
// +kubebuilder:validation:XValidation:message="Within backendRefs, when using RequestRedirect filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",rule="(has(self.backendRefs) && self.backendRefs.exists_one(b, (has(b.filters) && b.filters.exists_one(f, has(f.requestRedirect) && has(f.requestRedirect.path) && f.requestRedirect.path.type == 'ReplacePrefixMatch' && has(f.requestRedirect.path.replacePrefixMatch))) )) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
// +kubebuilder:validation:XValidation:message="Within backendRefs, When using URLRewrite filter with path.replacePrefixMatch, exactly one PathPrefix match must be specified",rule="(has(self.backendRefs) && self.backendRefs.exists_one(b, (has(b.filters) && b.filters.exists_one(f, has(f.urlRewrite) && has(f.urlRewrite.path) && f.urlRewrite.path.type == 'ReplacePrefixMatch' && has(f.urlRewrite.path.replacePrefixMatch))) )) ? ((size(self.matches) != 1 || !has(self.matches[0].path) || self.matches[0].path.type != 'PathPrefix') ? false : true) : true"
type HTTPRouteRule struct {
	// Name is the name of the route rule. This name MUST be unique within a Route if it is set.
	//
	// Support: Extended
	// +optional
	Name *SectionName `json:"name,omitempty"`

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
	// given to the match having:
	//
	// * "Exact" path match.
	// * "Prefix" path match with largest number of characters.
	// * Method match.
	// * Largest number of header matches.
	// * Largest number of query param matches.
	//
	// Note: The precedence of RegularExpression path matches are implementation-specific.
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
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:default={{path:{ type: "PathPrefix", value: "/"}}}
	Matches []HTTPRouteMatch `json:"matches,omitempty"`

	// Filters define the filters that are applied to requests that match
	// this rule.
	//
	// Wherever possible, implementations SHOULD implement filters in the order
	// they are specified.
	//
	// Implementations MAY choose to implement this ordering strictly, rejecting
	// any combination or order of filters that cannot be supported. If implementations
	// choose a strict interpretation of filter ordering, they MUST clearly document
	// that behavior.
	//
	// To reject an invalid combination or order of filters, implementations SHOULD
	// consider the Route Rules with this configuration invalid. If all Route Rules
	// in a Route are invalid, the entire Route would be considered invalid. If only
	// a portion of Route Rules are invalid, implementations MUST set the
	// "PartiallyInvalid" condition for the Route.
	//
	// Conformance-levels at this level are defined based on the type of filter:
	//
	// - ALL core filters MUST be supported by all implementations.
	// - Implementers are encouraged to support extended filters.
	// - Implementation-specific custom filters have no API guarantees across
	//   implementations.
	//
	// Specifying the same filter multiple times is not supported unless explicitly
	// indicated in the filter.
	//
	// All filters are expected to be compatible with each other except for the
	// URLRewrite and RequestRedirect filters, which may not be combined. If an
	// implementation cannot support other combinations of filters, they must clearly
	// document that limitation. In cases where incompatible or unsupported
	// filters are specified and cause the `Accepted` condition to be set to status
	// `False`, implementations may use the `IncompatibleFilters` reason to specify
	// this configuration error.
	//
	// Support: Core
	//
	// +optional
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="May specify either httpRouteFilterRequestRedirect or httpRouteFilterRequestRewrite, but not both",rule="!(self.exists(f, f.type == 'RequestRedirect') && self.exists(f, f.type == 'URLRewrite'))"
	// +kubebuilder:validation:XValidation:message="RequestHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
	// +kubebuilder:validation:XValidation:message="ResponseHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
	// +kubebuilder:validation:XValidation:message="RequestRedirect filter cannot be repeated",rule="self.filter(f, f.type == 'RequestRedirect').size() <= 1"
	// +kubebuilder:validation:XValidation:message="URLRewrite filter cannot be repeated",rule="self.filter(f, f.type == 'URLRewrite').size() <= 1"
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
	// When a HTTPBackendRef refers to a Service that has no ready endpoints,
	// implementations SHOULD return a 503 for requests to that backend instead.
	// If an implementation chooses to do this, all of the above rules for 500 responses
	// MUST also apply for responses that return a 503.
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
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	BackendRefs []HTTPBackendRef `json:"backendRefs,omitempty"`

	// Timeouts defines the timeouts that can be configured for an HTTP request.
	//
	// Support: Extended
	//
	// +optional
	Timeouts *HTTPRouteTimeouts `json:"timeouts,omitempty"`

	// Retry defines the configuration for when to retry an HTTP request.
	//
	// Support: Extended
	//
	// +optional
	// <gateway:experimental>
	Retry *HTTPRouteRetry `json:"retry,omitempty"`

	// SessionPersistence defines and configures session persistence
	// for the route rule.
	//
	// Support: Extended
	//
	// +optional
	// <gateway:experimental>
	SessionPersistence *SessionPersistence `json:"sessionPersistence,omitempty"`
}

// HTTPRouteTimeouts defines timeouts that can be configured for an HTTPRoute.
// Timeout values are represented with Gateway API Duration formatting.
//
// +kubebuilder:validation:XValidation:message="backendRequest timeout cannot be longer than request timeout",rule="!(has(self.request) && has(self.backendRequest) && duration(self.request) != duration('0s') && duration(self.backendRequest) > duration(self.request))"
type HTTPRouteTimeouts struct {
	// Request specifies the maximum duration for a gateway to respond to an HTTP request.
	// If the gateway has not been able to respond before this deadline is met, the gateway
	// MUST return a timeout error.
	//
	// For example, setting the `rules.timeouts.request` field to the value `10s` in an
	// `HTTPRoute` will cause a timeout if a client request is taking longer than 10 seconds
	// to complete.
	//
	// Setting a timeout to the zero duration (e.g. "0s") SHOULD disable the timeout
	// completely. Implementations that cannot completely disable the timeout MUST
	// instead interpret the zero duration as the longest possible value to which
	// the timeout can be set.
	//
	// This timeout is intended to cover as close to the whole request-response transaction
	// as possible although an implementation MAY choose to start the timeout after the entire
	// request stream has been received instead of immediately after the transaction is
	// initiated by the client.
	//
	// The value of Request is a Gateway API Duration string as defined by GEP-2257. When this
	// field is unspecified, request timeout behavior is implementation-specific.
	//
	// Support: Extended
	//
	// +optional
	Request *Duration `json:"request,omitempty"`

	// BackendRequest specifies a timeout for an individual request from the gateway
	// to a backend. This covers the time from when the request first starts being
	// sent from the gateway to when the full response has been received from the backend.
	//
	// Setting a timeout to the zero duration (e.g. "0s") SHOULD disable the timeout
	// completely. Implementations that cannot completely disable the timeout MUST
	// instead interpret the zero duration as the longest possible value to which
	// the timeout can be set.
	//
	// An entire client HTTP transaction with a gateway, covered by the Request timeout,
	// may result in more than one call from the gateway to the destination backend,
	// for example, if automatic retries are supported.
	//
	// The value of BackendRequest must be a Gateway API Duration string as defined by
	// GEP-2257.  When this field is unspecified, its behavior is implementation-specific;
	// when specified, the value of BackendRequest must be no more than the value of the
	// Request timeout (since the Request timeout encompasses the BackendRequest timeout).
	//
	// Support: Extended
	//
	// +optional
	BackendRequest *Duration `json:"backendRequest,omitempty"`
}

// HTTPRouteRetry defines retry configuration for an HTTPRoute.
//
// Implementations SHOULD retry on connection errors (disconnect, reset, timeout,
// TCP failure) if a retry stanza is configured.
type HTTPRouteRetry struct {
	// Codes defines the HTTP response status codes for which a backend request
	// should be retried.
	//
	// Support: Extended
	//
	// +optional
	// +listType=atomic
	Codes []HTTPRouteRetryStatusCode `json:"codes,omitempty"`

	// Attempts specifies the maximum number of times an individual request
	// from the gateway to a backend should be retried.
	//
	// If the maximum number of retries has been attempted without a successful
	// response from the backend, the Gateway MUST return an error.
	//
	// When this field is unspecified, the number of times to attempt to retry
	// a backend request is implementation-specific.
	//
	// Support: Extended
	//
	// +optional
	Attempts *int `json:"attempts,omitempty"`

	// Backoff specifies the minimum duration a Gateway should wait between
	// retry attempts and is represented in Gateway API Duration formatting.
	//
	// For example, setting the `rules[].retry.backoff` field to the value
	// `100ms` will cause a backend request to first be retried approximately
	// 100 milliseconds after timing out or receiving a response code configured
	// to be retryable.
	//
	// An implementation MAY use an exponential or alternative backoff strategy
	// for subsequent retry attempts, MAY cap the maximum backoff duration to
	// some amount greater than the specified minimum, and MAY add arbitrary
	// jitter to stagger requests, as long as unsuccessful backend requests are
	// not retried before the configured minimum duration.
	//
	// If a Request timeout (`rules[].timeouts.request`) is configured on the
	// route, the entire duration of the initial request and any retry attempts
	// MUST not exceed the Request timeout duration. If any retry attempts are
	// still in progress when the Request timeout duration has been reached,
	// these SHOULD be canceled if possible and the Gateway MUST immediately
	// return a timeout error.
	//
	// If a BackendRequest timeout (`rules[].timeouts.backendRequest`) is
	// configured on the route, any retry attempts which reach the configured
	// BackendRequest timeout duration without a response SHOULD be canceled if
	// possible and the Gateway should wait for at least the specified backoff
	// duration before attempting to retry the backend request again.
	//
	// If a BackendRequest timeout is _not_ configured on the route, retry
	// attempts MAY time out after an implementation default duration, or MAY
	// remain pending until a configured Request timeout or implementation
	// default duration for total request time is reached.
	//
	// When this field is unspecified, the time to wait between retry attempts
	// is implementation-specific.
	//
	// Support: Extended
	//
	// +optional
	Backoff *Duration `json:"backoff,omitempty"`
}

// HTTPRouteRetryStatusCode defines an HTTP response status code for
// which a backend request should be retried.
//
// Implementations MUST support the following status codes as retryable:
//
// * 500
// * 502
// * 503
// * 504
//
// Implementations MAY support specifying additional discrete values in the
// 500-599 range.
//
// Implementations MAY support specifying discrete values in the 400-499 range,
// which are often inadvisable to retry.
//
// +kubebuilder:validation:Minimum:=400
// +kubebuilder:validation:Maximum:=599
// <gateway:experimental>
type HTTPRouteRetryStatusCode int

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
	// Matches the URL path exactly and with case sensitivity. This means that
	// an exact path match on `/abc` will only match requests to `/abc`, NOT
	// `/abc/`, `/Abc`, or `/abcd`.
	PathMatchExact PathMatchType = "Exact"

	// Matches based on a URL path prefix split by `/`. Matching is
	// case-sensitive and done on a path element by element basis. A
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
//
// +kubebuilder:validation:XValidation:message="value must be an absolute path and start with '/' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? self.value.startsWith('/') : true"
// +kubebuilder:validation:XValidation:message="must not contain '//' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.contains('//') : true"
// +kubebuilder:validation:XValidation:message="must not contain '/./' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.contains('/./') : true"
// +kubebuilder:validation:XValidation:message="must not contain '/../' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.contains('/../') : true"
// +kubebuilder:validation:XValidation:message="must not contain '%2f' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.contains('%2f') : true"
// +kubebuilder:validation:XValidation:message="must not contain '%2F' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.contains('%2F') : true"
// +kubebuilder:validation:XValidation:message="must not contain '#' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.contains('#') : true"
// +kubebuilder:validation:XValidation:message="must not end with '/..' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.endsWith('/..') : true"
// +kubebuilder:validation:XValidation:message="must not end with '/.' when type one of ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? !self.value.endsWith('/.') : true"
// +kubebuilder:validation:XValidation:message="type must be one of ['Exact', 'PathPrefix', 'RegularExpression']",rule="self.type in ['Exact','PathPrefix'] || self.type == 'RegularExpression'"
// +kubebuilder:validation:XValidation:message="must only contain valid characters (matching ^(?:[-A-Za-z0-9/._~!$&'()*+,;=:@]|[%][0-9a-fA-F]{2})+$) for types ['Exact', 'PathPrefix']",rule="(self.type in ['Exact','PathPrefix']) ? self.value.matches(r\"\"\"^(?:[-A-Za-z0-9/._~!$&'()*+,;=:@]|[%][0-9a-fA-F]{2})+$\"\"\") : true"
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
//   - "/invalid" - "/ " is an invalid character
type HTTPHeaderName HeaderName

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
	// case-insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).
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
	// +required
	Name HTTPHeaderName `json:"name"`

	// Value is the value of HTTP Header to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	// +required
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
	// +required
	Name HTTPHeaderName `json:"name"`

	// Value is the value of HTTP query param to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=1024
	// +required
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

// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;DELETE;CONNECT;OPTIONS;TRACE;PATCH;*
type HTTPMethodWithWildcard string

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
//
// +kubebuilder:validation:XValidation:message="filter.requestHeaderModifier must be nil if the filter.type is not RequestHeaderModifier",rule="!(has(self.requestHeaderModifier) && self.type != 'RequestHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.requestHeaderModifier must be specified for RequestHeaderModifier filter.type",rule="!(!has(self.requestHeaderModifier) && self.type == 'RequestHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.responseHeaderModifier must be nil if the filter.type is not ResponseHeaderModifier",rule="!(has(self.responseHeaderModifier) && self.type != 'ResponseHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.responseHeaderModifier must be specified for ResponseHeaderModifier filter.type",rule="!(!has(self.responseHeaderModifier) && self.type == 'ResponseHeaderModifier')"
// +kubebuilder:validation:XValidation:message="filter.requestMirror must be nil if the filter.type is not RequestMirror",rule="!(has(self.requestMirror) && self.type != 'RequestMirror')"
// +kubebuilder:validation:XValidation:message="filter.requestMirror must be specified for RequestMirror filter.type",rule="!(!has(self.requestMirror) && self.type == 'RequestMirror')"
// +kubebuilder:validation:XValidation:message="filter.requestRedirect must be nil if the filter.type is not RequestRedirect",rule="!(has(self.requestRedirect) && self.type != 'RequestRedirect')"
// +kubebuilder:validation:XValidation:message="filter.requestRedirect must be specified for RequestRedirect filter.type",rule="!(!has(self.requestRedirect) && self.type == 'RequestRedirect')"
// +kubebuilder:validation:XValidation:message="filter.urlRewrite must be nil if the filter.type is not URLRewrite",rule="!(has(self.urlRewrite) && self.type != 'URLRewrite')"
// +kubebuilder:validation:XValidation:message="filter.urlRewrite must be specified for URLRewrite filter.type",rule="!(!has(self.urlRewrite) && self.type == 'URLRewrite')"
// <gateway:experimental:validation:XValidation:message="filter.cors must be nil if the filter.type is not CORS",rule="!(has(self.cors) && self.type != 'CORS')">
// <gateway:experimental:validation:XValidation:message="filter.cors must be specified for CORS filter.type",rule="!(!has(self.cors) && self.type == 'CORS')">
// <gateway:experimental:validation:XValidation:message="filter.externalAuth must be nil if the filter.type is not ExternalAuth",rule="!(has(self.externalAuth) && self.type != 'ExternalAuth')">
// <gateway:experimental:validation:XValidation:message="filter.externalAuth must be specified for ExternalAuth filter.type",rule="!(!has(self.externalAuth) && self.type == 'ExternalAuth')">
// +kubebuilder:validation:XValidation:message="filter.extensionRef must be nil if the filter.type is not ExtensionRef",rule="!(has(self.extensionRef) && self.type != 'ExtensionRef')"
// +kubebuilder:validation:XValidation:message="filter.extensionRef must be specified for ExtensionRef filter.type",rule="!(!has(self.extensionRef) && self.type == 'ExtensionRef')"
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
	// +kubebuilder:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;RequestRedirect;URLRewrite;ExtensionRef
	// <gateway:experimental:validation:Enum=RequestHeaderModifier;ResponseHeaderModifier;RequestMirror;RequestRedirect;URLRewrite;ExtensionRef;CORS;ExternalAuth>
	// +required
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
	// +kubebuilder:validation:XValidation:message="Only one of percent or fraction may be specified in HTTPRequestMirrorFilter",rule="!(has(self.percent) && has(self.fraction))"
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
	// +optional
	URLRewrite *HTTPURLRewriteFilter `json:"urlRewrite,omitempty"`

	// CORS defines a schema for a filter that responds to the
	// cross-origin request based on HTTP response header.
	//
	// Support: Extended
	//
	// +optional
	// <gateway:experimental>
	CORS *HTTPCORSFilter `json:"cors,omitempty"`

	// ExternalAuth configures settings related to sending request details
	// to an external auth service. The external service MUST authenticate
	// the request, and MAY authorize the request as well.
	//
	// If there is any problem communicating with the external service,
	// this filter MUST fail closed.
	//
	// Support: Extended
	//
	// +optional
	// <gateway:experimental>
	ExternalAuth *HTTPExternalAuthFilter `json:"externalAuth,omitempty"`

	// ExtensionRef is an optional, implementation-specific extension to the
	// "filter" behavior.  For example, resource "myroutefilter" in group
	// "networking.example.net"). ExtensionRef MUST NOT be used for core and
	// extended filters.
	//
	// This filter can be used multiple times within the same rule.
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
	HTTPRouteFilterURLRewrite HTTPRouteFilterType = "URLRewrite"

	// HTTPRouteFilterRequestMirror can be used to mirror HTTP requests to a
	// different backend. The responses from this backend MUST be ignored by
	// the Gateway.
	//
	// Support in HTTPRouteRule: Extended
	//
	// Support in HTTPBackendRef: Extended
	HTTPRouteFilterRequestMirror HTTPRouteFilterType = "RequestMirror"

	// HTTPRouteFilterCORS can be used to add CORS headers to an
	// HTTP response before it is sent to the client.
	//
	// Support in HTTPRouteRule: Extended
	//
	// Support in HTTPBackendRef: Extended
	// <gateway:experimental>
	HTTPRouteFilterCORS HTTPRouteFilterType = "CORS"

	// HTTPRouteFilterExternalAuth can be used to configure a Gateway implementation
	// to call out to an external Auth server, which MUST perform Authentication
	// and MAY perform Authorization on the matched request before the request
	// is forwarded to the backend.
	//
	// Support in HTTPRouteRule: Extended
	//
	// Feature Name: HTTPRouteExternalAuth
	//
	// <gateway:experimental>
	HTTPRouteFilterExternalAuth HTTPRouteFilterType = "ExternalAuth"

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
	// case-insensitive. (See https://tools.ietf.org/html/rfc7230#section-3.2).
	//
	// If multiple entries specify equivalent header names, the first entry with
	// an equivalent name MUST be considered for a match. Subsequent entries
	// with an equivalent header name MUST be ignored. Due to the
	// case-insensitivity of header names, "foo" and "Foo" are considered
	// equivalent.
	// +required
	Name HTTPHeaderName `json:"name"`

	// Value is the value of HTTP Header to be matched.
	//
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=4096
	// +required
	Value string `json:"value"`
}

// HTTPHeaderFilter defines a filter that modifies the headers of an HTTP
// request or response. Only one action for a given header name is
// permitted. Filters specifying multiple actions of the same or different
// type for any one header name are invalid. Configuration to set or add
// multiple values for a header must use RFC 7230 header value formatting,
// separating each value with a comma.
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
	// +listType=set
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
//
// +kubebuilder:validation:XValidation:message="replaceFullPath must be specified when type is set to 'ReplaceFullPath'",rule="self.type == 'ReplaceFullPath' ? has(self.replaceFullPath) : true"
// +kubebuilder:validation:XValidation:message="type must be 'ReplaceFullPath' when replaceFullPath is set",rule="has(self.replaceFullPath) ? self.type == 'ReplaceFullPath' : true"
// +kubebuilder:validation:XValidation:message="replacePrefixMatch must be specified when type is set to 'ReplacePrefixMatch'",rule="self.type == 'ReplacePrefixMatch' ? has(self.replacePrefixMatch) : true"
// +kubebuilder:validation:XValidation:message="type must be 'ReplacePrefixMatch' when replacePrefixMatch is set",rule="has(self.replacePrefixMatch) ? self.type == 'ReplacePrefixMatch' : true"
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
	// +kubebuilder:validation:Enum=ReplaceFullPath;ReplacePrefixMatch
	// +required
	Type HTTPPathModifierType `json:"type"`

	// ReplaceFullPath specifies the value with which to replace the full path
	// of a request during a rewrite or redirect.
	//
	// +kubebuilder:validation:MaxLength=1024
	// +optional
	ReplaceFullPath *string `json:"replaceFullPath,omitempty"`

	// ReplacePrefixMatch specifies the value with which to replace the prefix
	// match of a request during a rewrite or redirect. For example, a request
	// to "/foo/bar" with a prefix match of "/foo" and a ReplacePrefixMatch
	// of "/xyz" would be modified to "/xyz/bar".
	//
	// Note that this matches the behavior of the PathPrefix match type. This
	// matches full path elements. A path element refers to the list of labels
	// in the path split by the `/` separator. When specified, a trailing `/` is
	// ignored. For example, the paths `/abc`, `/abc/`, and `/abc/def` would all
	// match the prefix `/abc`, but the path `/abcd` would not.
	//
	// ReplacePrefixMatch is only compatible with a `PathPrefix` HTTPRouteMatch.
	// Using any other HTTPRouteMatch type on the same HTTPRouteRule will result in
	// the implementation setting the Accepted Condition for the Route to `status: False`.
	//
	// Request Path | Prefix Match | Replace Prefix | Modified Path
	// -------------|--------------|----------------|----------
	// /foo/bar     | /foo         | /xyz           | /xyz/bar
	// /foo/bar     | /foo         | /xyz/          | /xyz/bar
	// /foo/bar     | /foo/        | /xyz           | /xyz/bar
	// /foo/bar     | /foo/        | /xyz/          | /xyz/bar
	// /foo         | /foo         | /xyz           | /xyz
	// /foo/        | /foo         | /xyz           | /xyz/
	// /foo/bar     | /foo         | <empty string> | /bar
	// /foo/        | /foo         | <empty string> | /
	// /foo         | /foo         | <empty string> | /
	// /foo/        | /foo         | /              | /
	// /foo         | /foo         | /              | /
	//
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
	// Scheme redirects can affect the port of the redirect, for more information,
	// refer to the documentation for the port field of this filter.
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
	// When empty, the hostname in the `Host` header of the request is used.
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
	// +optional
	Path *HTTPPathModifier `json:"path,omitempty"`

	// Port is the port to be used in the value of the `Location`
	// header in the response.
	//
	// If no port is specified, the redirect port MUST be derived using the
	// following rules:
	//
	// * If redirect scheme is not-empty, the redirect port MUST be the well-known
	//   port associated with the redirect scheme. Specifically "http" to port 80
	//   and "https" to port 443. If the redirect scheme does not have a
	//   well-known port, the listener port of the Gateway SHOULD be used.
	// * If redirect scheme is empty, the redirect port MUST be the Gateway
	//   Listener port.
	//
	// Implementations SHOULD NOT add the port number in the 'Location'
	// header in the following cases:
	//
	// * A Location header that will use HTTP (whether that is determined via
	//   the Listener protocol or the Scheme field) _and_ use port 80.
	// * A Location header that will use HTTPS (whether that is determined via
	//   the Listener protocol or the Scheme field) _and_ use port 443.
	//
	// Support: Extended
	//
	// +optional
	//
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
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
type HTTPURLRewriteFilter struct {
	// Hostname is the value to be used to replace the Host header value during
	// forwarding.
	//
	// Support: Extended
	//
	// +optional
	Hostname *PreciseHostname `json:"hostname,omitempty"`

	// Path defines a path rewrite.
	//
	// Support: Extended
	//
	// +optional
	Path *HTTPPathModifier `json:"path,omitempty"`
}

// HTTPRequestMirrorFilter defines configuration for the RequestMirror filter.
type HTTPRequestMirrorFilter struct {
	// BackendRef references a resource where mirrored requests are sent.
	//
	// Mirrored requests must be sent only to a single destination endpoint
	// within this BackendRef, irrespective of how many endpoints are present
	// within this BackendRef.
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
	// +required
	BackendRef BackendObjectReference `json:"backendRef"`

	// Percent represents the percentage of requests that should be
	// mirrored to BackendRef. Its minimum value is 0 (indicating 0% of
	// requests) and its maximum value is 100 (indicating 100% of requests).
	//
	// Only one of Fraction or Percent may be specified. If neither field
	// is specified, 100% of requests will be mirrored.
	//
	// +optional
	// +kubebuilder:validation:Minimum=0
	// +kubebuilder:validation:Maximum=100
	Percent *int32 `json:"percent,omitempty"`

	// Fraction represents the fraction of requests that should be
	// mirrored to BackendRef.
	//
	// Only one of Fraction or Percent may be specified. If neither field
	// is specified, 100% of requests will be mirrored.
	//
	// +optional
	Fraction *Fraction `json:"fraction,omitempty"`
}

// HTTPCORSFilter defines a filter that that configures Cross-Origin Request
// Sharing (CORS).
type HTTPCORSFilter struct {
	// AllowOrigins indicates whether the response can be shared with requested
	// resource from the given `Origin`.
	//
	// The `Origin` consists of a scheme and a host, with an optional port, and
	// takes the form `<scheme>://<host>(:<port>)`.
	//
	// Valid values for scheme are: `http` and `https`.
	//
	// Valid values for port are any integer between 1 and 65535 (the list of
	// available TCP/UDP ports). Note that, if not included, port `80` is
	// assumed for `http` scheme origins, and port `443` is assumed for `https`
	// origins. This may affect origin matching.
	//
	// The host part of the origin may contain the wildcard character `*`. These
	// wildcard characters behave as follows:
	//
	// * `*` is a greedy match to the _left_, including any number of
	//   DNS labels to the left of its position. This also means that
	//   `*` will include any number of period `.` characters to the
	//   left of its position.
	// * A wildcard by itself matches all hosts.
	//
	// An origin value that includes _only_ the `*` character indicates requests
	// from all `Origin`s are allowed.
	//
	// When the `AllowOrigins` field is configured with multiple origins, it
	// means the server supports clients from multiple origins. If the request
	// `Origin` matches the configured allowed origins, the gateway must return
	// the given `Origin` and sets value of the header
	// `Access-Control-Allow-Origin` same as the `Origin` header provided by the
	// client.
	//
	// The status code of a successful response to a "preflight" request is
	// always an OK status (i.e., 204 or 200).
	//
	// If the request `Origin` does not match the configured allowed origins,
	// the gateway returns 204/200 response but doesn't set the relevant
	// cross-origin response headers. Alternatively, the gateway responds with
	// 403 status to the "preflight" request is denied, coupled with omitting
	// the CORS headers. The cross-origin request fails on the client side.
	// Therefore, the client doesn't attempt the actual cross-origin request.
	//
	// The `Access-Control-Allow-Origin` response header can only use `*`
	// wildcard as value when the `AllowCredentials` field is false or omitted.
	//
	// When the `AllowCredentials` field is true and `AllowOrigins` field
	// specified with the `*` wildcard, the gateway must return a single origin
	// in the value of the `Access-Control-Allow-Origin` response header,
	// instead of specifying the `*` wildcard. The value of the header
	// `Access-Control-Allow-Origin` is same as the `Origin` header provided by
	// the client.
	//
	// Support: Extended
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:XValidation:message="AllowOrigins cannot contain '*' alongside other origins",rule="!('*' in self && self.size() > 1)"
	// +optional
	AllowOrigins []CORSOrigin `json:"allowOrigins,omitempty"`

	// AllowCredentials indicates whether the actual cross-origin request allows
	// to include credentials.
	//
	// When set to true, the gateway will include the `Access-Control-Allow-Credentials`
	// response header with value true (case-sensitive).
	//
	// When set to false or omitted the gateway will omit the header
	// `Access-Control-Allow-Credentials` entirely (this is the standard CORS
	// behavior).
	//
	// Support: Extended
	//
	// +optional
	AllowCredentials *bool `json:"allowCredentials,omitempty"`

	// AllowMethods indicates which HTTP methods are supported for accessing the
	// requested resource.
	//
	// Valid values are any method defined by RFC9110, along with the special
	// value `*`, which represents all HTTP methods are allowed.
	//
	// Method names are case sensitive, so these values are also case-sensitive.
	// (See https://www.rfc-editor.org/rfc/rfc2616#section-5.1.1)
	//
	// Multiple method names in the value of the `Access-Control-Allow-Methods`
	// response header are separated by a comma (",").
	//
	// A CORS-safelisted method is a method that is `GET`, `HEAD`, or `POST`.
	// (See https://fetch.spec.whatwg.org/#cors-safelisted-method) The
	// CORS-safelisted methods are always allowed, regardless of whether they
	// are specified in the `AllowMethods` field.
	//
	// When the `AllowMethods` field is configured with one or more methods, the
	// gateway must return the `Access-Control-Allow-Methods` response header
	// which value is present in the `AllowMethods` field.
	//
	// If the HTTP method of the `Access-Control-Request-Method` request header
	// is not included in the list of methods specified by the response header
	// `Access-Control-Allow-Methods`, it will present an error on the client
	// side.
	//
	// The `Access-Control-Allow-Methods` response header can only use `*`
	// wildcard as value when the `AllowCredentials` field is false or omitted.
	//
	// When the `AllowCredentials` field is true and `AllowMethods` field
	// specified with the `*` wildcard, the gateway must specify one HTTP method
	// in the value of the Access-Control-Allow-Methods response header. The
	// value of the header `Access-Control-Allow-Methods` is same as the
	// `Access-Control-Request-Method` header provided by the client. If the
	// header `Access-Control-Request-Method` is not included in the request,
	// the gateway will omit the `Access-Control-Allow-Methods` response header,
	// instead of specifying the `*` wildcard. A Gateway implementation may
	// choose to add implementation-specific default methods.
	//
	// Support: Extended
	//
	// +listType=set
	// +kubebuilder:validation:MaxItems=9
	// +kubebuilder:validation:XValidation:message="AllowMethods cannot contain '*' alongside other methods",rule="!('*' in self && self.size() > 1)"
	// +optional
	AllowMethods []HTTPMethodWithWildcard `json:"allowMethods,omitempty"`

	// AllowHeaders indicates which HTTP request headers are supported for
	// accessing the requested resource.
	//
	// Header names are not case sensitive.
	//
	// Multiple header names in the value of the `Access-Control-Allow-Headers`
	// response header are separated by a comma (",").
	//
	// When the `AllowHeaders` field is configured with one or more headers, the
	// gateway must return the `Access-Control-Allow-Headers` response header
	// which value is present in the `AllowHeaders` field.
	//
	// If any header name in the `Access-Control-Request-Headers` request header
	// is not included in the list of header names specified by the response
	// header `Access-Control-Allow-Headers`, it will present an error on the
	// client side.
	//
	// If any header name in the `Access-Control-Allow-Headers` response header
	// does not recognize by the client, it will also occur an error on the
	// client side.
	//
	// A wildcard indicates that the requests with all HTTP headers are allowed.
	// The `Access-Control-Allow-Headers` response header can only use `*`
	// wildcard as value when the `AllowCredentials` field is false or omitted.
	//
	// When the `AllowCredentials` field is true and `AllowHeaders` field
	// specified with the `*` wildcard, the gateway must specify one or more
	// HTTP headers in the value of the `Access-Control-Allow-Headers` response
	// header. The value of the header `Access-Control-Allow-Headers` is same as
	// the `Access-Control-Request-Headers` header provided by the client. If
	// the header `Access-Control-Request-Headers` is not included in the
	// request, the gateway will omit the `Access-Control-Allow-Headers`
	// response header, instead of specifying the `*` wildcard. A Gateway
	// implementation may choose to add implementation-specific default headers.
	//
	// Support: Extended
	//
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	// +optional
	AllowHeaders []HTTPHeaderName `json:"allowHeaders,omitempty"`

	// ExposeHeaders indicates which HTTP response headers can be exposed
	// to client-side scripts in response to a cross-origin request.
	//
	// A CORS-safelisted response header is an HTTP header in a CORS response
	// that it is considered safe to expose to the client scripts.
	// The CORS-safelisted response headers include the following headers:
	// `Cache-Control`
	// `Content-Language`
	// `Content-Length`
	// `Content-Type`
	// `Expires`
	// `Last-Modified`
	// `Pragma`
	// (See https://fetch.spec.whatwg.org/#cors-safelisted-response-header-name)
	// The CORS-safelisted response headers are exposed to client by default.
	//
	// When an HTTP header name is specified using the `ExposeHeaders` field,
	// this additional header will be exposed as part of the response to the
	// client.
	//
	// Header names are not case sensitive.
	//
	// Multiple header names in the value of the `Access-Control-Expose-Headers`
	// response header are separated by a comma (",").
	//
	// A wildcard indicates that the responses with all HTTP headers are exposed
	// to clients. The `Access-Control-Expose-Headers` response header can only
	// use `*` wildcard as value when the `AllowCredentials` field is false or omitted.
	//
	// Support: Extended
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=64
	ExposeHeaders []HTTPHeaderName `json:"exposeHeaders,omitempty"`

	// MaxAge indicates the duration (in seconds) for the client to cache the
	// results of a "preflight" request.
	//
	// The information provided by the `Access-Control-Allow-Methods` and
	// `Access-Control-Allow-Headers` response headers can be cached by the
	// client until the time specified by `Access-Control-Max-Age` elapses.
	//
	// The default value of `Access-Control-Max-Age` response header is 5
	// (seconds).
	//
	// +optional
	// +kubebuilder:default=5
	// +kubebuilder:validation:Minimum=1
	MaxAge int32 `json:"maxAge,omitempty"`
}

// HTTPRouteExternalAuthProtcol specifies what protocol should be used
// for communicating with an external authorization server.
//
// Valid values are supplied as constants below.
type HTTPRouteExternalAuthProtocol string

const (
	HTTPRouteExternalAuthGRPCProtocol HTTPRouteExternalAuthProtocol = "GRPC"
	HTTPRouteExternalAuthHTTPProtocol HTTPRouteExternalAuthProtocol = "HTTP"
)

// HTTPExternalAuthFilter defines a filter that modifies requests by sending
// request details to an external authorization server.
//
// Support: Extended
// Feature Name: HTTPRouteExternalAuth
// +kubebuilder:validation:XValidation:message="grpc must be specified when protocol is set to 'GRPC'",rule="self.protocol == 'GRPC' ? has(self.grpc) : true"
// +kubebuilder:validation:XValidation:message="protocol must be 'GRPC' when grpc is set",rule="has(self.grpc) ? self.protocol == 'GRPC' : true"
// +kubebuilder:validation:XValidation:message="http must be specified when protocol is set to 'HTTP'",rule="self.protocol == 'HTTP' ? has(self.http) : true"
// +kubebuilder:validation:XValidation:message="protocol must be 'HTTP' when http is set",rule="has(self.http) ? self.protocol == 'HTTP' : true"
type HTTPExternalAuthFilter struct {
	// ExternalAuthProtocol describes which protocol to use when communicating with an
	// ext_authz authorization server.
	//
	// When this is set to GRPC, each backend must use the Envoy ext_authz protocol
	// on the port specified in `backendRefs`. Requests and responses are defined
	// in the protobufs explained at:
	// https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto
	//
	// When this is set to HTTP, each backend must respond with a `200` status
	// code in on a successful authorization. Any other code is considered
	// an authorization failure.
	//
	// Feature Names:
	// GRPC Support - HTTPRouteExternalAuthGRPC
	// HTTP Support - HTTPRouteExternalAuthHTTP
	//
	// +unionDiscriminator
	// +required
	// +kubebuilder:validation:Enum=HTTP;GRPC
	ExternalAuthProtocol HTTPRouteExternalAuthProtocol `json:"protocol,omitempty"`

	// BackendRef is a reference to a backend to send authorization
	// requests to.
	//
	// The backend must speak the selected protocol (GRPC or HTTP) on the
	// referenced port.
	//
	// If the backend service requires TLS, use BackendTLSPolicy to tell the
	// implementation to supply the TLS details to be used to connect to that
	// backend.
	//
	// +required
	BackendRef BackendObjectReference `json:"backendRef,omitempty"`

	// GRPCAuthConfig contains configuration for communication with ext_authz
	// protocol-speaking backends.
	//
	// If unset, implementations must assume the default behavior for each
	// included field is intended.
	//
	// +optional
	GRPCAuthConfig *GRPCAuthConfig `json:"grpc,omitempty"`

	// HTTPAuthConfig contains configuration for communication with HTTP-speaking
	// backends.
	//
	// If unset, implementations must assume the default behavior for each
	// included field is intended.
	//
	// +optional
	HTTPAuthConfig *HTTPAuthConfig `json:"http,omitempty"`

	// ForwardBody controls if requests to the authorization server should include
	// the body of the client request; and if so, how big that body is allowed
	// to be.
	//
	// It is expected that implementations will buffer the request body up to
	// `forwardBody.maxSize` bytes. Bodies over that size must be rejected with a
	// 4xx series error (413 or 403 are common examples), and fail processing
	// of the filter.
	//
	// If unset, or `forwardBody.maxSize` is set to `0`, then the body will not
	// be forwarded.
	//
	// Feature Name: HTTPRouteExternalAuthForwardBody
	//
	//
	// +optional
	ForwardBody *ForwardBodyConfig `json:"forwardBody,omitempty"`
}

// GRPCAuthConfig contains configuration for communication with Auth server
// backends that speak Envoy's ext_authz gRPC protocol.
//
// Requests and responses are defined in the protobufs explained at:
// https://www.envoyproxy.io/docs/envoy/latest/api-v3/service/auth/v3/external_auth.proto
type GRPCAuthConfig struct {
	// AllowedRequestHeaders specifies what headers from the client request
	// will be sent to the authorization server.
	//
	// If this list is empty, then all headers must be sent.
	//
	// If the list has entries, only those entries must be sent.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxLength=64
	AllowedRequestHeaders []string `json:"allowedHeaders,omitempty"`
}

// HTTPAuthConfig contains configuration for communication with HTTP-speaking
// backends.
type HTTPAuthConfig struct {
	// Path sets the prefix that paths from the client request will have added
	// when forwarded to the authorization server.
	//
	// When empty or unspecified, no prefix is added.
	//
	// Valid values are the same as the "value" regex for path values in the `match`
	// stanza, and the validation regex will screen out invalid paths in the same way.
	// Even with the validation, implementations MUST sanitize this input before using it
	// directly.
	//
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	// +kubebuilder:validation:Pattern="^(?:[-A-Za-z0-9/._~!$&'()*+,;=:@]|[%][0-9a-fA-F]{2})+$"
	Path string `json:"path,omitempty"`

	// AllowedRequestHeaders specifies what additional headers from the client request
	// will be sent to the authorization server.
	//
	// The following headers must always be sent to the authorization server,
	// regardless of this setting:
	//
	// * `Host`
	// * `Method`
	// * `Path`
	// * `Content-Length`
	// * `Authorization`
	//
	// If this list is empty, then only those headers must be sent.
	//
	// Note that `Content-Length` has a special behavior, in that the length
	// sent must be correct for the actual request to the external authorization
	// server - that is, it must reflect the actual number of bytes sent in the
	// body of the request to the authorization server.
	//
	// So if the `forwardBody` stanza is unset, or `forwardBody.maxSize` is set
	// to `0`, then `Content-Length` must be `0`. If `forwardBody.maxSize` is set
	// to anything other than `0`, then the `Content-Length` of the authorization
	// request must be set to the actual number of bytes forwarded.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxLength=64
	AllowedRequestHeaders []string `json:"allowedHeaders,omitempty"`

	// AllowedResponseHeaders specifies what headers from the authorization response
	// will be copied into the request to the backend.
	//
	// If this list is empty, then all headers from the authorization server
	// except Authority or Host must be copied.
	//
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxLength=64
	AllowedResponseHeaders []string `json:"allowedResponseHeaders,omitempty"`
}

// ForwardBody configures if requests to the authorization server should include
// the body of the client request; and if so, how big that body is allowed
// to be.
//
// If empty or unset, do not forward the body.
type ForwardBodyConfig struct {
	// MaxSize specifies how large in bytes the largest body that will be buffered
	// and sent to the authorization server. If the body size is larger than
	// `maxSize`, then the body sent to the authorization server must be
	// truncated to `maxSize` bytes.
	//
	// Experimental note: This behavior needs to be checked against
	// various dataplanes; it may need to be changed.
	// See https://github.com/kubernetes-sigs/gateway-api/pull/4001#discussion_r2291405746
	// for more.
	//
	// If 0, the body will not be sent to the authorization server.
	// +optional
	MaxSize uint16 `json:"maxSize,omitempty"`
}

// HTTPBackendRef defines how a HTTPRoute forwards a HTTP request.
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
	// * It refers to a Kubernetes Service that has an incompatible appProtocol
	//   for the given Route type
	//
	// * The BackendTLSPolicy object is installed in the cluster, a BackendTLSPolicy
	//   is present that refers to the Service, and the implementation is unable
	//   to meet the requirement. At the time of writing, BackendTLSPolicy is
	//   experimental, but once it becomes standard, this will become a MUST
	//   requirement.
	//
	// Support: Core for Kubernetes Service
	//
	// Support: Implementation-specific for any other resource
	//
	// Support for weight: Core
	//
	// Support for Kubernetes Service appProtocol: Extended
	//
	// Support for BackendTLSPolicy: Experimental and ImplementationSpecific
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
	// +listType=atomic
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:XValidation:message="May specify either httpRouteFilterRequestRedirect or httpRouteFilterRequestRewrite, but not both",rule="!(self.exists(f, f.type == 'RequestRedirect') && self.exists(f, f.type == 'URLRewrite'))"
	// +kubebuilder:validation:XValidation:message="RequestHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'RequestHeaderModifier').size() <= 1"
	// +kubebuilder:validation:XValidation:message="ResponseHeaderModifier filter cannot be repeated",rule="self.filter(f, f.type == 'ResponseHeaderModifier').size() <= 1"
	// +kubebuilder:validation:XValidation:message="RequestRedirect filter cannot be repeated",rule="self.filter(f, f.type == 'RequestRedirect').size() <= 1"
	// +kubebuilder:validation:XValidation:message="URLRewrite filter cannot be repeated",rule="self.filter(f, f.type == 'URLRewrite').size() <= 1"
	Filters []HTTPRouteFilter `json:"filters,omitempty"`
}

// HTTPRouteStatus defines the observed state of HTTPRoute.
type HTTPRouteStatus struct {
	RouteStatus `json:",inline"`
}
