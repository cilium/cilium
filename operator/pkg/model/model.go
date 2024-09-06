// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package model

import (
	"sort"
	"strconv"
	"strings"
	"time"
)

// Model holds an abstracted data model representing the translation
// of various types of Kubernetes config to Cilium config.
type Model struct {
	HTTP           []HTTPListener
	TLSPassthrough []TLSPassthroughListener
}

func (m *Model) GetListeners() []Listener {
	var listeners []Listener

	for i := range m.HTTP {
		listeners = append(listeners, &m.HTTP[i])
	}

	for i := range m.TLSPassthrough {
		listeners = append(listeners, &m.TLSPassthrough[i])
	}

	return listeners
}

type Listener interface {
	GetSources() []FullyQualifiedResource
	GetPort() uint32
	GetAnnotations() map[string]string
	GetLabels() map[string]string
}

// HTTPListener holds configuration for any listener that terminates and proxies HTTP
// including HTTP and HTTPS.
// Each holds the configuration info for one distinct HTTP listener, by
//   - Hostname
//   - TLS
//   - Address
//   - Port
type HTTPListener struct {
	// Name of the HTTPListener
	Name string
	// Sources is a slice of fully qualified resources this HTTPListener is sourced
	// from.
	Sources []FullyQualifiedResource
	// IPAddress that the listener should listen on.
	// The string must be parseable as an IP address.
	Address string
	// Port on which the service can be expected to be accessed by clients.
	Port uint32
	// Hostname that the listener should match.
	// Wildcards are supported in prefix or suffix forms, or the special wildcard `*`.
	// An empty list means that the Listener should match all hostnames.
	Hostname string
	// TLS Certificate information. If omitted, then the listener is a cleartext HTTP listener.
	TLS []TLSSecret
	// Routes associated with HTTP traffic to the service.
	// An empty list means that traffic will not be routed.
	Routes []HTTPRoute
	// Service configuration
	Service *Service
	// Infrastructure configuration
	Infrastructure *Infrastructure
	// ForceHTTPtoHTTPSRedirect enforces that, for HTTPListeners that have a
	// TLS field set and create a HTTPS listener, an equivalent plaintext HTTP
	// listener will be created that redirects requests from HTTP to HTTPS.
	//
	// This plaintext listener will override any other plaintext HTTP config in
	// the final rendered Envoy Config.
	ForceHTTPtoHTTPSRedirect bool
}

func (l HTTPListener) GetSources() []FullyQualifiedResource {
	return l.Sources
}

func (l HTTPListener) GetPort() uint32 {
	return l.Port
}

func (l HTTPListener) GetAnnotations() map[string]string {
	if l.Infrastructure != nil {
		return l.Infrastructure.Annotations
	}
	return nil
}

func (l HTTPListener) GetLabels() map[string]string {
	if l.Infrastructure != nil {
		return l.Infrastructure.Labels
	}
	return nil
}

// TLSPassthroughListener holds configuration for any listener that proxies TLS
// based on the SNI value.
// Each holds the configuration info for one distinct TLS listener, by
//   - Hostname
//   - Address
//   - Port
type TLSPassthroughListener struct {
	// Name of the TLSListener
	Name string
	// Sources is a slice of fully qualified resources this TLSListener is sourced
	// from.
	Sources []FullyQualifiedResource
	// IPAddress that the listener should listen on.
	// The string must be parseable as an IP address.
	Address string
	// Port on which the service can be expected to be accessed by clients.
	Port uint32
	// Hostname that the listener should match.
	// Wildcards are supported in prefix or suffix forms, or the special wildcard `*`.
	// An empty list means that the Listener should match all hostnames.
	Hostname string
	// Routes associated with traffic to the service.
	// An empty list means that traffic will not be routed.
	Routes []TLSPassthroughRoute
	// Service configuration
	Service *Service
	// Infrastructure configuration
	Infrastructure *Infrastructure
}

func (l TLSPassthroughListener) GetAnnotations() map[string]string {
	if l.Infrastructure != nil {
		return l.Infrastructure.Annotations
	}
	return nil
}

func (l TLSPassthroughListener) GetLabels() map[string]string {
	if l.Infrastructure != nil {
		return l.Infrastructure.Labels
	}
	return nil
}

func (l TLSPassthroughListener) GetSources() []FullyQualifiedResource {
	return l.Sources
}

func (l TLSPassthroughListener) GetPort() uint32 {
	return l.Port
}

// Service holds the configuration for desired Service details
type Service struct {
	// Type is the type of service that is being used for Listener (e.g. Load Balancer or Node port)
	// Defaults to Load Balancer type
	Type string
	// InsecureNodePort is the back-end port of the service that is being used for HTTP Listener
	// Applicable only if Type is Node NodePort
	InsecureNodePort *uint32
	// SecureNodePort is the back-end port of the service that is being used for HTTPS Listener
	// Applicable only if Type is Node NodePort
	SecureNodePort *uint32
}

// FullyQualifiedResource stores the full details of a Kubernetes resource, including
// the Group, Version, and Kind.
// Namespace must be set to the empty string for cluster-scoped resources.
type FullyQualifiedResource struct {
	Name      string
	Namespace string
	Group     string
	Version   string
	Kind      string
	UID       string
}

// TLSSecret holds a reference to a secret containing a TLS keypair.
type TLSSecret struct {
	Name      string
	Namespace string
}

// DirectResponse holds configuration for a direct response.
type DirectResponse struct {
	StatusCode int
	Body       string
}

// Header is a key-value pair.
type Header struct {
	Name  string
	Value string
}

// HTTPHeaderFilter holds configuration for a request header filter.
type HTTPHeaderFilter struct {
	// HeadersToAdd is a list of headers to add to the request.
	// Existing headers with the same name will be appended to.
	HeadersToAdd []Header
	// HeadersToSet is a list of headers to set in the request.
	// Existing headers will be overwritten.
	HeadersToSet []Header
	// HeadersToRemove is a list of headers to remove from the request.
	HeadersToRemove []string
}

// HTTPRequestRedirectFilter holds configuration for a request redirect.
type HTTPRequestRedirectFilter struct {
	// Scheme is the scheme to be used in the value of the `Location` header in
	// the response. When empty, the scheme of the request is used.
	Scheme *string

	// Hostname is the hostname to be used in the value of the `Location`
	// header in the response.
	// When empty, the hostname of the request is used.
	Hostname *string

	// Path defines parameters used to modify the path of the incoming request.
	// The modified path is then used to construct the `Location` header. When
	// empty, the request path is used as-is.
	Path *StringMatch

	// Port is the port to be used in the value of the `Location`
	// header in the response.
	// When empty, port (if specified) of the request is used.
	Port *int32

	// StatusCode is the HTTP status code to be used in response.
	//
	// Note that values may be added to this enum, implementations
	// must ensure that unknown values will not cause a crash.
	StatusCode *int
}

// HTTPURLRewriteFilter defines a filter that modifies a request during
// forwarding. At most one of these filters may be used on a Route rule. This
// MUST NOT be used on the same Route rule as a HTTPRequestRedirect filter.
type HTTPURLRewriteFilter struct {
	// Hostname is the value to be used to replace the Host header value during
	// forwarding.
	HostName *string

	// Path is the values to be used to replace the path
	Path *StringMatch
}

// HTTPRequestMirror defines configuration for the RequestMirror filter.
type HTTPRequestMirror struct {
	// Backend is the backend handling the requests
	Backend *Backend

	Numerator   int32
	Denominator int32
}

// HTTPRoute holds all the details needed to route HTTP traffic to a backend.
type HTTPRoute struct {
	Name string
	// Hostnames that the route should match
	Hostnames []string
	// PathMatch specifies that the HTTPRoute should match a path.
	PathMatch StringMatch
	// HeadersMatch specifies that the HTTPRoute should match a set of headers.
	HeadersMatch []KeyValueMatch
	// QueryParamsMatch specifies that the HTTPRoute should match a set of query parameters.
	QueryParamsMatch []KeyValueMatch
	Method           *string
	// Backend is the backend handling the requests
	Backends []Backend
	// BackendHTTPFilters can be used to add or remove HTTP
	BackendHTTPFilters []*BackendHTTPFilter
	// DirectResponse instructs the proxy to respond directly to the client.
	DirectResponse *DirectResponse

	// RequestHeaderFilter can be used to add or remove an HTTP
	// header from an HTTP request before it is sent to the upstream target.
	RequestHeaderFilter *HTTPHeaderFilter

	// ResponseHeaderModifier can be used to add or remove an HTTP
	// header from an HTTP response before it is sent to the client.
	ResponseHeaderModifier *HTTPHeaderFilter

	// RequestRedirect defines a schema for a filter that responds to the
	// request with an HTTP redirection.
	RequestRedirect *HTTPRequestRedirectFilter

	// Rewrite defines a schema for a filter that modifies the URL of the request.
	Rewrite *HTTPURLRewriteFilter

	// RequestMirrors defines a schema for a filter that mirrors HTTP requests
	// Unlike other filter, multiple request mirrors are supported
	RequestMirrors []*HTTPRequestMirror

	// IsGRPC is an indicator if this route is related to GRPC
	IsGRPC bool

	// Timeout holds the timeout configuration for a route.
	Timeout Timeout

	// Retry holds the retry configuration for a route.
	Retry *HTTPRetry
}

type BackendHTTPFilter struct {
	// Name is the name of the Backend, the name is having the format of "namespace:name:port"
	Name string
	// RequestHeaderFilter can be used to add or remove an HTTP
	// header from an HTTP request before it is sent to the upstream target.
	RequestHeaderFilter *HTTPHeaderFilter

	// ResponseHeaderModifier can be used to add or remove an HTTP
	// header from an HTTP response before it is sent to the client.
	ResponseHeaderModifier *HTTPHeaderFilter
}

// Infrastructure holds the labels and annotations configuration,
// which will be propagated to LB service.
type Infrastructure struct {
	// Labels is a map of labels to be propagated to LB service.
	Labels map[string]string

	// Annotations is a map of annotations to be propagated to LB service.
	Annotations map[string]string
}

// GetMatchKey returns the key to be used for matching the backend.
func (r *HTTPRoute) GetMatchKey() string {
	sb := strings.Builder{}

	if r.Method != nil {
		sb.WriteString("method:")
		sb.WriteString(*r.Method)
		sb.WriteString("|")
	}

	sb.WriteString("path:")
	sb.WriteString(r.PathMatch.String())
	sb.WriteString("|")

	sort.Slice(r.HeadersMatch, func(i, j int) bool {
		return r.HeadersMatch[i].String() < r.HeadersMatch[j].String()
	})
	for _, hm := range r.HeadersMatch {
		sb.WriteString("header:")
		sb.WriteString(hm.String())
		sb.WriteString("|")
	}

	sort.Slice(r.QueryParamsMatch, func(i, j int) bool {
		return r.QueryParamsMatch[i].String() < r.QueryParamsMatch[j].String()
	})
	for _, qm := range r.QueryParamsMatch {
		sb.WriteString("query:")
		sb.WriteString(qm.String())
		sb.WriteString("|")
	}

	return sb.String()
}

// TLSPassthroughRoute holds all the details needed to route TLS traffic to a backend.
type TLSPassthroughRoute struct {
	Name string
	// Hostnames that the route should match
	Hostnames []string
	// Backend is the backend handling the requests
	Backends []Backend
}

// StringMatch describes various types of string matching.
// Only one field may be set.
// If no fields are set, all paths should match (no path match criteria should
// be generated for Envoy.)
type StringMatch struct {
	Prefix string
	Exact  string
	Regex  string
}

func (sm StringMatch) String() string {
	sb := strings.Builder{}
	if sm.Prefix != "" {
		sb.WriteString("prefix:")
		sb.WriteString(sm.Prefix)
	} else if sm.Exact != "" {
		sb.WriteString("exact:")
		sb.WriteString(sm.Exact)
	} else if sm.Regex != "" {
		sb.WriteString("regex:")
		sb.WriteString(sm.Regex)
	}
	return sb.String()
}

type KeyValueMatch struct {
	Key   string
	Match StringMatch
}

func (kv KeyValueMatch) String() string {
	sb := strings.Builder{}
	sb.WriteString("kv:")
	sb.WriteString(kv.Key)
	sb.WriteString(":")
	sb.WriteString(kv.Match.String())
	return sb.String()
}

// Backend holds a Kubernetes Service that points to a backend for traffic.
type Backend struct {
	// Name of the Service.
	Name string
	// Namespace of the Service.
	Namespace string
	// Port contains the details of the port on the Service to connect to
	// If unset, the same port as the top-level Listener will be used.
	Port *BackendPort
	// AppProtocol contains the application protocol as per KEP-3726
	// for the port of the Service.
	AppProtocol *string

	// Weight specifies the percentage of traffic to send to this backend.
	// This is computed as weight/(sum of all weights in backends) * 100.
	Weight *int32
}

// BackendPort holds the details of what port on the Service to connect to.
// Only one of Port or Name can be set.
type BackendPort struct {
	// Port holds the numeric port to connect to.
	Port uint32
	// Name holds a string which will be used to connect to the port with a
	// matching spec.ports[].name in the target Service.
	Name string
}

// GetPort return the string representation of the port (either the port number or the port name)
func (be *BackendPort) GetPort() string {
	if be.Port != 0 {
		return strconv.Itoa(int(be.Port))
	}
	return be.Name
}

// Timeout holds the timeout configuration for a route.
type Timeout struct {
	// Request is the timeout for the request.
	Request *time.Duration
	// Backend is the timeout for the backend.
	Backend *time.Duration
}

// HTTPRetry holds the retry configuration for a route.
type HTTPRetry struct {
	// Codes defines the HTTP response status codes for which a backend request
	// should be retried.
	Codes []uint32

	// Attempts specifies the maximum number of times an individual request
	// from the gateway to a backend should be retried.
	Attempts *int

	// Backoff specifies the minimum duration a Gateway should wait between
	// retry attempts
	Backoff *time.Duration
}
