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

package echo

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// Field is a list of fields returned in responses from the Echo server.
type Field string

const (
	RequestIDField        Field = "X-Request-Id"
	ServiceVersionField   Field = "ServiceVersion"
	ServicePortField      Field = "ServicePort"
	StatusCodeField       Field = "StatusCode"
	URLField              Field = "URL"
	ForwarderURLField     Field = "Url"
	ForwarderMessageField Field = "Echo"
	ForwarderHeaderField  Field = "Header"
	HostField             Field = "Host"
	HostnameField         Field = "Hostname"
	MethodField           Field = "Method"
	ProtocolField         Field = "Proto"
	AlpnField             Field = "Alpn"
	RequestHeaderField    Field = "RequestHeader"
	ResponseHeaderField   Field = "ResponseHeader"
	ClusterField          Field = "Cluster"
	IPField               Field = "IP" // The Requester’s IP Address.
	LatencyField          Field = "Latency"
	ActiveRequestsField   Field = "ActiveRequests"
	DNSProtocolField      Field = "Protocol"
	DNSQueryField         Field = "Query"
	DNSServerField        Field = "DnsServer"
	CipherField           Field = "Cipher"
	TLSVersionField       Field = "Version"
	TLSServerName         Field = "ServerName"
)

var (
	requestIDFieldRegex      = regexp.MustCompile("(?i)" + string(RequestIDField) + "=(.*)")
	serviceVersionFieldRegex = regexp.MustCompile(string(ServiceVersionField) + "=(.*)")
	servicePortFieldRegex    = regexp.MustCompile(string(ServicePortField) + "=(.*)")
	statusCodeFieldRegex     = regexp.MustCompile(string(StatusCodeField) + "=(.*)")
	hostFieldRegex           = regexp.MustCompile(string(HostField) + "=(.*)")
	hostnameFieldRegex       = regexp.MustCompile(string(HostnameField) + "=(.*)")
	requestHeaderFieldRegex  = regexp.MustCompile(string(RequestHeaderField) + "=(.*)")
	responseHeaderFieldRegex = regexp.MustCompile(string(ResponseHeaderField) + "=(.*)")
	URLFieldRegex            = regexp.MustCompile(string(URLField) + "=(.*)")
	ClusterFieldRegex        = regexp.MustCompile(string(ClusterField) + "=(.*)")
	IPFieldRegex             = regexp.MustCompile(string(IPField) + "=(.*)")
	methodFieldRegex         = regexp.MustCompile(string(MethodField) + "=(.*)")
	protocolFieldRegex       = regexp.MustCompile(string(ProtocolField) + "=(.*)")
	alpnFieldRegex           = regexp.MustCompile(string(AlpnField) + "=(.*)")
)

// Response represents a response to a single echo request.
type Response struct {
	// RequestURL is the requested URL. This differs from URL, which is the just the path.
	// For example, RequestURL=http://foo/bar, URL=/bar
	RequestURL string
	// Method used (for HTTP).
	Method string
	// Protocol used for the request.
	Protocol string
	// Alpn value (for HTTP).
	Alpn string
	// RawContent is the original unparsed content for this response
	RawContent string
	// ID is a unique identifier of the resource in the response
	ID string
	// URL is the url the request is sent to
	URL string
	// Version is the version of the resource in the response
	Version string
	// Port is the port of the resource in the response
	Port string
	// Code is the response code
	Code string
	// Host is the host called by the request
	Host string
	// Hostname is the host that responded to the request
	Hostname string
	// The cluster where the server is deployed.
	Cluster string
	// IP is the requester's ip address
	IP string
	// rawBody gives a map of all key/values in the body of the response.
	rawBody         map[string]string
	RequestHeaders  http.Header
	ResponseHeaders http.Header
}

func ParseResponse(output string) Response {
	out := Response{
		RawContent:      output,
		RequestHeaders:  make(http.Header),
		ResponseHeaders: make(http.Header),
	}

	match := requestIDFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.ID = match[1]
	}

	match = methodFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Method = match[1]
	}

	match = protocolFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Protocol = match[1]
	}

	match = alpnFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Alpn = match[1]
	}

	match = serviceVersionFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Version = match[1]
	}

	match = servicePortFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Port = match[1]
	}

	match = statusCodeFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Code = match[1]
	}

	match = hostFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Host = match[1]
	}

	match = hostnameFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Hostname = match[1]
	}

	match = URLFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.URL = match[1]
	}

	match = ClusterFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.Cluster = match[1]
	}

	match = IPFieldRegex.FindStringSubmatch(output)
	if match != nil {
		out.IP = match[1]
	}

	out.rawBody = map[string]string{}

	matches := requestHeaderFieldRegex.FindAllStringSubmatch(output, -1)
	for _, kv := range matches {
		sl := strings.SplitN(kv[1], ":", 2)
		if len(sl) != 2 {
			continue
		}
		out.RequestHeaders.Set(sl[0], sl[1])
	}

	matches = responseHeaderFieldRegex.FindAllStringSubmatch(output, -1)
	for _, kv := range matches {
		sl := strings.SplitN(kv[1], ":", 2)
		if len(sl) != 2 {
			continue
		}
		out.ResponseHeaders.Set(sl[0], sl[1])
	}

	for _, l := range strings.Split(output, "\n") {
		prefixSplit := strings.Split(l, "body] ")
		if len(prefixSplit) != 2 {
			continue
		}
		kv := strings.SplitN(prefixSplit[1], "=", 2)
		if len(kv) != 2 {
			continue
		}
		out.rawBody[kv[0]] = kv[1]
	}

	return out
}

// HeaderType is a helper enum for retrieving Headers from a Response.
type HeaderType string

const (
	RequestHeader  HeaderType = "request"
	ResponseHeader HeaderType = "response"
)

// GetHeaders returns the appropriate headers for the given type.
func (r Response) GetHeaders(hType HeaderType) http.Header {
	switch hType {
	case RequestHeader:
		return r.RequestHeaders
	case ResponseHeader:
		return r.ResponseHeaders
	default:
		panic("invalid HeaderType enum: " + hType)
	}
}

// Body returns the lines of the response body, in order
func (r Response) Body() []string {
	type keyValue struct {
		k, v string
	}
	var keyValues []keyValue
	// rawBody is in random order, so get the order back via sorting.
	for k, v := range r.rawBody {
		keyValues = append(keyValues, keyValue{k, v})
	}
	sort.Slice(keyValues, func(i, j int) bool {
		return keyValues[i].k < keyValues[j].k
	})
	var resp []string
	for _, kv := range keyValues {
		resp = append(resp, kv.v)
	}
	return resp
}

func (r Response) String() string {
	out := ""
	out += fmt.Sprintf("RawContent:       %s\n", r.RawContent)
	out += fmt.Sprintf("ID:               %s\n", r.ID)
	out += fmt.Sprintf("Method:           %s\n", r.Method)
	out += fmt.Sprintf("Protocol:         %s\n", r.Protocol)
	out += fmt.Sprintf("Alpn:             %s\n", r.Alpn)
	out += fmt.Sprintf("URL:              %s\n", r.URL)
	out += fmt.Sprintf("Version:          %s\n", r.Version)
	out += fmt.Sprintf("Port:             %s\n", r.Port)
	out += fmt.Sprintf("Code:             %s\n", r.Code)
	out += fmt.Sprintf("Host:             %s\n", r.Host)
	out += fmt.Sprintf("Hostname:         %s\n", r.Hostname)
	out += fmt.Sprintf("Cluster:          %s\n", r.Cluster)
	out += fmt.Sprintf("IP:               %s\n", r.IP)
	out += fmt.Sprintf("Request Headers:  %v\n", r.RequestHeaders)
	out += fmt.Sprintf("Response Headers: %v\n", r.ResponseHeaders)

	return out
}
