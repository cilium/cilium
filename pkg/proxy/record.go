// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxy

import (
	"net/http"
	"net/url"
)

// FlowDirection is the type to indicate the flow direction
type FlowDirection string

const (
	// TypeRequest is a request message
	TypeRequest = "Request"

	// TypeResponse is a response to a request
	TypeResponse = "Response"
)

// FlowVerdict is the verdict taken on request/response
type FlowVerdict string

const (
	// VerdictForwared indicates that the request/response was forwarded
	VerdictForwared FlowVerdict = "Forwarded"

	// VerdictDenied indicates that the request/response was denied
	VerdictDenied = "Denied"

	// VerdictError indicates that there was an error processing the request/response
	VerdictError = "Error"
)

// ObservationPoint is the type used to describe point of observation
type ObservationPoint string

const (
	// Ingress indicates event was generated at ingress
	Ingress ObservationPoint = "Ingress"

	// Egress indicates event was generated at egress
	Egress = "Egress"
)

// EndpointInfo contains information about the endpoint sending/receiving the
// request/response
type EndpointInfo struct {
	ID       uint64
	IPv4     string
	IPv6     string
	Identity uint64
	Labels   []string
}

// NodeAddressInfo holds addressing information of the node the agent runs on
type NodeAddressInfo struct {
	IPv4 string
	IPv6 string
}

// IPPort bundles an IP address and port number
type IPPort struct {
	IP   string
	Port uint16
}

// LogRecord is the structure used to log individual request/response
// processing events
type LogRecord struct {
	// Direction is the direction of the flow
	Direction FlowDirection

	// Timestamp is the start of a request and then end of a response
	Timestamp string

	// NodeAddressInfo contains the IPs of the node where the event was generated
	NodeAddressInfo NodeAddressInfo

	// ObservationPoint indicates where the request/response was observed
	ObservationPoint ObservationPoint

	// SourceEndpoint is information about the soure endpoint if available
	SourceEndpoint EndpointInfo `json:"SourceEndpoint,omitempty"`

	// DestinationEndpoint is information about the soure endpoint if available
	DestinationEndpoint EndpointInfo `json:"DestinationEndpoint,omitempty"`

	// Source is the IP and port of the endpoint that generated the
	// request
	Source IPPort

	// Destination is the IP and port of the endpoint that is receiving the
	// request
	Destination IPPort

	// Verdict is the verdict on the flow taken
	Verdict FlowVerdict

	// Info includes information about the rule that matched or the error
	// that occurred. This is informational.
	Info string

	// Metadata is additional arbitrary metadata
	Metadata []string

	// The following are the protocol specific parts. Only one of the
	// following should ever be set. Unused fields will be omitted

	// HTTP contains information for HTTP request/responses
	HTTP LogRecordHTTP `json:"HTTP,omitempty"`

	// internal
	request http.Request
}

// LogRecordHTTP contains the HTTP specific portion of a log record
type LogRecordHTTP struct {
	// Code is the HTTP code being returned
	Code int

	// Method is the method of the request
	Method string

	// URL is the URL of the request
	URL *url.URL

	// Protocol is the HTTP protocol in use
	Protocol string

	// Header is the HTTP header in use
	Header http.Header
}
