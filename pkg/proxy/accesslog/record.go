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

package accesslog

import (
	"net/http"
	"net/url"
)

// FlowType is the type to indicate the flow direction
type FlowType string

const (
	// TypeRequest is a request message
	TypeRequest FlowType = "Request"

	// TypeResponse is a response to a request
	TypeResponse FlowType = "Response"

	// TypeSample is a packet sample
	TypeSample FlowType = "Sample"
)

// FlowVerdict is the verdict passed on the flow
type FlowVerdict string

const (
	// VerdictForwarded indicates that the flow was forwarded
	VerdictForwarded FlowVerdict = "Forwarded"

	// VerdictDenied indicates that the flow was denied
	VerdictDenied = "Denied"

	// VerdictError indicates that there was an error processing the flow
	VerdictError = "Error"
)

// ObservationPoint is the type used to describe point of observation
type ObservationPoint string

const (
	// Ingress indicates event was generated at ingress
	Ingress ObservationPoint = "Ingress"

	// Egress indicates event was generated at egress
	Egress ObservationPoint = "Egress"
)

// IPVersion indicates the flow's IP version
type IPVersion uint8

const (
	// VersionIPv4 indicates IPv4
	VersionIPv4 IPVersion = iota
	// VersionIPV6 indicates IPv6
	VersionIPV6
)

// EndpointInfo contains information about the endpoint sending/receiving the flow
type EndpointInfo struct {
	ID           uint64
	IPv4         string
	IPv6         string
	Port         uint16
	Identity     uint64
	LabelsSHA256 string // hex-encoded SHA-256 signature of the labels, 64 characters in length
	Labels       []string
}

// ServiceInfo contains information about the Kubernetes service
type ServiceInfo struct {
	// Name specifies the name of the service
	Name string

	// IPPort is the IP and transport port of the service
	IPPort IPPort
}

// FlowEvent identifies the event type of an L4 log record
type FlowEvent string

const (
	// FlowAdded means that this is a new flow
	FlowAdded FlowEvent = "FlowAdded"

	// FlowRemoved means that a flow has been deleted
	FlowRemoved FlowEvent = "FlowRemoved"
)

// DropReason indicates the reason why the flow was dropped
type DropReason uint16

// TransportProtocol defines layer 4 protocols
type TransportProtocol uint16

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
// processing events or sampled packets
type LogRecord struct {
	// Type is the type of the flow
	Type FlowType

	// Timestamp is the start of a request, the end of a response, or the time the packet has been sampled,
	// depending on the flow type
	Timestamp string

	// NodeAddressInfo contains the IPs of the node where the event was generated
	NodeAddressInfo NodeAddressInfo

	// ObservationPoint indicates where the flow was observed
	ObservationPoint ObservationPoint

	// SourceEndpoint is information about the source endpoint, if available
	SourceEndpoint EndpointInfo

	// DestinationEndpoint is information about the destination endpoint, if available
	DestinationEndpoint EndpointInfo

	// IPVersion indicates the version of the IP protocol in use
	IPVersion IPVersion

	// Verdict is the verdict on the flow taken
	Verdict FlowVerdict

	// Info includes information about the rule that matched or the error
	// that occurred
	Info string

	// Metadata is additional arbitrary metadata
	Metadata []string

	// TransportProtocol identifies the flow's transport layer (layer 4) protocol
	TransportProtocol TransportProtocol

	// FlowEvent identifies the flow event for L4 log record
	FlowEvent FlowEvent

	// ServiceInfo identifies the Kubernetes service this flow went through. It is set to
	// nil if the flow did not go though any service. Note that this field is always set to
	// nil if ObservationPoint is Ingress since currently Cilium cannot tell at ingress
	// whether the packet went through a service before.
	ServiceInfo *ServiceInfo

	// DropReason indicates the reason of the drop. This field is set if and only if
	// the Verdict field is set to VerdictDenied. Otherwise it's set to nil.
	DropReason *DropReason

	// The following are the protocol specific parts. Only one of the
	// following should ever be set. Unused fields will be omitted

	// HTTP contains information for HTTP request/responses
	HTTP *LogRecordHTTP `json:"HTTP,omitempty"`

	// Kafka contains information for Kafka request/responses
	Kafka *LogRecordKafka `json:"Kafka,omitempty"`
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

	// Headers are all HTTP headers present in the request
	Headers http.Header
}

// KafkaTopic contains the topic for requests
type KafkaTopic struct {
	Topic string `json:"Topic,omitempty"`
}

// LogRecordKafka contains the Kafka-specific portion of a log record
type LogRecordKafka struct {
	// ErrorCode is the Kafka error code being returned
	ErrorCode int

	// APIVersion of the Kafka api used
	APIVersion int16

	// APIKey for Kafka message
	// Reference: https://kafka.apache.org/protocol#protocol_api_keys
	APIKey string

	// CorrelationID is a user-supplied integer value that will be passed
	// back with the response
	CorrelationID int32

	// Topic of the request, currently is a single topic
	// Note that this string can be empty since not all messages use
	// Topic. example: LeaveGroup, Heartbeat
	Topic KafkaTopic
}
