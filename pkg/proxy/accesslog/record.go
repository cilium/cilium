// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package accesslog

import (
	"net"
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

	// VerdictError indicates that the flow was redirected through the proxy
	VerdictRedirected = "Redirected"
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

// EndpointInfo contains information about the sending (resp. receiving) endpoint.
// If the field using this struct is SourceEndpoint, all fields correspond to
// the sending endpoint, if the field using this struct is DestinationEndpoint,
// then all fields correspond to the receiving endpoint.
type EndpointInfo struct {
	// ID is the endpoint id
	ID uint64

	// IPv4 is the IPv4 address of the endpoint
	IPv4 string

	// IPv6 is the IPv6 address of the endpoint
	IPv6 string

	// Port represents the source point for SourceEndpoint and the
	// destination port for DestinationEndpoint
	Port uint16

	// Identity is the security identity of the endpoint
	Identity uint64

	// Labels is the list of security relevant labels of the endpoint
	Labels []string
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

	// DNS contains information for DNS request/responses
	DNS *LogRecordDNS `json:"DNS,omitempty"`

	// L7 contains information about generic L7 protocols
	L7 *LogRecordL7 `json:"L7,omitempty"`
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

	// Headers are all HTTP headers present in the request and response. Request records
	// contain request headers, while response headers contain response headers and the
	// 'x-request-id' from the request headers, if any. If response headers already contain
	// a 'x-request-id' with a different value then both will be included as two separate
	// entries with the same key.
	Headers http.Header

	// MissingHeaders are HTTP request headers that were deemed missing from the request
	MissingHeaders http.Header

	// RejectedHeaders are HTTP request headers that were rejected from the request
	RejectedHeaders http.Header
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

type DNSDataSource string

const (
	// DNSSourceProxy indicates that the DNS record was created by a proxy
	// intercepting a DNS request/response.
	DNSSourceProxy DNSDataSource = "proxy"
)

// LogRecordDNS contains the DNS specific portion of a log record
type LogRecordDNS struct {
	// Query is the name in the original query
	Query string `json:"Query,omitempty"`

	// IPs are any IPs seen in this response.
	// This field is filled only for DNS responses with IPs.
	IPs []net.IP `json:"IPs,omitempty"`

	// TTL is the lowest applicable TTL for this data
	// This field is filled only for DNS responses.
	TTL uint32 `json:"TTL,omitempty"`

	// CNAMEs are any CNAME records seen in the response leading from Query
	// to the IPs.
	// This field is filled only for DNS responses with CNAMEs to IP data.
	CNAMEs []string `json:"CNAMEs,omitempty"`

	// ObservationSource represents the source of the data in this LogRecordDNS.
	// Empty or undefined may indicate older cilium versions, as it is expected
	// to be filled in.
	ObservationSource DNSDataSource `json:"ObservationSource,omitempty"`

	// RCode is the response code
	// defined as per https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
	// Use 	github.com/cilium/dns.RcodeToString map to retrieve string representation
	RCode int `json:"RCode,omitempty"`

	// QTypes are question types in DNS message
	// https://www.ietf.org/rfc/rfc1035.txt
	// Use github.com/cilium/dns.TypeToString map to retrieve string representation
	QTypes []uint16 `json:"QTypes,omitempty"`

	// AnswerTypes are record types in the answer section
	// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
	// Use github.com/cilium/dns.TypeToString map to retrieve string representation
	AnswerTypes []uint16 `json:"AnswerTypes,omitempty"`
}

// LogRecordL7 contains the generic L7 portion of a log record
type LogRecordL7 struct {
	// Proto is the name of the protocol this record represents
	Proto string `json:"Proto,omitempty"`

	// Fields is a map of key-value pairs describing the protocol
	Fields map[string]string
}
