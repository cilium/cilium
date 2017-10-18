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

package api

import (
	"github.com/cilium/cilium/pkg/labels"

	"regexp"
)

// Rule is a policy rule which must be applied to all endpoints which match the
// labels contained in the endpointSelector
//
// Each rule is split into an ingress section which contains all rules
// applicable at ingress, and an egress section applicable at egress. For rule
// types such as `L4Rule` and `CIDR` which can be applied at both ingress and
// egress, both ingress and egress side have to either specifically allow the
// connection or one side has to be omitted.
//
// Either ingress, egress, or both can be provided. If both ingress and egress
// are omitted, the rule has no effect.
type Rule struct {
	// EndpointSelector selects all endpoints which should be subject to
	// this rule. Cannot be empty.
	EndpointSelector EndpointSelector `json:"endpointSelector"`

	// Ingress is a list of IngressRule which are enforced at ingress.
	// If omitted or empty, this rule does not apply at ingress.
	//
	// +optional
	Ingress []IngressRule `json:"ingress,omitempty"`

	// Egress is a list of EgressRule which are enforced at egress.
	// If omitted or empty, this rule does not apply at egress.
	//
	// +optional
	Egress []EgressRule `json:"egress,omitempty"`

	// Labels is a list of optional strings which can be used to
	// re-identify the rule or to store metadata. It is possible to lookup
	// or delete strings based on labels. Labels are not required to be
	// unique, multiple rules can have overlapping or identical labels.
	//
	// +optional
	Labels labels.LabelArray `json:"labels,omitempty"`

	// Description is a free form string, it can be used by the creator of
	// the rule to store human readable explanation of the purpose of this
	// rule. Rules cannot be identified by comment.
	//
	// +optional
	Description string `json:"description,omitempty"`
}

// Entity specifies the class of receiver/sender endpoints that do not have individual identities.
// Entities are used to describe "outside of cluster", "host", etc.
type Entity string

const (
	// EntityWorld is an entity that represents traffic external to endpoint's cluster
	EntityWorld Entity = "world"
	// EntityHost is an entity that represents traffic within endpoint host
	EntityHost Entity = "host"
)

// EntitySelectorMapping maps special entity names that come in policies to selectors
var EntitySelectorMapping = map[Entity]EndpointSelector{
	EntityWorld: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameWorld,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
	EntityHost: NewESFromLabels(&labels.Label{
		Key:    labels.IDNameHost,
		Value:  "",
		Source: labels.LabelSourceReserved,
	}),
}

// IngressRule contains all rule types which can be applied at ingress,
// i.e. network traffic that originates outside of the endpoint and
// is entering the endpoint selected by the endpointSelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
//
// - If multiple members are set, all of them need to match in order for
//   the rule to take effect. The exception to this rule is FromRequires field;
//   the effects of any Requires field in any rule will apply to all other
//   rules as well.
//
// - For now, combining ToPorts, FromCIDR, and FromEndpoints in the same rule
//   is not supported and any such rules will be rejected. In the future, this
//   will be supported and if multiple members of this structure are specified,
//   then all members must match in order for the rule to take effect. The
//   exception to this rule is the Requires field, the effects of any Requires
//   field in any rule will apply to all other rules as well.
type IngressRule struct {
	// FromEndpoints is a list of endpoints identified by an
	// EndpointSelector which are allowed to communicate with the endpoint
	// subject to the rule.
	//
	// Example:
	// Any endpoint with the label "role=backend" can be consumed by any
	// endpoint carrying the label "role=frontend".
	//
	// +optional
	FromEndpoints []EndpointSelector `json:"fromEndpoints,omitempty"`

	// FromRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be reachable. These
	// additional constraints do no by itself grant access privileges and
	// must always be accompanied with at least one matching FromEndpoints.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires consuming endpoint
	// to also carry the label "team=A".
	//
	// +optional
	FromRequires []EndpointSelector `json:"fromRequires,omitempty"`

	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// receive connections on.
	//
	// Example:
	// Any endpoint with the label "app=httpd" can only accept incoming
	// connections on port 80/tcp.
	//
	// +optional
	ToPorts []PortRule `json:"toPorts,omitempty"`

	// FromCIDR is a list of IP blocks which the endpoint subject to the
	// rule is allowed to receive connections from. This will match on
	// the source IP address of incoming connections. Adding  a prefix into
	// FromCIDR or into FromCIDRSet with no ExcludeCIDRs is  equivalent.
	// Overlaps are allowed between FromCIDR and FromCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=my-legacy-pet" is allowed to receive
	// connections from 10.3.9.1
	//
	// +optional
	FromCIDR []CIDR `json:"fromCIDR,omitempty"`

	// FromCIDRSet is a list of IP blocks which the endpoint subject to the
	// rule is allowed to receive connections from in addition to FromEndpoints,
	// along with a list of subnets contained within their corresponding IP block
	// from which traffic should not be allowed.
	// This will match on the source IP address of incoming connections. Adding
	// a prefix into FromCIDR or into FromCIDRSet with no ExcludeCIDRs is
	// equivalent. Overlaps are allowed between FromCIDR and FromCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=my-legacy-pet" is allowed to receive
	// connections from 10.0.0.0/8 except from IPs in subnet 10.96.0.0/12.
	//
	// +optional
	FromCIDRSet []CIDRRule `json:"fromCIDRSet,omitempty"`

	// FromEntities is a list of special entities which the endpoint subject
	// to the rule is allowed to receive connections from. Supported entities are
	// `world` and `host`
	//
	// +optional
	FromEntities []Entity `json:"fromEntities,omitempty"`
}

// EgressRule contains all rule types which can be applied at egress, i.e.
// network traffic that originates inside the endpoint and exits the endpoint
// selected by the endpointSelector.
//
// - All members of this structure are optional. If omitted or empty, the
//   member will have no effect on the rule.
//
// - For now, combining ToPorts and ToCIDR in the same rule is not supported
//   and such rules will be rejected. In the future, this will be supported and
//   if if multiple members of the structure are specified, then all members
//   must match in order for the rule to take effect.
type EgressRule struct {
	// ToPorts is a list of destination ports identified by port number and
	// protocol which the endpoint subject to the rule is allowed to
	// connect to.
	//
	// Example:
	// Any endpoint with the label "role=frontend" is allowed to initiate
	// connections to destination port 8080/tcp
	//
	// +optional
	ToPorts []PortRule `json:"toPorts,omitempty"`

	// ToCIDR is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections. This will match on the
	// destination IP address of outgoing connections. Adding a prefix into
	// ToCIDR or into ToCIDRSet with no ExcludeCIDRs is equivalent. Overlaps
	// are allowed between ToCIDR and ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24
	//
	// +optional
	ToCIDR []CIDR `json:"toCIDR,omitempty"`

	// ToCIDRSet is a list of IP blocks which the endpoint subject to the rule
	// is allowed to initiate connections to in addition to connections
	// which are allowed via FromEndpoints, along with a list of subnets contained
	// within their corresponding IP block to which traffic should not be
	// allowed. This will match on the destination IP address of outgoing
	// connections. Adding a prefix into ToCIDR or into ToCIDRSet with no
	// ExcludeCIDRs is equivalent. Overlaps are allowed between ToCIDR and
	// ToCIDRSet.
	//
	// Example:
	// Any endpoint with the label "app=database-proxy" is allowed to
	// initiate connections to 10.2.3.0/24 except from IPs in subnet 10.2.3.0/28.
	//
	// +optional
	ToCIDRSet []CIDRRule `json:"toCIDRSet,omitempty"`

	// ToEntities is a list of special entities to which the endpoint subject
	// to the rule is allowed to initiate connections. Supported entities are
	// `world` and `host`
	//
	// +optional
	ToEntities []Entity `json:"toEntities,omitempty"`
}

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
type CIDR string

// L4Proto is a layer 4 protocol name
type L4Proto string

const (
	ProtoTCP L4Proto = "TCP"
	ProtoUDP L4Proto = "UDP"
	ProtoAny L4Proto = "ANY"
)

// PortProtocol specifies an L4 port with an optional transport protocol
type PortProtocol struct {
	// Port is an L4 port number. For now the string will be strictly
	// parsed as a single uint16. In the future, this field may support
	// ranges in the form "1024-2048
	Port string `json:"port"`

	// Protocol is the L4 protocol. If omitted or empty, any protocol
	// matches. Accepted values: "TCP", "UDP", ""/"ANY"
	//
	// Matching on ICMP is not supported.
	//
	// +optional
	Protocol L4Proto `json:"protocol,omitempty"`
}

// PortRule is a list of ports/protocol combinations with optional Layer 7
// rules which must be met.
type PortRule struct {
	// Ports is a list of L4 port/protocol
	//
	// If omitted or empty but RedirectPort is set, then all ports of the
	// endpoint subject to either the ingress or egress rule are being
	// redirected.
	//
	// +optional
	Ports []PortProtocol `json:"ports,omitempty"`

	// RedirectPort is the L4 port which, if set, all traffic matching the
	// Ports is being redirected to. Whatever listener behind that port
	// becomes responsible to enforce the port rules and is also
	// responsible to reinject all traffic back and ensure it reaches its
	// original destination.
	RedirectPort int `json:"redirectPort,omitempty"`

	// Rules is a list of additional port level rules which must be met in
	// order for the PortRule to allow the traffic. If omitted or empty,
	// no layer 7 rules are enforced.
	//
	// +optional
	Rules *L7Rules `json:"rules,omitempty"`
}

// CIDRRule is a rule that specifies a CIDR prefix to/from which outside
// communication  is allowed, along with an optional list of subnets within that
// CIDR prefix to/from which outside communication is not allowed.
type CIDRRule struct {
	// CIDR is a CIDR prefix / IP Block.
	//
	Cidr CIDR `json:"cidr"`

	// ExceptCIDRs is a list of IP blocks which the endpoint subject to the rule
	// is not allowed to initiate connections to. These CIDR prefixes should be
	// contained within Cidr. These exceptions are only applied to the Cidr in
	// this CIDRRule, and do not apply to any other CIDR prefixes in any other
	// CIDRRules.
	//
	// +optional
	ExceptCIDRs []CIDR `json:"except,omitempty"`
}

// L7Rules is a union of port level rule types. Mixing of different port
// level rule types is disallowed, so exactly one of the following must be set.
// If none are specified, then no additional port level rules are applied.
type L7Rules struct {
	// HTTP specific rules.
	//
	// +optional
	HTTP []PortRuleHTTP `json:"http,omitempty"`

	// Kafka-specific rules.
	//
	// +optional
	Kafka []PortRuleKafka `json:"kafka,omitempty"`
}

// PortRuleHTTP is a list of HTTP protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule does not have any
// effect.
//
// All fields of this type are extended POSIX regex as defined by IEEE Std
// 1003.1, (i.e this follows the egrep/unix syntax, not the perl syntax)
// matched against the path of an incoming request. Currently it can contain
// characters disallowed from the conventional "path" part of a URL as defined
// by RFC 3986.
type PortRuleHTTP struct {
	// Path is an extended POSIX regex matched against the path of a
	// request. Currently it can contain characters disallowed from the
	// conventional "path" part of a URL as defined by RFC 3986. Paths must
	// begin with a '/'.
	//
	// If omitted or empty, all paths are all allowed.
	//
	// +optional
	Path string `json:"path,omitempty" protobuf:"bytes,1,opt,name=path"`

	// Method is an extended POSIX regex matched against the method of a
	// request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...
	//
	// If omitted or empty, all methods are allowed.
	//
	// +optional
	Method string `json:"method,omitempty" protobuf:"bytes,1,opt,name=method"`

	// Host is an extended POSIX regex matched against the host header of a
	// request, e.g. "foo.com"
	//
	// If omitted or empty, the value of the host header is ignored.
	//
	// +optional
	Host string `json:"host,omitempty" protobuf:"bytes,1,opt,name=method"`

	// Headers is a list of HTTP headers which must be present in the
	// request. If omitted or empty, requests are allowed regardless of
	// headers present.
	//
	// +optional
	Headers []string `json:"headers,omitempty"`
}

// PortRuleKafka is a list of Kafka protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule does not have any
// effect.
type PortRuleKafka struct {
	// APIVersion is the version matched against the api version of the
	// Kafka message. If set, it has to be a string representing a positive
	// integer.
	//
	// If omitted or empty, all versions are allowed.
	//
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`

	// APIKey is a case-insensitive string matched against the key of a
	// request, e.g. "produce", "fetch", "createtopic", "deletetopic", et al
	// Reference: https://kafka.apache.org/protocol#protocol_api_keys
	//
	// If omitted or empty, all keys are allowed.
	//
	// +optional
	APIKey string `json:"apiKey,omitempty"`

	// ClientID is the client identifier as provided in the request.
	//
	// From Kafka protocol documentation:
	// This is a user supplied identifier for the client application. The
	// user can use any identifier they like and it will be used when
	// logging errors, monitoring aggregates, etc. For example, one might
	// want to monitor not just the requests per second overall, but the
	// number coming from each client application (each of which could
	// reside on multiple servers). This id acts as a logical grouping
	// across all requests from a particular client.
	//
	// If omitempty or empty, all client identifiers are allowed.
	//
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// Topic is a regex matched against the topic of the
	// Kafka message. Ignored if the matched request message type doesn't
	// contain any topic. Maximum size of Topic can be 249 characters as
	// per recent Kafka spec and allowed characters are
	// a-z, A-Z, 0-9, -, . and _
	// Older Kafka versions had longer topic lengths of 255, but in Kafka 0.10
	// version the length was changed from 255 to 249. For compatibility
	// reasons we are using 255
	//
	// If omitted or empty, all topics are allowed.
	//
	// +optional
	Topic string `json:"topic,omitempty"`

	// --------------------------------------------------------------------
	// Private fields. These fields are used internally and are not exposed
	// via the API.

	// apiKeyInt is the integer representation of APIKey
	apiKeyInt int16

	// apiVersionInt is the integer representation of APIVersion
	apiVersionInt int16
}

const (
	apiKeyWildcard     int16 = -1
	apiVersionWildcard int16 = -1
)

// KafkaAPIKeyMap is the map of all allowed kafka API keys
// with the key values.
// Reference: https://kafka.apache.org/protocol#protocol_api_keys
var KafkaAPIKeyMap = map[string]int16{
	"produce":              0,  /* Produce */
	"fetch":                1,  /* Fetch */
	"offsets":              2,  /* Offsets */
	"metadata":             3,  /* Metadata */
	"leaderandisr":         4,  /* LeaderAndIsr */
	"stopreplica":          5,  /* StopReplica */
	"updatemetadata":       6,  /* UpdateMetadata */
	"controlledshutdown":   7,  /* ControlledShutdown */
	"offsetcommit":         8,  /* OffsetCommit */
	"offsetfetch":          9,  /* OffsetFetch */
	"findcoordinator":      10, /* FindCoordinator */
	"joingroup":            11, /* JoinGroup */
	"heartbeat":            12, /* Heartbeat */
	"leavegroup":           13, /* LeaveGroup */
	"syncgroup":            14, /* SyncGroup */
	"describegroups":       15, /* DescribeGroups */
	"listgroups":           16, /* ListGroups */
	"saslhandshake":        17, /* SaslHandshake */
	"apiversions":          18, /* ApiVersions */
	"createtopics":         19, /* CreateTopics */
	"deletetopics":         20, /* DeleteTopics */
	"deleterecords":        21, /* DeleteRecords */
	"initproducerid":       22, /* InitProducerId */
	"offsetforleaderepoch": 23, /* OffsetForLeaderEpoch */
	"addpartitionstotxn":   24, /* AddPartitionsToTxn */
	"addoffsetstotxn":      25, /* AddOffsetsToTxn */
	"endtxn":               26, /* EndTxn */
	"writetxnmarkers":      27, /* WriteTxnMarkers */
	"txnoffsetcommit":      28, /* TxnOffsetCommit */
	"describeacls":         29, /* DescribeAcls */
	"createacls":           30, /* CreateAcls */
	"deleteacls":           31, /* DeleteAcls */
	"describeconfigs":      32, /* DescribeConfigs */
	"alterconfigs":         33, /* AlterConfigs */
}

// KafkaMaxTopicLen is the maximum character len of a topic.
// Older Kafka versions had longer topic lengths of 255, in Kafka 0.10 version
// the length was changed from 255 to 249. For compatibility reasons we are
// using 255
const (
	KafkaMaxTopicLen = 255
)

// KafkaTopicValidChar is a one-time regex generation of all allowed characters
// in kafka topic name.
var KafkaTopicValidChar = regexp.MustCompile(`^[a-zA-Z0-9\\._\\-]+$`)

// GetAPIKey returns the APIKey as integer or the bool set to true if any API
// key is allowed
func (kr *PortRuleKafka) GetAPIKey() (int16, bool) {
	if kr.apiKeyInt == apiKeyWildcard {
		return 0, true
	}

	return kr.apiKeyInt, false
}

// GetAPIVersion returns the APIVersion as integer or the bool set to true if
// any API version is allowed
func (kr *PortRuleKafka) GetAPIVersion() (int16, bool) {
	if kr.apiVersionInt == apiVersionWildcard {
		return 0, true
	}

	return kr.apiVersionInt, false
}
