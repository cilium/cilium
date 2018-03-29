// Copyright 2016-2018 Authors of Cilium
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

package v2

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
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
	// rule is allowed to receive connections from. Only connections which
	// do *not* originate from the cluster or from the local host are subject
	// to CIDR rules. In order to allow in-cluster connectivity, use the
	// FromEndpoints field.  This will match on the source IP address of
	// incoming connections. Adding  a prefix into FromCIDR or into
	// FromCIDRSet with no ExcludeCIDRs is  equivalent.  Overlaps are
	// allowed between FromCIDR and FromCIDRSet.
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

// ServiceSelector is a label selector for k8s services
type ServiceSelector EndpointSelector

// Service wraps around selectors for services
type Service struct {
	// K8sServiceSelector selects services by k8s labels and namespace
	K8sServiceSelector *K8sServiceSelectorNamespace `json:"k8sServiceSelector,omitempty"`
	// K8sService selects service by name and namespace pair
	K8sService *K8sServiceNamespace `json:"k8sService,omitempty"`
}

// K8sServiceNamespace is an abstraction for the k8s service + namespace types.
type K8sServiceNamespace struct {
	ServiceName string `json:"serviceName,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

// K8sServiceSelectorNamespace wraps service selector with namespace
type K8sServiceSelectorNamespace struct {
	Selector  ServiceSelector `json:"selector"`
	Namespace string          `json:"namespace,omitempty"`
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
	// ToEndpoints is a list of endpoints identified by an EndpointSelector to
	// which the endpoints subject to the rule are allowed to communicate.
	//
	// Example:
	// Any endpoint with the label "role=frontend" can communicate with any
	// endpoint carrying the label "role=backend".
	//
	// +optional
	ToEndpoints []EndpointSelector `json:"toEndpoints,omitempty"`

	// ToRequires is a list of additional constraints which must be met
	// in order for the selected endpoints to be able to connect to other
	// endpoints. These additional constraints do no by itself grant access
	// privileges and must always be accompanied with at least one matching
	// ToEndpoints.
	//
	// Example:
	// Any Endpoint with the label "team=A" requires any endpoint to which it
	// communicates to also carry the label "team=A".
	//
	// +optional
	ToRequires []EndpointSelector `json:"toRequires,omitempty"`

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
	// is allowed to initiate connections. Only connections destined for
	// outside of the cluster and not targeting the host will be subject
	// to CIDR rules.  This will match on the destination IP address of
	// outgoing connections. Adding a prefix into ToCIDR or into ToCIDRSet
	// with no ExcludeCIDRs is equivalent. Overlaps are allowed between
	// ToCIDR and ToCIDRSet.
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

	// ToServices is a list of services to which the endpoint subject
	// to the rule is allowed to initiate connections.
	//
	// Example:
	// Any endpoint with the label "app=backend-app" is allowed to
	// initiate connections to all cidrs backing the "external-service" service
	// + optional
	ToServices []Service `json:"toServices,omitempty"`
}

// CIDR specifies a block of IP addresses.
// Example: 192.0.2.1/32
type CIDR string

// CIDRMatchAll is a []CIDR that matches everything
var CIDRMatchAll = []CIDR{CIDR("0.0.0.0/0"), CIDR("::/0")}

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

	// Generated indicates whether the rule was generated based on other rules
	// or provided by user
	Generated bool `json:"-"`
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
	// conventional "path" part of a URL as defined by RFC 3986.
	//
	// If omitted or empty, all paths are all allowed.
	//
	// +optional
	Path string `json:"path,omitempty"`

	// Method is an extended POSIX regex matched against the method of a
	// request, e.g. "GET", "POST", "PUT", "PATCH", "DELETE", ...
	//
	// If omitted or empty, all methods are allowed.
	//
	// +optional
	Method string `json:"method,omitempty"`

	// Host is an extended POSIX regex matched against the host header of a
	// request, e.g. "foo.com"
	//
	// If omitted or empty, the value of the host header is ignored.
	//
	// +optional
	Host string `json:"host,omitempty"`

	// Headers is a list of HTTP headers which must be present in the
	// request. If omitted or empty, requests are allowed regardless of
	// headers present.
	//
	// +optional
	Headers []string `json:"headers,omitempty"`
}

// PortRuleKafka is a list of Kafka protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule will match all
// Kafka messages.
type PortRuleKafka struct {
	// Role is a case-insensitive string and describes a group of API keys
	// necessary to perform certain higher-level Kafka operations such as "produce"
	// or "consume". A Role automatically expands into all APIKeys required
	// to perform the specified higher-level operation.
	//
	// The following values are supported:
	//  - "produce": Allow producing to the topics specified in the rule
	//  - "consume": Allow consuming from the topics specified in the rule
	//
	// This field is incompatible with the APIKey field, i.e APIKey and Role
	// cannot both be specified in the same rule.
	//
	// If omitted or empty, and if APIKey is not specified, then all keys are
	// allowed.

	// +optional
	Role string `json:"role,omitempty"`

	// APIKey is a case-insensitive string matched against the key of a
	// request, e.g. "produce", "fetch", "createtopic", "deletetopic", et al
	// Reference: https://kafka.apache.org/protocol#protocol_api_keys
	//
	// If omitted or empty, and if Role is not specified, then all keys are allowed.
	//
	// +optional
	APIKey string `json:"apiKey,omitempty"`

	// APIVersion is the version matched against the api version of the
	// Kafka message. If set, it has to be a string representing a positive
	// integer.
	//
	// If omitted or empty, all versions are allowed.
	//
	// +optional
	APIVersion string `json:"apiVersion,omitempty"`

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
	// If omitted or empty, all client identifiers are allowed.
	//
	// +optional
	ClientID string `json:"clientID,omitempty"`

	// Topic is the topic name contained in the message. If a Kafka request
	// contains multiple topics, then all topics must be allowed or the
	// message will be rejected.
	//
	// This constraint is ignored if the matched request message type
	// doesn't contain any topic. Maximum size of Topic can be 249
	// characters as per recent Kafka spec and allowed characters are
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

	// apiKeyInt is the integer representation of expanded Role. It is a
	// list of all low-level apiKeys to
	// be expanded as per the value of Role
	apiKeyInt KafkaRole

	// apiVersionInt is the integer representation of APIVersion
	apiVersionInt *int16
}

// List of Kafka apiKeys which have a topic in their
// request
const (
	ProduceKey              = 0
	FetchKey                = 1
	OffsetsKey              = 2
	MetadataKey             = 3
	LeaderAndIsr            = 4
	StopReplica             = 5
	UpdateMetadata          = 6
	OffsetCommitKey         = 8
	OffsetFetchKey          = 9
	FindCoordinatorKey      = 10
	JoinGroupKey            = 11
	CreateTopicsKey         = 19
	DeleteTopicsKey         = 20
	DeleteRecordsKey        = 21
	OffsetForLeaderEpochKey = 23
	AddPartitionsToTxnKey   = 24
	WriteTxnMarkersKey      = 27
	TxnOffsetCommitKey      = 28
	AlterReplicaLogDirsKey  = 34
	DescribeLogDirsKey      = 35
	CreatePartitionsKey     = 37
)

// List of Kafka apiKey which are not associated with
// any topic
const (
	HeartbeatKey   = 12
	LeaveGroupKey  = 13
	SyncgroupKey   = 14
	APIVersionsKey = 18
)

// List of Kafka Roles
const (
	ProduceRole = "produce"
	ConsumeRole = "consume"
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

// KafkaReverseApiKeyMap is the map of all allowed kafka API keys
// with the key values.
// Reference: https://kafka.apache.org/protocol#protocol_api_keys
var KafkaReverseAPIKeyMap = map[int16]string{
	0:  "produce",              /* Produce */
	1:  "fetch",                /* Fetch */
	2:  "offsets",              /* Offsets */
	3:  "metadata",             /* Metadata */
	4:  "leaderandisr",         /* LeaderAndIsr */
	5:  "stopreplica",          /* StopReplica */
	6:  "updatemetadata",       /* UpdateMetadata */
	7:  "controlledshutdown",   /* ControlledShutdown */
	8:  "offsetcommit",         /* OffsetCommit */
	9:  "offsetfetch",          /* OffsetFetch */
	10: "findcoordinator",      /* FindCoordinator */
	11: "joingroup",            /* JoinGroup */
	12: "heartbeat",            /* Heartbeat */
	13: "leavegroup",           /* LeaveGroup */
	14: "syncgroup",            /* SyncGroup */
	15: "describegroups",       /* DescribeGroups */
	16: "listgroups",           /* ListGroups */
	17: "saslhandshake",        /* SaslHandshake */
	18: "apiversions",          /* ApiVersions */
	19: "createtopics",         /* CreateTopics */
	20: "deletetopics",         /* DeleteTopics */
	21: "deleterecords",        /* DeleteRecords */
	22: "initproducerid",       /* InitProducerId */
	23: "offsetforleaderepoch", /* OffsetForLeaderEpoch */
	24: "addpartitionstotxn",   /* AddPartitionsToTxn */
	25: "addoffsetstotxn",      /* AddOffsetsToTxn */
	26: "endtxn",               /* EndTxn */
	27: "writetxnmarkers",      /* WriteTxnMarkers */
	28: "txnoffsetcommit",      /* TxnOffsetCommit */
	29: "describeacls",         /* DescribeAcls */
	30: "createacls",           /* CreateAcls */
	31: "deleteacls",           /* DeleteAcls */
	32: "describeconfigs",      /* DescribeConfigs */
	33: "alterconfigs",         /* AlterConfigs */
}

// KafkaRole is the list of all low-level apiKeys to
// be expanded as per the value of Role
type KafkaRole []int16

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

// CheckAPIKeyRole checks the apiKey value in the request, and returns true if
// it is allowed else false
func (kr *PortRuleKafka) CheckAPIKeyRole(kind int16) bool {
	// wildcard expression
	if len(kr.apiKeyInt) == 0 {
		return true
	}

	// Check kind
	for _, apiKey := range kr.apiKeyInt {
		if apiKey == kind {
			return true
		}
	}
	return false
}

// GetAPIVersion returns the APIVersion as integer or the bool set to true if
// any API version is allowed
func (kr *PortRuleKafka) GetAPIVersion() (int16, bool) {
	if kr.apiVersionInt == nil {
		return 0, true
	}

	return *kr.apiVersionInt, false
}

// MapRoleToAPIKey maps the Role to the low level set of APIKeys for that role
func (kr *PortRuleKafka) MapRoleToAPIKey() error {
	// Expand the kr.apiKeyInt array based on the Role.
	// For produce role, we need to add mandatory apiKeys produce, metadata and
	// apiversions. While for consume, we need to add mandatory apiKeys like
	// fetch, offsets, offsetcommit, offsetfetch, apiversions, metadata,
	// findcoordinator, joingroup, heartbeat,
	// leavegroup and syncgroup.
	switch strings.ToLower(kr.Role) {
	case ProduceRole:
		kr.apiKeyInt = KafkaRole{ProduceKey, MetadataKey, APIVersionsKey}
		return nil
	case ConsumeRole:
		kr.apiKeyInt = KafkaRole{FetchKey, OffsetsKey, MetadataKey,
			OffsetCommitKey, OffsetFetchKey, FindCoordinatorKey,
			JoinGroupKey, HeartbeatKey, LeaveGroupKey, SyncgroupKey, APIVersionsKey}
		return nil
	default:
		return fmt.Errorf("Invalid Kafka Role %s", kr.Role)
	}
}
