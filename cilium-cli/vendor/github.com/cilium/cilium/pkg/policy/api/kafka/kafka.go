// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafka

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// PortRule is a list of Kafka protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule will match all
// Kafka messages.
type PortRule struct {
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
	//
	// +kubebuilder:validation:Enum=produce;consume
	// +kubebuilder:validation:Optional
	Role string `json:"role,omitempty"`

	// APIKey is a case-insensitive string matched against the key of a
	// request, e.g. "produce", "fetch", "createtopic", "deletetopic", et al
	// Reference: https://kafka.apache.org/protocol#protocol_api_keys
	//
	// If omitted or empty, and if Role is not specified, then all keys are allowed.
	//
	// +kubebuilder:validation:Optional
	APIKey string `json:"apiKey,omitempty"`

	// APIVersion is the version matched against the api version of the
	// Kafka message. If set, it has to be a string representing a positive
	// integer.
	//
	// If omitted or empty, all versions are allowed.
	//
	// +kubebuilder:validation:Optional
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
	// +kubebuilder:validation:Optional
	ClientID string `json:"clientID,omitempty"`

	// Topic is the topic name contained in the message. If a Kafka request
	// contains multiple topics, then all topics must be allowed or the
	// message will be rejected.
	//
	// This constraint is ignored if the matched request message type
	// doesn't contain any topic. Maximum size of Topic can be 249
	// characters as per recent Kafka spec and allowed characters are
	// a-z, A-Z, 0-9, -, . and _.
	//
	// Older Kafka versions had longer topic lengths of 255, but in Kafka 0.10
	// version the length was changed from 255 to 249. For compatibility
	// reasons we are using 255.
	//
	// If omitted or empty, all topics are allowed.
	//
	// +kubebuilder:validation:MaxLength=255
	// +kubebuilder:validation:Optional
	Topic string `json:"topic,omitempty"`
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

// APIKeyMap is the map of all allowed kafka API keys
// with the key values.
// Reference: https://kafka.apache.org/protocol#protocol_api_keys
var APIKeyMap = map[string]int16{
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

// ReverseApiKeyMap is the map of all allowed kafka API keys
// with the key values.
// Reference: https://kafka.apache.org/protocol#protocol_api_keys
var ReverseAPIKeyMap = map[int16]string{
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

func ApiKeyToString(apiKey int16) string {
	if key, ok := ReverseAPIKeyMap[apiKey]; ok {
		return key
	}
	return fmt.Sprintf("%d", apiKey)
}

// MaxTopicLen is the maximum character len of a topic.
// Older Kafka versions had longer topic lengths of 255, in Kafka 0.10 version
// the length was changed from 255 to 249. For compatibility reasons we are
// using 255
const (
	MaxTopicLen = 255
)

// TopicValidChar is a one-time regex generation of all allowed characters
// in kafka topic name.
var TopicValidChar = regexp.MustCompile(`^[a-zA-Z0-9\\._\\-]+$`)

// Sanitize sanitizes Kafka rules
// TODO we need to add support to check
// wildcard and prefix/suffix later on.
func (kr *PortRule) Sanitize() error {
	if (len(kr.APIKey) > 0) && (len(kr.Role) > 0) {
		return fmt.Errorf("cannot set both Role %q and APIKey %q together", kr.Role, kr.APIKey)
	}

	if len(kr.APIKey) > 0 {
		if _, ok := APIKeyMap[strings.ToLower(kr.APIKey)]; !ok {
			return fmt.Errorf("invalid Kafka APIKey %q", kr.APIKey)
		}
	}

	if len(kr.Role) > 0 {
		switch strings.ToLower(kr.Role) {
		default:
			return fmt.Errorf("invalid Kafka Role %q", kr.Role)
		case ProduceRole:
		case ConsumeRole:
		}
	}

	if len(kr.APIVersion) > 0 {
		n, err := strconv.ParseInt(kr.APIVersion, 10, 16)
		if err != nil || n < 0 || n > math.MaxInt16 {
			return fmt.Errorf("invalid Kafka APIVersion %q", kr.APIVersion)
		}
	}

	if len(kr.Topic) > 0 {
		if len(kr.Topic) > MaxTopicLen {
			return fmt.Errorf("kafka topic exceeds maximum len of %d", MaxTopicLen)
		}
		if TopicValidChar.MatchString(kr.Topic) == false {
			return fmt.Errorf("invalid Kafka Topic name %q", kr.Topic)
		}
	}
	return nil
}

// GetAPIVersion() returns the numeric API version for the PortRule
func (kr *PortRule) GetAPIVersion() int32 {
	if kr.APIVersion != "" {
		n, err := strconv.ParseInt(kr.APIVersion, 10, 16)
		if err != nil || n < 0 || n > math.MaxInt16 {
			panic(fmt.Sprintf("Unsanitized Kafka PortRule: %v", kr))
		}
		return int32(n)
	}
	return -1 // any version is allowed
}

// GetAPIKeys() returns a slice of numeric apikeys for the PortRule
func (kr *PortRule) GetAPIKeys() []int32 {
	// Expand the kr.apiKeyInt array based on the Role.
	// For produce role, we need to add mandatory apiKeys produce, metadata and
	// apiversions. While for consume, we need to add mandatory apiKeys like
	// fetch, offsets, offsetcommit, offsetfetch, apiversions, metadata,
	// findcoordinator, joingroup, heartbeat,
	// leavegroup and syncgroup.
	switch strings.ToLower(kr.Role) {
	case ProduceRole:
		return []int32{int32(ProduceKey), int32(MetadataKey), int32(APIVersionsKey)}
	case ConsumeRole:
		return []int32{int32(FetchKey), int32(OffsetsKey), int32(MetadataKey),
			int32(OffsetCommitKey), int32(OffsetFetchKey), int32(FindCoordinatorKey),
			int32(JoinGroupKey), int32(HeartbeatKey), int32(LeaveGroupKey), int32(SyncgroupKey), int32(APIVersionsKey)}
	default:
		if kr.APIKey != "" {
			if apiKey, ok := APIKeyMap[strings.ToLower(kr.APIKey)]; ok {
				return []int32{int32(apiKey)}
			}
		}
	}
	return nil
}

// Exists returns true if the Kafka rule already exists in the list of rules
func (k *PortRule) Exists(rules []PortRule) bool {
	for _, existingRule := range rules {
		if *k == existingRule {
			return true
		}
	}

	return false
}
