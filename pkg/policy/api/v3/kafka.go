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

package v3

import (
	"fmt"
	"regexp"
	"strings"
)

// PortRuleKafka is a list of Kafka protocol constraints. All fields are
// optional, if all fields are empty or missing, the rule will match all
// Kafka messages.
type PortRuleKafka struct {
	// Role is a case-insensitive string and describes a group of API keys
	// necessary to perform certain higher level Kafka operations such as "produce"
	// or "consume". An APIGroup automatically expands into all APIKeys required
	// to perform the specified higher level operation.
	//
	// The following values are supported:
	//  - "produce": Allow producing to the topics specified in the rule
	//  - "consume": Allow consuming from the topics specified in the rule
	//
	// This field is incompatible with the APIKey field, either APIKey or Role
	// may be specified.
	//
	// If omitted or empty, the field has no effect and the logic of the APIKey
	// field applies.
	//
	// +optional
	Role string `json:"role,omitempty"`

	// APIKey is a case-insensitive string matched against the key of a
	// request, e.g. "produce", "fetch", "createtopic", "deletetopic", et al
	// Reference: https://kafka.apache.org/protocol#protocol_api_keys
	//
	// If omitted or empty, all keys are allowed.
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
	// via the

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
