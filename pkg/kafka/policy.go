// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kafka

import (
	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/flowdebug"
	api "github.com/cilium/cilium/pkg/policy/api/kafka"
)

type Rule struct {
	// ApiVersion is the allowed version, or < 0 if all versions
	// are to be allowed
	APIVersion int16

	// ApiKeys is the set of all numerical apiKeys that are allowed.
	// If empty, all API keys are allowed.
	APIKeys map[int16]struct{}

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
	// If empty, all client identifiers are allowed.
	ClientID string

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
	// reasons we are allowing 255.
	//
	// If empty, all topics are allowed.
	Topic string
}

// NewRule creates a new rule from already sanitized inputs
func NewRule(apiVersion int32, apiKeys []int32, clientID, topic string) Rule {
	r := Rule{
		APIVersion: int16(apiVersion),
		ClientID:   clientID,
		Topic:      topic,
		APIKeys:    make(map[int16]struct{}, len(apiKeys)),
	}
	for _, key := range apiKeys {
		r.APIKeys[int16(key)] = struct{}{}
	}
	return r
}

// CheckAPIKeyRole checks the apiKey value in the request, and returns true if
// it is allowed else false
func (r *Rule) CheckAPIKeyRole(kind int16) bool {
	// wildcard expression
	if len(r.APIKeys) == 0 {
		return true
	}

	// Check kind
	_, ok := r.APIKeys[kind]
	return ok
}

// CheckAPIVersion returns true if 'apiVersion' is allowed
func (r *Rule) CheckAPIVersion(apiVersion int16) bool {
	return r.APIVersion < 0 || apiVersion == r.APIVersion
}

// CheckClientID returns true if 'clientID' is allowed
func (r *Rule) CheckClientID(clientID string) bool {
	return r.ClientID == "" || clientID == r.ClientID
}

// isTopicAPIKey returns true if kind is apiKey message type which contains a
// topic in its request.
func isTopicAPIKey(kind int16) bool {
	switch kind {
	case api.ProduceKey,
		api.FetchKey,
		api.OffsetsKey,
		api.MetadataKey,
		api.LeaderAndIsr,
		api.StopReplica,
		api.UpdateMetadata,
		api.OffsetCommitKey,
		api.OffsetFetchKey,
		api.CreateTopicsKey,
		api.DeleteTopicsKey,
		api.DeleteRecordsKey,
		api.OffsetForLeaderEpochKey,
		api.AddPartitionsToTxnKey,
		api.WriteTxnMarkersKey,
		api.TxnOffsetCommitKey,
		api.AlterReplicaLogDirsKey,
		api.DescribeLogDirsKey,
		api.CreatePartitionsKey:

		return true
	}
	return false
}

// Matches returns true if Rule matches the request and and all required topics have matched.
func (r Rule) Matches(data interface{}) bool {
	req, ok := data.(*RequestMessage)
	if !ok {
		logrus.Warningf("Matches() called with type other than Kafka RequestMessage: %v", data)
		return false
	}

	if flowdebug.Enabled() {
		logrus.Debugf("Matching Kafka request %s against rule %v", req.String(), r)
	}

	if !r.CheckAPIKeyRole(req.kind) {
		return false
	}

	if !r.CheckAPIVersion(req.version) {
		return false
	}

	if !r.CheckClientID(req.clientID) {
		return false
	}

	// Last step, check topic if applicable.
	// Rule without a topic allows all topics and request types without topics
	// are allowed regardless the rule's topic.
	if r.Topic != "" && isTopicAPIKey(req.kind) {
		// Rule has a topic constraint and the request type carries topics.
		//
		// Check it this rule's topic is in the request, but keep matching
		// other rules (by returning false) even if this rule is satisfied
		// if there are other topics in the request not matched yet.
		//
		// (req.topics is initialized with all the topics in the request
		// before any rules are matched.)
		if _, exists := req.topics[r.Topic]; exists {
			delete(req.topics, r.Topic)
			if len(req.topics) == 0 {
				return true // all topics have matched
			}
		}
		return false // more topic matches needed
	}

	// All rule's constraints are satisfied
	return true
}
