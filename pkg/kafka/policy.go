// Copyright 2017 Authors of Cilium
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

package kafka

import (
	"github.com/cilium/cilium/pkg/flowdebug"
	"github.com/cilium/cilium/pkg/policy/api/v2"

	"github.com/optiopay/kafka/proto"
	"github.com/sirupsen/logrus"
)

// isTopicAPIKey returns true if kind is apiKey message type which contains a
// topic in its request.
func isTopicAPIKey(kind int16) bool {
	switch kind {
	case v2.ProduceKey,
		v2.FetchKey,
		v2.OffsetsKey,
		v2.MetadataKey,
		v2.LeaderAndIsr,
		v2.StopReplica,
		v2.UpdateMetadata,
		v2.OffsetCommitKey,
		v2.OffsetFetchKey,
		v2.CreateTopicsKey,
		v2.DeleteTopicsKey,
		v2.DeleteRecordsKey,
		v2.OffsetForLeaderEpochKey,
		v2.AddPartitionsToTxnKey,
		v2.WriteTxnMarkersKey,
		v2.TxnOffsetCommitKey,
		v2.AlterReplicaLogDirsKey,
		v2.DescribeLogDirsKey,
		v2.CreatePartitionsKey:

		return true
	}
	return false
}

func matchNonTopicRequests(req *RequestMessage, rule v2.PortRuleKafka) bool {
	// matchNonTopicRequests() is called when
	// the kafka parser was not able to parse beyond the generic header.
	// This could be due to 2 sceanrios:
	// 1. It was a non-topic request
	// 2. The parser could not parse further even if there was a topic present.
	// For scenario 2, if topic is present, we need to return
	// false since topic can never be associated with this request kind.
	if rule.Topic != "" && isTopicAPIKey(req.kind) {
		return false
	}
	// TODO add functionality for parsing clientID GH-3097
	//if rule.ClientID != "" && rule.ClientID != req.GetClientID() {
	//	return false
	//}
	return true
}
func produceTopicContained(neededTopic string, topics []proto.ProduceReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchProduceReq(req *proto.ProduceReq, rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !produceTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func fetchTopicContained(neededTopic string, topics []proto.FetchReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchFetchReq(req *proto.FetchReq, rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !fetchTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func offsetTopicContained(neededTopic string, topics []proto.OffsetReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchOffsetReq(req *proto.OffsetReq, rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !offsetTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func topicContained(neededTopic string, topics []string) bool {
	for _, topic := range topics {
		if topic == neededTopic {
			return true
		}
	}

	return false
}

func matchMetadataReq(req *proto.MetadataReq, rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !topicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func offsetCommitTopicContained(neededTopic string, topics []proto.OffsetCommitReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchOffsetCommitReq(req *proto.OffsetCommitReq, rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !offsetCommitTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func offsetFetchTopicContained(neededTopic string, topics []proto.OffsetFetchReqTopic) bool {
	for _, topic := range topics {
		if topic.Name == neededTopic {
			return true
		}
	}

	return false
}

func matchOffsetFetchReq(req *proto.OffsetFetchReq, rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.Topic != "" && !offsetFetchTopicContained(rule.Topic, req.Topics) {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func (req *RequestMessage) ruleMatches(rule v2.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	flowdebug.Log(log.WithFields(logrus.Fields{
		fieldRequest: req.String(),
		fieldRule:    rule,
	}), "Matching Kafka rule")

	if !rule.CheckAPIKeyRole(req.kind) {
		return false
	}

	apiVersion, isWildcard := rule.GetAPIVersion()
	if !isWildcard && apiVersion != req.version {
		return false
	}

	// If the rule contains no additional conditionals, it is not required
	// to match into the request specific fields.
	if rule.Topic == "" && rule.ClientID == "" {
		return true
	}

	switch val := req.request.(type) {
	case *proto.ProduceReq:
		return matchProduceReq(val, rule)
	case *proto.FetchReq:
		return matchFetchReq(val, rule)
	case *proto.OffsetReq:
		return matchOffsetReq(val, rule)
	case *proto.MetadataReq:
		return matchMetadataReq(val, rule)
	case *proto.OffsetCommitReq:
		return matchOffsetCommitReq(val, rule)
	case *proto.OffsetFetchReq:
		return matchOffsetFetchReq(val, rule)
	case *proto.ConsumerMetadataReq:
		return true
	case nil:
		// This is the case when requests like
		// heartbeat,findcordinator, et al
		// are specified. They are not
		// associated with a topic, but we should
		// still check for ClientID present in request header.
		return matchNonTopicRequests(req, rule)
	default:
		// If all conditions have been met, allow the request
		return true
	}
}

// MatchesRule validates the Kafka request message against the provided list of
// rules. The function will return true if the policy allows the message,
// otherwise false is returned.
func (req *RequestMessage) MatchesRule(rules []v2.PortRuleKafka) bool {
	for _, rule := range rules {
		if req.ruleMatches(rule) {
			return true
		}
	}

	return false
}
