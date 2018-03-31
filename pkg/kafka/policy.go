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
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/optiopay/kafka/proto"
	"github.com/sirupsen/logrus"
)

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

func matchNonTopicRequests(req *RequestMessage, rule api.PortRuleKafka) bool {
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

func matchProduceReq(req *proto.ProduceReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchFetchReq(req *proto.FetchReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchOffsetReq(req *proto.OffsetReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchMetadataReq(req *proto.MetadataReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchOffsetCommitReq(req *proto.OffsetCommitReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func matchOffsetFetchReq(req *proto.OffsetFetchReq, rule api.PortRuleKafka) bool {
	if req == nil {
		return false
	}

	if rule.ClientID != "" && rule.ClientID != req.ClientID {
		return false
	}

	return true
}

func (req *RequestMessage) ruleMatches(rule api.PortRuleKafka) bool {
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
func (req *RequestMessage) MatchesRule(rules []api.PortRuleKafka) bool {
	topics := req.GetTopics()
	// Maintain a map of all topics in the request.
	// We should allow the request only if all topics are
	// allowed by the list of rules.
	reqTopicsMap := make(map[string]bool, len(topics))
	for _, topic := range topics {
		reqTopicsMap[topic] = true
	}

	for _, rule := range rules {
		if rule.Topic == "" || len(topics) == 0 {
			if req.ruleMatches(rule) {
				return true
			}
		} else if reqTopicsMap[rule.Topic] {
			if req.ruleMatches(rule) {
				delete(reqTopicsMap, rule.Topic)
				if len(reqTopicsMap) == 0 {
					return true
				}
			}
		}
	}
	return false
}
