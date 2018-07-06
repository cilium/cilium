// Copyright 2018 Authors of Cilium
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

package distiller

import (
	"strconv"

	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/policy/api"
)

func getKafkaRuleApiVersion(k *api.PortRuleKafka) int32 {

	if k.APIVersion == "" {
		return -1
	}

	// Sanitization has occurred on rule at this time, so ignore errors.
	apiVersionInt64, _ := strconv.ParseInt(k.APIVersion, 10, 32)
	return int32(apiVersionInt64)
}

func getKafkaRuleRole(k *api.PortRuleKafka) []*cilium.KafkaNetworkPolicyRule {
	apiVersion := getKafkaRuleApiVersion(k)
	apiKeys, _ := k.RoleToAPIKeys()
	kafkaNetworkPolicyRules := make([]*cilium.KafkaNetworkPolicyRule, 0, len(apiKeys))

	for _, apiKey := range apiKeys {

		var topic string
		if k.Topic != "" && IsTopicAPIKey(apiKey) {
			topic = k.Topic
		}

		kafkaNetworkPolicyRule := &cilium.KafkaNetworkPolicyRule{
			ApiVersion: apiVersion,
			ApiKey:     int32(apiKey),
			Topic:      topic,
			ClientId:   k.ClientID,
		}

		kafkaNetworkPolicyRules = append(kafkaNetworkPolicyRules, kafkaNetworkPolicyRule)
	}

	return kafkaNetworkPolicyRules
}

func getKafkaRuleApiKey(k *api.PortRuleKafka) []*cilium.KafkaNetworkPolicyRule {
	var apiKey int32
	apiVersion := getKafkaRuleApiVersion(k)

	if k.APIKey == "" {
		apiKey = -1
	} else {
		// Has already been sanitized, don't need to worry if key is not in map.
		apiKey = int32(api.KafkaAPIKeyMap[k.APIKey])
	}

	var topic string
	if k.Topic != "" && IsTopicAPIKey(int16(apiKey)) {
		topic = k.Topic
	}

	kafkaNetworkPolicyRule := &cilium.KafkaNetworkPolicyRule{
		ApiVersion: apiVersion,
		ApiKey:     apiKey,
		ClientId:   k.ClientID,
		Topic:      topic,
	}

	return []*cilium.KafkaNetworkPolicyRule{kafkaNetworkPolicyRule}
}

func GetKafkaRule(k *api.PortRuleKafka) []*cilium.KafkaNetworkPolicyRule {
	// Role can be specified, or APIKey can be specified, but not both.
	// The rule is already sanitized as this point, so it is ensured that we
	// will not have both fields populated.
	if k.Role != "" {
		return getKafkaRuleRole(k)

	}
	return getKafkaRuleApiKey(k)
}

// IsTopicAPIKey returns true if kind is apiKey message type which contains a
// topic in its request.
func IsTopicAPIKey(kind int16) bool {
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
