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
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/envoy/cilium"
	"github.com/cilium/cilium/pkg/policy/api"
	. "gopkg.in/check.v1"
)

func (ds *ResolverTestSuite) TestGetKafkaRuleApiVersion(c *C) {
	rule := &api.PortRuleKafka{
		APIKey:     "metadata",
		APIVersion: "0",
		ClientID:   "",
		Topic:      "foo",
	}

	apiVersion := getKafkaRuleApiVersion(rule)
	c.Assert(apiVersion, Equals, int32(0))

	// Empty APIVersion maps to a negative number.
	rule = &api.PortRuleKafka{
		APIKey:   "metadata",
		ClientID: "",
		Topic:    "foo",
	}

	apiVersion = getKafkaRuleApiVersion(rule)
	c.Assert(apiVersion, Equals, int32(-1))
}

func (ds *ResolverTestSuite) TestKafkaRuleRole(c *C) {
	rule := &api.PortRuleKafka{
		Role:       api.ProduceRole,
		APIVersion: "0",
		ClientID:   "",
		Topic:      "foo",
	}
	rules := getKafkaRuleRole(rule)
	kafkaNetworkPolicyRules := []*cilium.KafkaNetworkPolicyRule{
		{
			ApiVersion: 0,
			ApiKey:     api.ProduceKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.MetadataKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.APIVersionsKey,
			ClientId:   "",
			Topic:      "",
		},
	}

	c.Assert(rules, comparator.DeepEquals, kafkaNetworkPolicyRules)

	rule = &api.PortRuleKafka{
		Role:       api.ConsumeRole,
		APIVersion: "0",
		ClientID:   "",
		Topic:      "foo",
	}
	rules = getKafkaRuleRole(rule)
	kafkaNetworkPolicyRules = []*cilium.KafkaNetworkPolicyRule{
		{
			ApiVersion: 0,
			ApiKey:     api.FetchKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.OffsetsKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.MetadataKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.OffsetCommitKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.OffsetFetchKey,
			ClientId:   "",
			Topic:      "foo",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.FindCoordinatorKey,
			ClientId:   "",
			Topic:      "",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.JoinGroupKey,
			ClientId:   "",
			Topic:      "",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.HeartbeatKey,
			ClientId:   "",
			Topic:      "",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.LeaveGroupKey,
			ClientId:   "",
			Topic:      "",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.SyncgroupKey,
			ClientId:   "",
			Topic:      "",
		},
		{
			ApiVersion: 0,
			ApiKey:     api.APIVersionsKey,
			ClientId:   "",
			Topic:      "",
		},
	}
	c.Assert(rules, comparator.DeepEquals, kafkaNetworkPolicyRules)

}

func (ds *ResolverTestSuite) GetKafkaRuleAPIKey(c *C) {
	rule := &api.PortRuleKafka{
		APIKey:     "metadata",
		APIVersion: "0",
		ClientID:   "",
		Topic:      "foo",
	}

	rules := getKafkaRuleApiKey(rule)

	kafkaNetworkPolicyRules := []*cilium.KafkaNetworkPolicyRule{
		{
			ApiVersion: 0,
			ApiKey:     3,
			ClientId:   "",
			Topic:      "foo",
		},
	}

	c.Assert(rules, comparator.DeepEquals, kafkaNetworkPolicyRules)

	rule = &api.PortRuleKafka{
		APIKey:   "metadata",
		ClientID: "",
		Topic:    "foo",
	}

	rules = getKafkaRuleApiKey(rule)

	kafkaNetworkPolicyRules = []*cilium.KafkaNetworkPolicyRule{
		{
			ApiVersion: -1,
			ApiKey:     3,
			ClientId:   "",
			Topic:      "foo",
		},
	}

	c.Assert(rules, comparator.DeepEquals, kafkaNetworkPolicyRules)
}
