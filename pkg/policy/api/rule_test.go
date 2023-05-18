// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"

	. "github.com/cilium/checkmate"
)

func checkMarshalUnmarshal(c *C, r *Rule) {
	jsonData, err := json.Marshal(r)
	c.Assert(err, IsNil)

	newRule := Rule{}
	err = json.Unmarshal(jsonData, &newRule)
	c.Assert(err, IsNil)

	c.Check(newRule.EndpointSelector.LabelSelector == nil, Equals, r.EndpointSelector.LabelSelector == nil)
	c.Check(newRule.NodeSelector.LabelSelector == nil, Equals, r.NodeSelector.LabelSelector == nil)
}

// This test ensures that the NodeSelector and EndpointSelector fields are kept
// empty when the rule is marshalled/unmarshalled.
func (s *PolicyAPITestSuite) TestJSONMarshalling(c *C) {
	validEndpointRule := Rule{
		EndpointSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(c, &validEndpointRule)

	validNodeRule := Rule{
		NodeSelector: WildcardEndpointSelector,
	}
	checkMarshalUnmarshal(c, &validNodeRule)
}

func getEgressRuleWithToGroups() *Rule {
	return &Rule{
		Egress: []EgressRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToGroups: []ToGroups{
						GetToGroupsRule(),
					},
				},
			},
		},
	}
}

func getEgressDenyRuleWithToGroups() *Rule {
	return &Rule{
		EgressDeny: []EgressDenyRule{
			{
				EgressCommonRule: EgressCommonRule{
					ToGroups: []ToGroups{
						GetToGroupsRule(),
					},
				},
			},
		},
	}
}

func (s *PolicyAPITestSuite) TestRequiresDerivative(c *C) {
	egressWithoutToGroups := Rule{}
	c.Assert(egressWithoutToGroups.RequiresDerivative(), Equals, false)

	egressRuleWithToGroups := getEgressRuleWithToGroups()
	c.Assert(egressRuleWithToGroups.RequiresDerivative(), Equals, true)

	egressDenyRuleWithToGroups := getEgressDenyRuleWithToGroups()
	c.Assert(egressDenyRuleWithToGroups.RequiresDerivative(), Equals, true)
}

func (s *PolicyAPITestSuite) TestCreateDerivative(c *C) {
	egressWithoutToGroups := Rule{}
	newRule, err := egressWithoutToGroups.CreateDerivative(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(len(newRule.Egress), Equals, 0)
	c.Assert(len(newRule.EgressDeny), Equals, 0)

	RegisterToGroupsProvider(AWSProvider, GetCallBackWithRule("192.168.1.1"))

	egressRuleWithToGroups := getEgressRuleWithToGroups()
	newRule, err = egressRuleWithToGroups.CreateDerivative(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(len(newRule.EgressDeny), Equals, 0)
	c.Assert(len(newRule.Egress), Equals, 1)
	c.Assert(len(newRule.Egress[0].ToCIDRSet), Equals, 1)

	egressDenyRuleWithToGroups := getEgressDenyRuleWithToGroups()
	newRule, err = egressDenyRuleWithToGroups.CreateDerivative(context.TODO())
	c.Assert(err, IsNil)
	c.Assert(len(newRule.Egress), Equals, 0)
	c.Assert(len(newRule.EgressDeny), Equals, 1)
	c.Assert(len(newRule.EgressDeny[0].ToCIDRSet), Equals, 1)
}
