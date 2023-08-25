// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	. "github.com/cilium/checkmate"
)

// TestRulesDeepEqual tests that individual rules (via Rule.DeepEqual()) and
// a collection of rules (via Rules.DeepEqual()) correctly validates the
// equality of the rule or rules.
func (s *PolicyAPITestSuite) TestRulesDeepEqual(c *C) {
	var invalidRules *Rules

	c.Assert(invalidRules.DeepEqual(nil), Equals, true)
	c.Assert(invalidRules.DeepEqual(invalidRules), Equals, true)

	wcSelector1 := WildcardEndpointSelector
	validPortRules := Rules{
		NewRule().WithEndpointSelector(wcSelector1).
			WithIngressRules([]IngressRule{{
				IngressCommonRule: IngressCommonRule{
					FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
				},
				ToPorts: []PortRule{{
					Ports: []PortProtocol{
						{Port: "80", Protocol: ProtoTCP},
						{Port: "81", Protocol: ProtoTCP},
					},
					Rules: &L7Rules{
						HTTP: []PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			}}),
	}

	c.Assert(invalidRules.DeepEqual(&validPortRules), Equals, false)
	c.Assert(validPortRules.DeepEqual(invalidRules), Equals, false)
	c.Assert(validPortRules.DeepEqual(nil), Equals, false)
	c.Assert(validPortRules.DeepEqual(&validPortRules), Equals, true)

	// Same as WildcardEndpointSelector, but different pointer.
	wcSelector2 := NewESFromLabels()
	validPortRulesClone := Rules{
		validPortRules[0].DeepCopy(),
	}
	validPortRulesClone[0].EndpointSelector = wcSelector2

	c.Assert(validPortRules.DeepEqual(&validPortRulesClone), Equals, true)
}
