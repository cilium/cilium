// Copyright 2019 Authors of Cilium
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

// +build !privileged_tests

package api

import (
	. "gopkg.in/check.v1"
)

// TestRulesDeepEquals tests that individual rules (via Rule.DeepEquals()) and
// a collection of rules (via Rules.DeepEquals()) correctly validates the
// equality of the rule or rules.
func (s *PolicyAPITestSuite) TestRulesDeepEquals(c *C) {
	var invalidRules Rules

	c.Assert(invalidRules.DeepEquals(nil), Equals, true)
	c.Assert(invalidRules.DeepEquals(invalidRules), Equals, true)

	wcSelector1 := WildcardEndpointSelector
	validPortRules := Rules{
		NewRule().WithEndpointSelector(wcSelector1).
			WithIngressRules([]IngressRule{{
				FromEndpoints: []EndpointSelector{WildcardEndpointSelector},
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

	c.Assert(invalidRules.DeepEquals(validPortRules), Equals, false)
	c.Assert(validPortRules.DeepEquals(invalidRules), Equals, false)
	c.Assert(validPortRules.DeepEquals(nil), Equals, false)
	c.Assert(validPortRules.DeepEquals(validPortRules), Equals, true)

	// Same as WildcardEndpointSelector, but different pointer.
	wcSelector2 := NewESFromLabels()
	validPortRulesClone := Rules{
		validPortRules[0].DeepCopy(),
	}
	validPortRulesClone[0].EndpointSelector = wcSelector2

	c.Assert(validPortRules.DeepEquals(validPortRulesClone), Equals, true)
}
