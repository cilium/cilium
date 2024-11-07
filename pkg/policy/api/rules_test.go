// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestRulesDeepEqual tests that individual rules (via Rule.DeepEqual()) and
// a collection of rules (via Rules.DeepEqual()) correctly validates the
// equality of the rule or rules.
func TestRulesDeepEqual(t *testing.T) {
	setUpSuite(t)

	var invalidRules *Rules

	require.True(t, invalidRules.DeepEqual(nil))
	require.True(t, invalidRules.DeepEqual(invalidRules))

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

	require.False(t, invalidRules.DeepEqual(&validPortRules))
	require.False(t, validPortRules.DeepEqual(invalidRules))
	require.False(t, validPortRules.DeepEqual(nil))
	require.True(t, validPortRules.DeepEqual(&validPortRules))

	// Same as WildcardEndpointSelector, but different pointer.
	wcSelector2 := NewESFromLabels()
	validPortRulesClone := Rules{
		validPortRules[0].DeepCopy(),
	}
	validPortRulesClone[0].EndpointSelector = wcSelector2

	require.True(t, validPortRules.DeepEqual(&validPortRulesClone))
}
