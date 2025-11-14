// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

// TestRulesDeepEqual tests that individual rules (via Rule.DeepEqual()) and
// a collection of rules (via Rules.DeepEqual()) correctly validates the
// equality of the rule or rules.
func TestRulesDeepEqual(t *testing.T) {
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

func TestRuleMarshalling(t *testing.T) {
	// EndpointSelector marshalling unit test covers more specific scenarios.
	// Check selector_test.go
	testSelectors := map[string]struct {
		jsonStr       string
		expected      EndpointSelector
		sanitized     EndpointSelector
		sanitizedJSON string
	}{
		"empty": {
			jsonStr: `{}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{},
			},
			sanitized: EndpointSelector{
				LabelSelector:             &slim_metav1.LabelSelector{},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{},MatchExpressions:[]LabelSelectorRequirement{},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedJSON: `{}`,
		},
		"matchLabels": {
			jsonStr: `{"matchLabels":{"app":"frontend"}}`,
			expected: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"app": "frontend"},
				},
			},
			sanitized: EndpointSelector{
				LabelSelector: &slim_metav1.LabelSelector{
					MatchLabels: map[string]string{"any.app": "frontend"},
				},
				cachedLabelSelectorString: "&LabelSelector{MatchLabels:map[string]string{any.app: frontend,},MatchExpressions:[]LabelSelectorRequirement{},}",
				Generated:                 false,
				sanitized:                 true,
			},
			sanitizedJSON: `{"matchLabels":{"any:app":"frontend"}}`,
		},
	}

	dummyRule := struct {
		jsonStr       string
		expected      []IngressRule
		sanitized     []IngressRule
		sanitizedJSON string
	}{
		jsonStr: `[{"fromEndpoints":[{}]}]`,
		expected: []IngressRule{{IngressCommonRule: IngressCommonRule{
			FromEndpoints: []EndpointSelector{testSelectors["empty"].expected},
		}}},
		sanitized: []IngressRule{{IngressCommonRule: IngressCommonRule{
			FromEndpoints: []EndpointSelector{testSelectors["empty"].sanitized},
		}}},
		sanitizedJSON: `[{"fromEndpoints":[{}]}]`,
	}
	enableDefaultDenySanitized := `"enableDefaultDeny":{"ingress":true,"egress":false}`

	defaultDenyEnabled := func(ret bool) *bool { return &ret }
	defaultDenyConfig := DefaultDenyConfig{
		Egress:  defaultDenyEnabled(false),
		Ingress: defaultDenyEnabled(true),
	}

	type errorType int
	const (
		noError errorType = iota
		inputUnmarshalError
		sanitizeError
	)

	tests := []struct {
		name                string
		inputJSON           string
		expected            Rule
		sanitizedExepected  Rule
		sanitizedOutputJSON string
		expectedErr         errorType
	}{
		{
			name:                "Empty JSON",
			inputJSON:           `{}`,
			expected:            Rule{},
			sanitizedExepected:  Rule{},
			sanitizedOutputJSON: `{}`,
			expectedErr:         sanitizeError,
		},
		{
			name:                "Invalid JSON",
			inputJSON:           `{"endpointSelector"`,
			expected:            Rule{},
			sanitizedExepected:  Rule{},
			sanitizedOutputJSON: `{}`,
			expectedErr:         inputUnmarshalError,
		},
		{
			name:      "With valid EndpointSelector and no Rules",
			inputJSON: fmt.Sprintf(`{"endpointSelector":%s}`, testSelectors["empty"].jsonStr),
			expected: Rule{
				EndpointSelector: testSelectors["empty"].expected,
			},
			sanitizedExepected:  Rule{},
			sanitizedOutputJSON: `{}`,
			expectedErr:         sanitizeError,
		},
		{
			name:      "With empty EndpointSelector and no NodeSelector",
			inputJSON: fmt.Sprintf(`{"endpointSelector":%s,"ingress":%s}`, testSelectors["empty"].jsonStr, dummyRule.jsonStr),
			expected: Rule{
				EndpointSelector: testSelectors["empty"].expected,
				Ingress:          dummyRule.expected,
			},
			sanitizedExepected: Rule{
				EndpointSelector:  testSelectors["empty"].sanitized,
				Ingress:           dummyRule.sanitized,
				EnableDefaultDeny: defaultDenyConfig,
			},
			sanitizedOutputJSON: fmt.Sprintf(
				`{"endpointSelector":%s,"ingress":%s,%s}`,
				testSelectors["empty"].sanitizedJSON, dummyRule.sanitizedJSON, enableDefaultDenySanitized,
			),
			expectedErr: noError,
		},
		{
			name:      "With empty NodeSelector and no EndpointSelector",
			inputJSON: fmt.Sprintf(`{"nodeSelector":%s,"ingress":%s}`, testSelectors["empty"].jsonStr, dummyRule.jsonStr),
			expected: Rule{
				NodeSelector: testSelectors["empty"].expected,
				Ingress:      dummyRule.expected,
			},
			sanitizedExepected: Rule{
				NodeSelector:      testSelectors["empty"].sanitized,
				Ingress:           dummyRule.sanitized,
				EnableDefaultDeny: defaultDenyConfig,
			},
			sanitizedOutputJSON: fmt.Sprintf(`{"nodeSelector":%s,"ingress":%s,%s}`, testSelectors["empty"].sanitizedJSON, dummyRule.sanitizedJSON, enableDefaultDenySanitized),
			expectedErr:         noError,
		},
		{
			name: "With empty EndpointSelector and NodeSelector",
			inputJSON: fmt.Sprintf(
				`{"endpointSelector":%s,"nodeSelector":%s,"ingress":%s}`,
				testSelectors["empty"].jsonStr,
				testSelectors["empty"].jsonStr,
				dummyRule.jsonStr,
			),
			expected: Rule{
				EndpointSelector: testSelectors["empty"].expected,
				NodeSelector:     testSelectors["empty"].expected,
				Ingress:          dummyRule.expected,
			},
			sanitizedExepected:  Rule{},
			sanitizedOutputJSON: `{}`,
			expectedErr:         sanitizeError,
		},
		{
			name:      "With matchLabels EndpointSelector",
			inputJSON: fmt.Sprintf(`{"endpointSelector":%s,"ingress":%s}`, testSelectors["matchLabels"].jsonStr, dummyRule.jsonStr),
			expected: Rule{
				EndpointSelector: testSelectors["matchLabels"].expected,
				Ingress:          dummyRule.expected,
			},
			sanitizedExepected: Rule{
				EndpointSelector:  testSelectors["matchLabels"].sanitized,
				Ingress:           dummyRule.sanitized,
				EnableDefaultDeny: defaultDenyConfig,
			},
			sanitizedOutputJSON: fmt.Sprintf(
				`{"endpointSelector":%s,"ingress":%s,%s}`,
				testSelectors["matchLabels"].sanitizedJSON, dummyRule.sanitizedJSON, enableDefaultDenySanitized,
			),
			expectedErr: noError,
		},
		{
			name:      "With matchLabels NodeSelector",
			inputJSON: fmt.Sprintf(`{"nodeSelector":%s,"ingress":%s}`, testSelectors["matchLabels"].jsonStr, dummyRule.jsonStr),
			expected: Rule{
				NodeSelector: testSelectors["matchLabels"].expected,
				Ingress:      dummyRule.expected,
			},
			sanitizedExepected: Rule{
				NodeSelector:      testSelectors["matchLabels"].sanitized,
				Ingress:           dummyRule.sanitized,
				EnableDefaultDeny: defaultDenyConfig,
			},
			sanitizedOutputJSON: fmt.Sprintf(
				`{"nodeSelector":%s,"ingress":%s,%s}`,
				testSelectors["matchLabels"].sanitizedJSON, dummyRule.sanitizedJSON, enableDefaultDenySanitized,
			),
			expectedErr: noError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := Rule{}

			err := json.Unmarshal([]byte(tt.inputJSON), &rule)
			if tt.expectedErr == inputUnmarshalError {
				require.ErrorContains(t, err, "unexpected end of JSON input")
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected, rule, "UnMarshalled Rule")

			ruleMarshalled, err := json.Marshal(&rule)
			require.NoError(t, err)
			require.Equalf(t, tt.inputJSON, string(ruleMarshalled), "Marshalled Rule")

			err = rule.Sanitize()
			if tt.expectedErr == sanitizeError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.sanitizedExepected, rule, "Sanitized Rule")

			ruleSanitizedMarshalled, err := json.Marshal(&rule)
			require.NoError(t, err)
			require.Equalf(t, tt.sanitizedOutputJSON, string(ruleSanitizedMarshalled), "Marshalled Sanitized Rule")
		})
	}
}
