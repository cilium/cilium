// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestIngressRequiresDerivativeRuleWithoutToGroups(t *testing.T) {
	ig := IngressRule{}
	require.False(t, ig.RequiresDerivative())
}

func TestRequiresDerivativeRuleWithFromGroups(t *testing.T) {
	ig := IngressRule{}
	ig.FromGroups = []Groups{
		GetGroupsRule(),
	}
	require.True(t, ig.RequiresDerivative())
}

func TestCreateDerivativeRuleWithoutFromGroups(t *testing.T) {
	ig := &IngressRule{
		IngressCommonRule: IngressCommonRule{
			FromEndpoints: []EndpointSelector{
				{
					LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{
						"test": "true",
					},
					},
				},
			},
		},
	}
	newRule, err := ig.CreateDerivative(context.TODO())
	require.Equal(t, newRule, ig)
	require.NoError(t, err)
}

func TestCreateDerivativeRuleWithFromGroups(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	ig := &IngressRule{
		IngressCommonRule: IngressCommonRule{
			FromGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	require.True(t, ig.RequiresDerivative())

	newRule, err := ig.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.FromGroups)
	require.Len(t, newRule.FromCIDRSet, 1)
}

func TestIngressCommonRuleDeepEqual(t *testing.T) {
	testCases := []struct {
		name      string
		in, other *IngressCommonRule
		expected  bool
	}{
		{
			name:     "All fields are nil in both",
			in:       &IngressCommonRule{},
			other:    &IngressCommonRule{},
			expected: true,
		},
		{
			name: "All fields are empty in both",
			in: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
				FromCIDR:      []CIDR{},
				FromCIDRSet:   []CIDRRule{},
				FromEntities:  []Entity{},
			},
			other: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
				FromCIDR:      []CIDR{},
				FromCIDRSet:   []CIDRRule{},
				FromEntities:  []Entity{},
			},
			expected: true,
		},
		{
			name: "FromEndpoints is nil in left operand",
			in: &IngressCommonRule{
				FromEndpoints: nil,
			},
			other: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
			},
			expected: false,
		},
		{
			name: "FromEndpoints is empty in left operand",
			in: &IngressCommonRule{
				FromEndpoints: []EndpointSelector{},
			},
			other: &IngressCommonRule{
				FromEndpoints: nil,
			},
			expected: false,
		},
		{
			name: "FromCIDR is nil in left operand",
			in: &IngressCommonRule{
				FromCIDR: nil,
			},
			other: &IngressCommonRule{
				FromCIDR: []CIDR{},
			},
			expected: false,
		},
		{
			name: "FromCIDR is empty in left operand",
			in: &IngressCommonRule{
				FromCIDR: []CIDR{},
			},
			other: &IngressCommonRule{
				FromCIDR: nil,
			},
			expected: false,
		},
		{
			name: "FromCIDRSet is nil in left operand",
			in: &IngressCommonRule{
				FromCIDRSet: nil,
			},
			other: &IngressCommonRule{
				FromCIDRSet: []CIDRRule{},
			},
			expected: false,
		},
		{
			name: "FromCIDRSet is empty in left operand",
			in: &IngressCommonRule{
				FromCIDRSet: []CIDRRule{},
			},
			other: &IngressCommonRule{
				FromCIDRSet: nil,
			},
			expected: false,
		},
		{
			name: "FromEntities is nil in left operand",
			in: &IngressCommonRule{
				FromEntities: nil,
			},
			other: &IngressCommonRule{
				FromEntities: []Entity{},
			},
			expected: false,
		},
		{
			name: "FromEntities is empty in left operand",
			in: &IngressCommonRule{
				FromEntities: []Entity{},
			},
			other: &IngressCommonRule{
				FromEntities: nil,
			},
			expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, tc.in.DeepEqual(tc.other))
		})
	}
}

func TestIngressCommonRuleMarshalling(t *testing.T) {
	testCases := []struct {
		name     string
		in       *IngressCommonRule
		expected string
	}{
		{
			name: "ToCIDRSet is nil",
			in: &IngressCommonRule{
				FromCIDRSet: nil,
			},
			expected: `{}`,
		},
		{
			name: "ToCIDRSet is empty",
			in: &IngressCommonRule{
				FromCIDRSet: []CIDRRule{},
			},
			expected: `{"fromCIDRSet":[]}`,
		},
		{
			name: "ToCIDRSet has CIDR",
			in: &IngressCommonRule{
				FromCIDRSet: []CIDRRule{
					{
						Cidr: "192.168.1.0/24",
					},
				},
			},
			expected: `{"fromCIDRSet":[{"cidr":"192.168.1.0/24"}]}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.expected, string(data))

			rule := IngressCommonRule{}
			err = json.Unmarshal(data, &rule)
			require.NoError(t, err)
			require.True(t, tc.in.DeepEqual(&rule))
		})
	}
}
