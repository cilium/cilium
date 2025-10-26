// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"

	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
)

func TestRequiresDerivativeRuleWithoutToGroups(t *testing.T) {
	eg := EgressRule{}
	require.False(t, eg.RequiresDerivative())
}

func TestRequiresDerivativeRuleWithToGroups(t *testing.T) {
	eg := EgressRule{}
	eg.ToGroups = []Groups{
		GetGroupsRule(),
	}
	require.True(t, eg.RequiresDerivative())
}

func TestCreateDerivativeRuleWithoutToGroups(t *testing.T) {
	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToEndpoints: []EndpointSelector{
				{
					LabelSelector: &slim_metav1.LabelSelector{MatchLabels: map[string]string{
						"test": "true",
					},
					},
				},
			},
		},
	}
	newRule, err := eg.CreateDerivative(context.TODO())
	require.Equal(t, newRule, eg)
	require.NoError(t, err)
}

func TestCreateDerivativeRuleWithToGroupsWitInvalidRegisterCallback(t *testing.T) {
	cb := func(ctx context.Context, group *Groups) ([]netip.Addr, error) {
		return []netip.Addr{}, fmt.Errorf("Invalid error")
	}
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}
	_, err := eg.CreateDerivative(context.TODO())
	require.Error(t, err)
}

func TestCreateDerivativeRuleWithToGroupsAndToPorts(t *testing.T) {
	cb := GetCallBackWithRule("192.168.1.1")
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	require.True(t, eg.RequiresDerivative())

	newRule, err := eg.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Empty(t, newRule.ToGroups)
	require.Len(t, newRule.ToCIDRSet, 1)
}

func TestCreateDerivativeWithoutErrorAndNoIPs(t *testing.T) {
	// Testing that if the len of the Ips returned by provider is 0 to block
	// all the IPS outside.
	cb := GetCallBackWithRule()
	RegisterToGroupsProvider(AWSProvider, cb)

	eg := &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToGroups: []Groups{
				GetGroupsRule(),
			},
		},
	}

	// Checking that the derivative rule is working correctly
	require.True(t, eg.RequiresDerivative())

	newRule, err := eg.CreateDerivative(context.TODO())
	require.NoError(t, err)
	require.Equal(t, &EgressRule{
		EgressCommonRule: EgressCommonRule{
			ToCIDRSet: CIDRRuleSlice{},
		},
	}, newRule)
}

func TestEgressCommonRuleDeepEqual(t *testing.T) {
	testCases := []struct {
		name      string
		in, other *EgressCommonRule
		expected  bool
	}{
		{
			name:     "All fields are nil in both",
			in:       &EgressCommonRule{},
			other:    &EgressCommonRule{},
			expected: true,
		},
		{
			name: "All fields are empty in both",
			in: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
				ToCIDR:      []CIDR{},
				ToCIDRSet:   []CIDRRule{},
				ToEntities:  []Entity{},
			},
			other: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
				ToCIDR:      []CIDR{},
				ToCIDRSet:   []CIDRRule{},
				ToEntities:  []Entity{},
			},
			expected: true,
		},
		{
			name: "ToEndpoints is nil in left operand",
			in: &EgressCommonRule{
				ToEndpoints: nil,
			},
			other: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
			},
			expected: false,
		},
		{
			name: "ToEndpoints is empty in left operand",
			in: &EgressCommonRule{
				ToEndpoints: []EndpointSelector{},
			},
			other: &EgressCommonRule{
				ToEndpoints: nil,
			},
			expected: false,
		},
		{
			name: "ToCIDR is nil in left operand",
			in: &EgressCommonRule{
				ToCIDR: nil,
			},
			other: &EgressCommonRule{
				ToCIDR: []CIDR{},
			},
			expected: false,
		},
		{
			name: "ToCIDR is empty in left operand",
			in: &EgressCommonRule{
				ToCIDR: []CIDR{},
			},
			other: &EgressCommonRule{
				ToCIDR: nil,
			},
			expected: false,
		},
		{
			name: "ToCIDRSet is nil in left operand",
			in: &EgressCommonRule{
				ToCIDRSet: nil,
			},
			other: &EgressCommonRule{
				ToCIDRSet: []CIDRRule{},
			},
			expected: false,
		},
		{
			name: "ToCIDRSet is empty in left operand",
			in: &EgressCommonRule{
				ToCIDRSet: []CIDRRule{},
			},
			other: &EgressCommonRule{
				ToCIDRSet: nil,
			},
			expected: false,
		},
		{
			name: "ToEntities is nil in left operand",
			in: &EgressCommonRule{
				ToEntities: nil,
			},
			other: &EgressCommonRule{
				ToEntities: []Entity{},
			},
			expected: false,
		},
		{
			name: "ToEntities is empty in left operand",
			in: &EgressCommonRule{
				ToEntities: []Entity{},
			},
			other: &EgressCommonRule{
				ToEntities: nil,
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

func TestEgressCommonRuleMarshalling(t *testing.T) {
	testCases := []struct {
		name     string
		in       *EgressCommonRule
		expected string
	}{
		{
			name: "ToCIDRSet is nil",
			in: &EgressCommonRule{
				ToCIDRSet: nil,
			},
			expected: `{}`,
		},
		{
			name: "ToCIDRSet is empty",
			in: &EgressCommonRule{
				ToCIDRSet: []CIDRRule{},
			},
			expected: `{"toCIDRSet":[]}`,
		},
		{
			name: "ToCIDRSet has CIDR",
			in: &EgressCommonRule{
				ToCIDRSet: []CIDRRule{
					{
						Cidr: "192.168.1.0/24",
					},
				},
			},
			expected: `{"toCIDRSet":[{"cidr":"192.168.1.0/24"}]}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.in)
			require.NoError(t, err)
			require.Equal(t, tc.expected, string(data))

			rule := EgressCommonRule{}
			err = json.Unmarshal(data, &rule)
			require.NoError(t, err)
			require.True(t, tc.in.DeepEqual(&rule))
		})
	}
}
