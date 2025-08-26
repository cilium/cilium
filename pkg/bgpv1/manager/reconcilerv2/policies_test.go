// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconcilerv2

import (
	"cmp"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

func Test_MergeRoutePolicies(t *testing.T) {

	localPrefDefault := int64(100)
	localPrefLow := int64(50)
	localPrefHigh := int64(200)

	var nilPointerInt64 *int64

	conditionsNeighborOne := types.RoutePolicyConditions{
		MatchNeighbors: []string{"fd00::1"},
		MatchFamilies:  []types.Family{{Afi: types.AfiIPv6}},
	}

	conditionsNeighborThree := types.RoutePolicyConditions{
		MatchNeighbors: []string{"fd00::3"},
		MatchFamilies:  []types.Family{{Afi: types.AfiIPv6}},
	}

	tests := []struct {
		name          string
		policyA       *types.RoutePolicy
		policyB       *types.RoutePolicy
		errorExpected bool
		expected      *types.RoutePolicy
	}{
		{
			name:          "nil policy",
			policyA:       nil,
			policyB:       nil,
			errorExpected: true,
			expected:      nil,
		},
		{
			name:    "nil policyA",
			policyA: nil,
			policyB: &types.RoutePolicy{
				Name: "policy",
			},
			errorExpected: true,
			expected:      nil,
		},
		{
			name: "nil policyB",
			policyA: &types.RoutePolicy{
				Name: "policy",
			},
			policyB:       nil,
			errorExpected: true,
			expected:      nil,
		},
		{
			name: "policy names mismatched",
			policyA: &types.RoutePolicy{
				Name: "policy",
			},
			policyB: &types.RoutePolicy{
				Name: "notpolicy",
			},
			errorExpected: true,
			expected:      nil,
		},
		{
			name: "policy types mismatched",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Type: types.RoutePolicyTypeExport,
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Type: types.RoutePolicyTypeImport,
			},
			errorExpected: true,
			expected:      nil,
		},
		{
			name: "empty statements",
			policyA: &types.RoutePolicy{
				Name:       "policy",
				Statements: []*types.RoutePolicyStatement{},
			},
			policyB: &types.RoutePolicy{
				Name:       "policy",
				Statements: []*types.RoutePolicyStatement{},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name:       "policy",
				Statements: []*types.RoutePolicyStatement{},
			},
		},
		{
			name: "nil statement.Action.SetLocalPref",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							SetLocalPreference: nil,
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							SetLocalPreference: nil,
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							SetLocalPreference: nil,
						},
					},
				},
			},
		},
		{
			name: "nil dereferenced statement.Action.SetLocalPref",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							SetLocalPreference: nilPointerInt64, // can be nil or a nil pointer
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							SetLocalPreference: &localPrefDefault, // In policy B, local pref is set
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
							// Ensures that nil is properly handled by selecting the non-nil value
							SetLocalPreference: &localPrefDefault,
						},
					},
				},
			},
		},
		{
			name: "both set standard communities",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"100:100", "101:101"},
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"200:200", "202:202"},
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"100:100", "101:101", "200:200", "202:202"},
						},
					},
				},
			},
		},
		{
			name: "both set large communities",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"},
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"2000:2000:2000", "2222:2222:2222"},
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{
								"1000:1000:1000",
								"1111:1111:1111",
								"2000:2000:2000",
								"2222:2222:2222",
							},
						},
					},
				},
			},
		},
		{
			name: "both set standard and large communities",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"100:100", "101:101"},
						},
					},
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"},
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"200:200", "202:202"},
						},
					},
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"2000:2000:2000", "2222:2222:2222"},
						},
					},
					{
						Conditions: conditionsNeighborThree,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"3333:3333:3333"},
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"100:100", "101:101", "200:200", "202:202"},
							AddLargeCommunities: []string{
								"1000:1000:1000",
								"1111:1111:1111",
								"2000:2000:2000",
								"2222:2222:2222",
							},
						},
					},
					{
						Conditions: conditionsNeighborThree,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"3333:3333:3333"},
						},
					},
				},
			},
		},
		{
			name: "deduplicates standard and large communities",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddCommunities:      []string{"100:100", "101:101"},
							AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"},
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddCommunities:      []string{"100:100", "101:101", "200:200"},
							AddLargeCommunities: []string{"1000:1000:1000", "2000:2000:2000", "2222:2222:2222"},
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"100:100", "101:101", "200:200"},
							AddLargeCommunities: []string{
								"1000:1000:1000",
								"1111:1111:1111",
								"2000:2000:2000",
								"2222:2222:2222",
							},
						},
					},
				},
			},
		},
		{
			name: "both set standard and large communities with differing local preference",
			policyA: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							AddCommunities:     []string{"100:100", "101:101"},
							SetLocalPreference: &localPrefLow,
						},
					},
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"},
							SetLocalPreference:  &localPrefLow,
						},
					},
				},
			},
			policyB: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionAccept,
							AddCommunities:     []string{"200:200", "202:202"},
							SetLocalPreference: &localPrefHigh,
						},
					},
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"2000:2000:2000", "2222:2222:2222"},
							SetLocalPreference:  &localPrefHigh,
						},
					},
					{
						Conditions: conditionsNeighborThree,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"3333:3333:3333"},
							SetLocalPreference:  &localPrefDefault,
						},
					},
				},
			},
			errorExpected: false,
			expected: &types.RoutePolicy{
				Name: "policy",
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: conditionsNeighborOne,
						Actions: types.RoutePolicyActions{
							RouteAction:    types.RoutePolicyActionAccept,
							AddCommunities: []string{"100:100", "101:101", "200:200", "202:202"},
							AddLargeCommunities: []string{
								"1000:1000:1000",
								"1111:1111:1111",
								"2000:2000:2000",
								"2222:2222:2222",
							},
							SetLocalPreference: &localPrefHigh,
						},
					},
					{
						Conditions: conditionsNeighborThree,
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionAccept,
							AddLargeCommunities: []string{"3333:3333:3333"},
							SetLocalPreference:  &localPrefDefault,
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			result, err := MergeRoutePolicies(tt.policyA, tt.policyB)
			if tt.errorExpected == true {
				req.Error(err)
			} else {
				req.NoError(err)
			}

			if tt.expected != nil {
				req.NotNil(result)
				SortRouteStatementsByName(result.Statements)
				SortRouteStatementsByName(tt.expected.Statements)
			}

			req.Equal(tt.expected, result)
		})
	}
}

func SortRouteStatementsByName(statements []*types.RoutePolicyStatement) {
	slices.SortFunc(statements, func(i, j *types.RoutePolicyStatement) int {
		return cmp.Compare(i.Conditions.String(), j.Conditions.String())
	})
}
