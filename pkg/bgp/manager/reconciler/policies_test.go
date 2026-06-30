// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"net/netip"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/statedb"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgp/fake"
	bgpTables "github.com/cilium/cilium/pkg/bgp/manager/tables"
	"github.com/cilium/cilium/pkg/bgp/types"
)

func TestMergeRoutePolicyStatements(t *testing.T) {
	localPrefDefault := int64(100)
	localPrefLow := int64(50)
	localPrefHigh := int64(200)

	var nilPointerInt64 *int64

	conditionsNeighborOne := types.RoutePolicyConditions{
		MatchNeighbors: &types.RoutePolicyNeighborMatch{
			Type:      types.RoutePolicyMatchAny,
			Neighbors: []netip.Addr{netip.MustParseAddr("fd00::1")},
		},
		MatchFamilies: []types.Family{{Afi: types.AfiIPv6}},
	}

	conditionsNeighborThree := types.RoutePolicyConditions{
		MatchNeighbors: &types.RoutePolicyNeighborMatch{
			Type:      types.RoutePolicyMatchAny,
			Neighbors: []netip.Addr{netip.MustParseAddr("fd00::3")},
		},
		MatchFamilies: []types.Family{{Afi: types.AfiIPv6}},
	}

	testStatement := func(actions types.RoutePolicyActions) *types.RoutePolicyStatement {
		return &types.RoutePolicyStatement{
			Conditions: conditionsNeighborOne,
			Actions:    actions,
		}
	}

	namedStatement := func(name string, actions types.RoutePolicyActions) *types.RoutePolicyStatement {
		return &types.RoutePolicyStatement{
			Name:       name,
			Conditions: conditionsNeighborOne,
			Actions:    actions,
		}
	}

	tests := []struct {
		name          string
		statementA    *types.RoutePolicyStatement
		statementB    *types.RoutePolicyStatement
		errorExpected bool
		expected      *types.RoutePolicyStatement
	}{
		{
			name: "statement names mismatched",
			statementA: &types.RoutePolicyStatement{
				Name:       "statement-a",
				Conditions: conditionsNeighborOne,
			},
			statementB: &types.RoutePolicyStatement{
				Name:       "statement-b",
				Conditions: conditionsNeighborOne,
			},
			errorExpected: true,
		},
		{
			name: "statement conditions mismatched",
			statementA: &types.RoutePolicyStatement{
				Name:       "statement",
				Conditions: conditionsNeighborOne,
			},
			statementB: &types.RoutePolicyStatement{
				Name:       "statement",
				Conditions: conditionsNeighborThree,
			},
			errorExpected: true,
		},
		{
			name:          "statement route actions mismatched",
			statementA:    namedStatement("statement", types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept}),
			statementB:    namedStatement("statement", types.RoutePolicyActions{RouteAction: types.RoutePolicyActionReject}),
			errorExpected: true,
		},
		{
			name:       "nil statement.Action.SetLocalPref",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: nil}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: nil}),
			expected:   testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: nil}),
		},
		{
			name:       "nil dereferenced statement.Action.SetLocalPref",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: nilPointerInt64}),   // can be nil or a nil pointer
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: &localPrefDefault}), // In policy B, local pref is set
			// Ensures that nil is properly handled by selecting the non-nil value.
			expected: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: &localPrefDefault}),
		},
		{
			name:       "both set standard communities",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101"}}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"200:200", "202:202"}}),
			expected:   testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101", "200:200", "202:202"}}),
		},
		{
			name:       "both set large communities",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"}}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddLargeCommunities: []string{"2000:2000:2000", "2222:2222:2222"}}),
			expected: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddLargeCommunities: []string{
				"1000:1000:1000",
				"1111:1111:1111",
				"2000:2000:2000",
				"2222:2222:2222",
			}}),
		},
		{
			name:       "merges standard and large communities from different statements",
			statementA: namedStatement("statement", types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101"}}),
			statementB: namedStatement("statement", types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"}}),
			expected:   namedStatement("statement", types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101"}, AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"}}),
		},
		{
			name:       "both set standard and large communities",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101"}, AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"}}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"200:200", "202:202"}, AddLargeCommunities: []string{"2000:2000:2000", "2222:2222:2222"}}),
			expected: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101", "200:200", "202:202"}, AddLargeCommunities: []string{
				"1000:1000:1000",
				"1111:1111:1111",
				"2000:2000:2000",
				"2222:2222:2222",
			}}),
		},
		{
			name:       "deduplicates standard and large communities",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101"}, AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"}}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101", "200:200"}, AddLargeCommunities: []string{"1000:1000:1000", "2000:2000:2000", "2222:2222:2222"}}),
			expected: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101", "200:200"}, AddLargeCommunities: []string{
				"1000:1000:1000",
				"1111:1111:1111",
				"2000:2000:2000",
				"2222:2222:2222",
			}}),
		},
		{
			name:       "both set standard and large communities with differing local preference",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101"}, AddLargeCommunities: []string{"1000:1000:1000", "1111:1111:1111"}, SetLocalPreference: &localPrefLow}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"200:200", "202:202"}, AddLargeCommunities: []string{"2000:2000:2000", "2222:2222:2222"}, SetLocalPreference: &localPrefHigh}),
			expected: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, AddCommunities: []string{"100:100", "101:101", "200:200", "202:202"}, AddLargeCommunities: []string{
				"1000:1000:1000",
				"1111:1111:1111",
				"2000:2000:2000",
				"2222:2222:2222",
			}, SetLocalPreference: &localPrefHigh}),
		},
		{
			name:       "keeps higher local preference from statement A",
			statementA: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: &localPrefHigh}),
			statementB: testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: &localPrefLow}),
			expected:   testStatement(types.RoutePolicyActions{RouteAction: types.RoutePolicyActionAccept, SetLocalPreference: &localPrefHigh}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)

			result, err := mergeRoutePolicyStatements(tt.statementA, tt.statementB)
			if tt.errorExpected {
				req.Error(err)
				return
			}

			req.NoError(err)
			req.Equal(tt.expected, result)
		})
	}
}

func TestRoutePolicySoftReset(t *testing.T) {
	logger := hivetest.Logger(t)
	peer0 := netip.MustParseAddr("10.0.0.1")
	peer1 := netip.MustParseAddr("fd00::2")
	peer2 := netip.MustParseAddr("fe80::1%eth0")
	allPeer := netip.Addr{}

	// In this test, we're only interested in which neighbors are resetted with which
	// direction. This is an abstructed policy to make the test easier.
	type policy struct {
		name      string
		typ       types.RoutePolicyType
		neighbors []netip.Addr
	}

	tests := []struct {
		name            string
		currentPolicies []*policy
		desiredPolicies []*policy
		expectedResets  map[netip.Addr]types.SoftResetDirection
	}{
		{
			name:            "new outbound policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,
				peer1: types.SoftResetDirectionOut,
				peer2: types.SoftResetDirectionOut,
			},
		},
		{
			name:            "new inbound policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionIn,
				peer1: types.SoftResetDirectionIn,
				peer2: types.SoftResetDirectionIn,
			},
		},
		{
			name:            "new outbound and inbound policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionBoth,
				peer1: types.SoftResetDirectionBoth,
				peer2: types.SoftResetDirectionBoth,
			},
		},
		{
			name:            "new mixed policies",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "outbound0",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0},
				},
				{
					name:      "outbound1",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer1},
				},
				{
					name:      "inbound0",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1},
				},
				{
					name:      "inbound1",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,
				peer1: types.SoftResetDirectionBoth,
				peer2: types.SoftResetDirectionIn,
			},
		},
		// Update test cases
		{
			name: "update outbound policy neighbors",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut, // was in old policy
				peer1: types.SoftResetDirectionOut, // in both old and new policy
				peer2: types.SoftResetDirectionOut, // in new policy
			},
		},
		{
			name: "update inbound policy neighbors",
			currentPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionIn, // was in old policy
				peer1: types.SoftResetDirectionIn, // in both old and new policy
				peer2: types.SoftResetDirectionIn, // in new policy
			},
		},
		{
			name: "update policy type from export to import",
			currentPolicies: []*policy{
				{
					name:      "policy",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "policy",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionBoth, // affected by both old export and new import policy
				peer1: types.SoftResetDirectionBoth, // affected by both old export and new import policy
			},
		},
		{
			name: "update mixed policies with neighbor changes",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer2},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionBoth, // affected by both policy types
				peer1: types.SoftResetDirectionBoth, // affected by both policy types
				peer2: types.SoftResetDirectionBoth, // affected by both policy types
			},
		},
		// Delete test cases
		{
			name: "delete outbound policy",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,
				peer1: types.SoftResetDirectionOut,
				peer2: types.SoftResetDirectionOut,
			},
		},
		{
			name: "delete inbound policy",
			currentPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1, peer2},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionIn,
				peer1: types.SoftResetDirectionIn,
				peer2: types.SoftResetDirectionIn,
			},
		},
		{
			name: "delete one of multiple policies",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut, // outbound policy deleted
				peer1: types.SoftResetDirectionOut, // outbound policy deleted, inbound remains
				// peer2 has no reset because it only had inbound policy which remains unchanged
			},
		},
		{
			name: "delete all policies",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer1, peer2},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				peer0: types.SoftResetDirectionOut,  // had outbound policy
				peer1: types.SoftResetDirectionBoth, // had both policies
				peer2: types.SoftResetDirectionIn,   // had inbound policy
			},
		},
		{
			name: "no changes - same policies",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{},
		},
		{
			name:            "new policy with empty neighbors (all neighbors)",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name:            "new policy with empty neighbors for import (all neighbors)",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionIn,
			},
		},
		{
			name:            "new policies with empty neighbors for both import and export (all neighbors)",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
				{
					name:      "all-inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionBoth,
			},
		},
		{
			name:            "mixed policy - some specific neighbors and all neighbors",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "specific-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
				{
					name:      "all-inbound",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionIn,
				peer0:   types.SoftResetDirectionOut,
				peer1:   types.SoftResetDirectionOut,
			},
		},
		{
			name: "update policy from specific neighbors to all neighbors",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name: "update policy from all neighbors to specific neighbors",
			currentPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			desiredPolicies: []*policy{
				{
					name:      "outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name: "delete policy with all neighbors",
			currentPolicies: []*policy{
				{
					name:      "all-outbound",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
			},
			desiredPolicies: []*policy{},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
			},
		},
		{
			name:            "all neighbors export, specific neighbors import",
			currentPolicies: []*policy{},
			desiredPolicies: []*policy{
				{
					name:      "all-export",
					typ:       types.RoutePolicyTypeExport,
					neighbors: []netip.Addr{},
				},
				{
					name:      "specific-import",
					typ:       types.RoutePolicyTypeImport,
					neighbors: []netip.Addr{peer0, peer1},
				},
			},
			expectedResets: map[netip.Addr]types.SoftResetDirection{
				allPeer: types.SoftResetDirectionOut,
				peer0:   types.SoftResetDirectionIn,
				peer1:   types.SoftResetDirectionIn,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := require.New(t)
			router := fake.NewFakeRouter()

			current := RoutePolicyMap{}
			for _, policy := range tt.currentPolicies {
				routePolicy := &types.RoutePolicy{
					Name: policy.name,
					Type: policy.typ,
					Statements: []*types.RoutePolicyStatement{
						{
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				}
				if len(policy.neighbors) > 0 {
					routePolicy.Statements[0].Conditions = types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: policy.neighbors,
						},
					}
				}
				current[policy.name] = routePolicy
			}

			desired := RoutePolicyMap{}
			for _, policy := range tt.desiredPolicies {
				routePolicy := &types.RoutePolicy{
					Name: policy.name,
					Type: policy.typ,
					Statements: []*types.RoutePolicyStatement{
						{
							Actions: types.RoutePolicyActions{
								RouteAction: types.RoutePolicyActionAccept,
							},
						},
					},
				}
				if len(policy.neighbors) > 0 {
					routePolicy.Statements[0].Conditions = types.RoutePolicyConditions{
						MatchNeighbors: &types.RoutePolicyNeighborMatch{
							Type:      types.RoutePolicyMatchAny,
							Neighbors: policy.neighbors,
						},
					}
				}
				desired[policy.name] = routePolicy
			}

			_, err := ReconcileRoutePolicies(&ReconcileRoutePoliciesParams{
				Logger:          logger,
				Ctx:             t.Context(),
				Router:          router,
				CurrentPolicies: current,
				DesiredPolicies: desired,
			})
			req.NoError(err)

			// Check if the reset happened for expected peers
			req.Equal(tt.expectedResets, router.GetResets())
		})
	}
}

func requireDesiredRoutePolicies(t *testing.T, db *statedb.DB, table statedb.Table[*bgpTables.DesiredRoutePolicy],
	instanceName string, owner string, expectedPolicies []*bgpTables.DesiredRoutePolicy) {
	t.Helper()

	expectedByKey := make(map[bgpTables.DesiredRoutePolicyKey]*bgpTables.DesiredRoutePolicy)
	for _, expected := range expectedPolicies {
		expectedByKey[expected.GetKey()] = expected
	}

	actualByKey := make(map[bgpTables.DesiredRoutePolicyKey]*bgpTables.DesiredRoutePolicy)
	for actual := range table.List(db.ReadTxn(), bgpTables.DesiredRoutePoliciesByInstanceOwner(instanceName, owner)) {
		actualByKey[actual.GetKey()] = actual
	}

	require.Equal(t, expectedByKey, actualByKey)
}
