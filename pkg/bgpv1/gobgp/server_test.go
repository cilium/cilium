// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"net/netip"
	"testing"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/require"
	"k8s.io/utils/pointer"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

var testServerParameters = types.ServerParameters{
	Global: types.BGPGlobal{
		ASN:        65000,
		RouterID:   "127.0.0.1",
		ListenPort: -1,
	},
}

func TestAddRemoveRoutePolicy(t *testing.T) {
	var table = []struct {
		name        string
		policy      *types.RoutePolicy
		expectError bool
	}{
		{
			name: "test add/del simple policy",
			policy: &types.RoutePolicy{
				Name: "testpolicy1",
				Type: types.RoutePolicyTypeExport,
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: []string{"172.16.0.1/32"},
							MatchPrefixes: []*types.RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: types.RoutePolicyActions{
							RouteAction:         types.RoutePolicyActionNone,
							AddCommunities:      []string{"65000:100"},
							AddLargeCommunities: []string{"4294967295:0:100"},
							SetLocalPreference:  pointer.Int64(150),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "test add/del complex policy",
			policy: &types.RoutePolicy{
				Name: "testpolicy1",
				Type: types.RoutePolicyTypeExport,
				Statements: []*types.RoutePolicyStatement{
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: []string{"172.16.0.1/32", "10.10.10.10/32"},
							MatchPrefixes: []*types.RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
								{
									CIDR:         netip.MustParsePrefix("192.188.0.0/16"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionNone,
							AddCommunities:     []string{"65000:100", "65000:101"},
							SetLocalPreference: pointer.Int64(150),
						},
					},
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: []string{"fe80::210:5aff:feaa:20a2/128"},
							MatchPrefixes: []*types.RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("2001:0DB8::/64"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
								{
									CIDR:         netip.MustParsePrefix("2002::/16"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionNone,
							AddCommunities:     []string{"65000:100", "65000:101"},
							SetLocalPreference: pointer.Int64(150),
						},
					},
				},
			},
			expectError: false,
		},
		{
			name: "test invalid policy",
			policy: &types.RoutePolicy{
				Name: "testpolicy1",
				Type: types.RoutePolicyTypeExport,
				Statements: []*types.RoutePolicyStatement{
					// valid statement
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: []string{"172.16.0.1/32"},
							MatchPrefixes: []*types.RoutePolicyPrefixMatch{
								{
									CIDR:         netip.MustParsePrefix("1.2.3.0/24"),
									PrefixLenMin: 24,
									PrefixLenMax: 32,
								},
							},
						},
						Actions: types.RoutePolicyActions{
							RouteAction:        types.RoutePolicyActionNone,
							AddCommunities:     []string{"65000:100"},
							SetLocalPreference: pointer.Int64(150),
						},
					},
					// invalid statement - wrong neighbor address
					{
						Conditions: types.RoutePolicyConditions{
							MatchNeighbors: []string{"ABCD"},
						},
						Actions: types.RoutePolicyActions{
							RouteAction: types.RoutePolicyActionNone,
						},
					},
				},
			},
			expectError: true,
		},
		{
			name:        "test nil policy",
			policy:      nil,
			expectError: true,
		},
	}
	for _, tt := range table {
		t.Run(tt.name, func(t *testing.T) {
			router, err := NewGoBGPServerWithConfig(context.Background(), log, testServerParameters)
			require.NoError(t, err)

			t.Cleanup(func() {
				router.Stop()
			})
			gobgpServer := router.(*GoBGPServer).server

			// add testing policy
			err = router.AddRoutePolicy(context.Background(), types.RoutePolicyRequest{Policy: tt.policy})
			if tt.expectError {
				// if error is expected, check that polices are cleaned up and return
				require.Error(t, err)
				checkPoliciesCleanedUp(t, gobgpServer)
				return
			}
			require.NoError(t, err)

			// compile a map of created defined sets
			definedSets := make(map[string]*gobgp.DefinedSet)
			err = gobgpServer.ListDefinedSet(context.Background(), &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_NEIGHBOR}, func(ds *gobgp.DefinedSet) {
				definedSets[ds.Name] = ds
			})
			require.NoError(t, err)
			err = gobgpServer.ListDefinedSet(context.Background(), &gobgp.ListDefinedSetRequest{DefinedType: gobgp.DefinedType_PREFIX}, func(ds *gobgp.DefinedSet) {
				definedSets[ds.Name] = ds
			})
			require.NoError(t, err)

			// check that policy was added properly
			cnt := 0
			err = gobgpServer.ListPolicy(context.Background(), &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
				cnt++
				require.Equal(t, tt.policy.Name, p.Name)
				require.Len(t, p.Statements, len(tt.policy.Statements))
				for i, stmt := range p.Statements {
					expStmt := tt.policy.Statements[i]
					require.Equal(t, policyStatementName(tt.policy.Name, i), stmt.Name)
					if len(expStmt.Conditions.MatchNeighbors) > 0 {
						require.NotNil(t, stmt.Conditions.NeighborSet)
						require.NotNil(t, definedSets[stmt.Conditions.NeighborSet.Name], "defined set for MatchNeighbors must exist")
						require.Equal(t, expStmt.Conditions.MatchNeighbors, definedSets[stmt.Conditions.NeighborSet.Name].List)
					}
					if len(expStmt.Conditions.MatchPrefixes) > 0 {
						require.NotNil(t, stmt.Conditions.PrefixSet)
						require.NotNil(t, definedSets[stmt.Conditions.PrefixSet.Name], "defined set for MatchPrefixes must exist")
						require.Equal(t, len(expStmt.Conditions.MatchPrefixes), len(definedSets[stmt.Conditions.PrefixSet.Name].Prefixes))
						for j, expPrefix := range expStmt.Conditions.MatchPrefixes {
							prefix := definedSets[stmt.Conditions.PrefixSet.Name].Prefixes[j]
							require.Equal(t, expPrefix.CIDR, netip.MustParsePrefix(prefix.IpPrefix))
							require.EqualValues(t, expPrefix.PrefixLenMin, prefix.MaskLengthMin)
							require.EqualValues(t, expPrefix.PrefixLenMax, prefix.MaskLengthMax)
						}
					}
					require.Equal(t, toGoBGPRouteAction(expStmt.Actions.RouteAction), stmt.Actions.RouteAction)
					if len(expStmt.Actions.AddCommunities) > 0 {
						require.NotNil(t, stmt.Actions.Community)
						require.Equal(t, expStmt.Actions.AddCommunities, stmt.Actions.Community.Communities)
					}
					if len(expStmt.Actions.AddLargeCommunities) > 0 {
						require.NotNil(t, stmt.Actions.LargeCommunity)
						require.Equal(t, expStmt.Actions.AddLargeCommunities, stmt.Actions.LargeCommunity.Communities)
					}
					if expStmt.Actions.SetLocalPreference != nil {
						require.NotNil(t, stmt.Actions.LocalPref)
						require.EqualValues(t, *expStmt.Actions.SetLocalPreference, stmt.Actions.LocalPref.Value)
					}
				}
			})
			require.NoError(t, err)
			require.Equal(t, 1, cnt)

			// check policy assignment
			cnt = 0
			err = gobgpServer.ListPolicyAssignment(context.Background(), &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
				if a.Direction == toGoBGPPolicyDirection(tt.policy.Type) {
					require.Len(t, a.Policies, 1)
					require.Equal(t, tt.policy.Name, a.Policies[0].Name)
				}
				cnt += len(a.Policies)
			})
			require.NoError(t, err)
			require.Equal(t, 1, cnt)

			// remove testing policy
			err = router.RemoveRoutePolicy(context.Background(), types.RoutePolicyRequest{Policy: tt.policy})
			require.NoError(t, err)

			checkPoliciesCleanedUp(t, gobgpServer)
		})
	}
}

func checkPoliciesCleanedUp(t *testing.T, gobgpServer *server.BgpServer) {
	// check that polies were removed
	cnt := 0
	err := gobgpServer.ListPolicy(context.Background(), &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
		cnt++
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policies")

	// check that policy assignments were removed
	cnt = 0
	err = gobgpServer.ListPolicyAssignment(context.Background(), &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
		cnt += len(a.Policies)
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policy assignments")

	// check that defined sets were removed
	cnt = 0
	err = gobgpServer.ListDefinedSet(context.Background(), &gobgp.ListDefinedSetRequest{}, func(ds *gobgp.DefinedSet) {
		cnt++
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policy defined sets")
}
