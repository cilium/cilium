// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

var testServerParameters = types.ServerParameters{
	Global: types.BGPGlobal{
		ASN:        65000,
		RouterID:   "127.0.0.1",
		ListenPort: -1,
	},
}

// TestGlobalImportPolicy verifies the presence of a global import policy. This is configured
// internally by Cilium at startup.
func TestGlobalImportPolicy(t *testing.T) {
	router, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), testServerParameters)
	require.NoError(t, err)

	t.Cleanup(func() {
		router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
	})

	gobgpServer := router.(*GoBGPServer).server
	request := &gobgp.ListPolicyAssignmentRequest{
		Name:      "global",
		Direction: gobgp.PolicyDirection_IMPORT,
	}
	response := []*gobgp.PolicyAssignment{}

	// For this test, we must call the underlying GoBGP server directly.
	// router.GetRoutePolicies() returns only the sub-policy for local routes.
	err = gobgpServer.ListPolicyAssignment(context.Background(), request, func(policyAssignment *gobgp.PolicyAssignment) {
		response = append(response, policyAssignment)
	})
	require.NoError(t, err)

	// check that retrieved policy matches the expected
	require.Len(t, response, 1)

	if response[0].Name != globalPolicyAssignmentName {
		t.Errorf("expected %s but got %s", globalPolicyAssignmentName, response[0].Name)
	}

	expected := []*gobgp.Policy{
		{
			Name: globalAllowLocalPolicyName,
			Statements: []*gobgp.Statement{
				{
					Name: fmt.Sprintf("%s_stmt0", globalAllowLocalPolicyName),
					Conditions: &gobgp.Conditions{
						RouteType:  gobgp.Conditions_ROUTE_TYPE_LOCAL,
						RpkiResult: -1,
					},

					Actions: &gobgp.Actions{RouteAction: gobgp.RouteAction_ACCEPT}},
			},
		},
	}

	require.Equal(t, expected, response[0].Policies)
}

func TestAddRemoveRoutePolicy(t *testing.T) {
	for _, tt := range types.TestCommonRoutePolicies {
		t.Run(tt.Name, func(t *testing.T) {
			router, err := NewGoBGPServer(context.Background(), hivetest.Logger(t), testServerParameters)
			require.NoError(t, err)

			t.Cleanup(func() {
				router.Stop(context.Background(), types.StopRequest{FullDestroy: true})
			})
			gobgpServer := router.(*GoBGPServer).server

			// add testing policy
			err = router.AddRoutePolicy(context.Background(), types.RoutePolicyRequest{Policy: tt.Policy})
			if !tt.Valid {
				// if error is expected, check that polices are cleaned up and return
				require.Error(t, err)
				checkPoliciesCleanedUp(t, gobgpServer)
				return
			}
			require.NoError(t, err)

			// retrieve policies
			pResp, err := router.GetRoutePolicies(context.Background())
			require.NoError(t, err)

			// ignore the global policy that is configured when starting GoBGP
			filteredPolicies := []*types.RoutePolicy{}
			for _, policy := range pResp.Policies {
				if policy.Name == globalAllowLocalPolicyName {
					continue
				}
				filteredPolicies = append(filteredPolicies, policy)
			}
			pResp.Policies = filteredPolicies

			// check that retrieved policy matches the expected
			require.Len(t, pResp.Policies, 1)
			require.Equal(t, tt.Policy, pResp.Policies[0])

			// remove testing policy
			err = router.RemoveRoutePolicy(context.Background(), types.RoutePolicyRequest{Policy: tt.Policy})
			require.NoError(t, err)

			checkPoliciesCleanedUp(t, gobgpServer)
		})
	}
}

func checkPoliciesCleanedUp(t *testing.T, gobgpServer *server.BgpServer) {
	// check that polies were removed
	cnt := 0
	err := gobgpServer.ListPolicy(context.Background(), &gobgp.ListPolicyRequest{}, func(p *gobgp.Policy) {
		// ignore the global policy that is configured when starting GoBGP
		if p.Name == globalAllowLocalPolicyName {
			return
		}
		cnt++
	})
	require.NoError(t, err)
	require.Equal(t, 0, cnt, "leaked policies")

	// check that policy assignments were removed
	cnt = 0
	err = gobgpServer.ListPolicyAssignment(context.Background(), &gobgp.ListPolicyAssignmentRequest{}, func(a *gobgp.PolicyAssignment) {
		// ignore the global policy that is configured when starting GoBGP
		for _, policy := range a.Policies {
			if policy.Name == globalAllowLocalPolicyName {
				return
			}
		}
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
