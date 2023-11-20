// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"testing"

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

func TestAddRemoveRoutePolicy(t *testing.T) {
	for _, tt := range types.TestCommonRoutePolicies {
		t.Run(tt.Name, func(t *testing.T) {
			router, err := NewGoBGPServer(context.Background(), log, testServerParameters)
			require.NoError(t, err)

			t.Cleanup(func() {
				router.Stop()
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

			// check that retrieved policy matches the expected
			require.Len(t, pResp.Policies, 1)
			require.EqualValues(t, tt.Policy, pResp.Policies[0])

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
