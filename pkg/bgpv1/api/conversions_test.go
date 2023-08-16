// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package api

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bgpv1/types"
)

var testRouterASN = int64(65001)

// Test common Route conversions appearing in the codebase
func TestRouteConversions(t *testing.T) {
	for _, tt := range types.CommonPaths {
		t.Run(tt.Name, func(t *testing.T) {
			expectedRoute := &types.Route{
				Prefix: tt.Path.NLRI.String(),
				Paths:  []*types.Path{&tt.Path},
			}

			apiRoutes, err := ToAPIRoutes([]*types.Route{expectedRoute}, testRouterASN)
			require.NoError(t, err)
			require.NotZero(t, apiRoutes)

			agentRoutes, err := ToAgentRoutes(apiRoutes)
			require.NoError(t, err)
			require.NotZero(t, agentRoutes)

			require.EqualValues(t, expectedRoute, agentRoutes[0])
		})
	}
}
