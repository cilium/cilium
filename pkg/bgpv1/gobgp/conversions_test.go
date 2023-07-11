// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gobgp

import (
	"context"
	"testing"

	gobgp "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/require"
)

// Test common Path type conversions appearing in the codebase
func TestPathConversions(t *testing.T) {
	for _, tt := range commonPaths {
		t.Run(tt.name, func(t *testing.T) {
			s := server.NewBgpServer()
			go s.Serve()

			err := s.StartBgp(context.TODO(), &gobgp.StartBgpRequest{
				Global: &gobgp.Global{
					Asn:        65000,
					RouterId:   "127.0.0.1",
					ListenPort: -1,
				},
			})
			require.NoError(t, err)

			t.Cleanup(func() {
				s.Stop()
			})

			path, err := ToGoBGPPath(&tt.path)
			require.NoError(t, err)

			res, err := s.AddPath(context.TODO(), &gobgp.AddPathRequest{
				Path: path,
			})
			require.NoError(t, err)
			require.NotZero(t, res.Uuid)

			req := &gobgp.ListPathRequest{
				Family: path.Family,
			}
			err = s.ListPath(context.TODO(), req, func(destination *gobgp.Destination) {
				paths, err := ToAgentPaths(destination.Paths)
				require.NoError(t, err)
				require.NotZero(t, paths)
				require.EqualValues(t, tt.path.NLRI, paths[0].NLRI)
				require.EqualValues(t, tt.path.PathAttributes, paths[0].PathAttributes)
			})
			require.NoError(t, err)
		})
	}
}
