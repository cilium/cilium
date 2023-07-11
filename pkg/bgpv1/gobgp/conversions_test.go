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

// Test common Path type conversions appearing in the codebase
func TestPathConversions(t *testing.T) {
	for _, tt := range types.CommonPaths {
		t.Run(tt.Name, func(t *testing.T) {
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

			path, err := ToGoBGPPath(&tt.Path)
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
				require.EqualValues(t, tt.Path.NLRI, paths[0].NLRI)
				require.EqualValues(t, len(tt.Path.PathAttributes), len(paths[0].PathAttributes))
				for i := range tt.Path.PathAttributes {
					// byte-compare encoded path attributes
					data1, err := tt.Path.PathAttributes[i].Serialize()
					require.NoError(t, err)
					data2, err := paths[0].PathAttributes[i].Serialize()
					require.NoError(t, err)
					require.EqualValues(t, data1, data2)
				}
			})
			require.NoError(t, err)
		})
	}
}
