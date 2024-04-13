// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"context"
	"testing"

	"github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/config/defines"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestVRFMapsHive(t *testing.T) {
	testutils.PrivilegedTest(t)

	type in struct {
		cell.In

		Map4             *VRFMap4
		Map6             *VRFMap6
		NodeExtraDefines []defines.Map `group:"header-node-defines"`
	}

	hive := hive.New(
		cell.Provide(
			newVRFMaps,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableSRv6: true,
				}
			},
		),
		cell.Invoke(func(in in) {
			// Test DI works
			require.NotNil(t, in.Map4)
			require.NotNil(t, in.Map6)

			merged := defines.Map{}
			for _, def := range in.NodeExtraDefines {
				require.NoError(t, merged.Merge(def))
			}

			require.Contains(t, merged, "SRV6_VRF_MAP4")
			require.Contains(t, merged, "SRV6_VRF_MAP6")
			require.Contains(t, merged, "SRV6_VRF_MAP_SIZE")

			// Setup cleanup
			t.Cleanup(func() {
				in.Map4.Unpin()
				in.Map6.Unpin()
			})
		}),
	)

	logger := hivetest.Logger(t)

	require.NoError(t, hive.Start(logger, context.TODO()))

	// Test map creation
	require.FileExists(t, bpf.MapPath(vrfMapName4))
	require.FileExists(t, bpf.MapPath(vrfMapName6))

	require.NoError(t, hive.Stop(logger, context.TODO()))

	// Map should be pinned even after stopping the hive
	require.FileExists(t, bpf.MapPath(vrfMapName4))
	require.FileExists(t, bpf.MapPath(vrfMapName6))
}
