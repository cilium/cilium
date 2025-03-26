// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package srv6map

import (
	"context"
	"net/netip"
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

func TestSIDMapsHive(t *testing.T) {
	testutils.PrivilegedTest(t)

	type in struct {
		cell.In

		Map              *SIDMap
		NodeExtraDefines []defines.Map `group:"header-node-defines"`
	}

	hive := hive.New(
		cell.Provide(
			newSIDMap,
			func() *option.DaemonConfig {
				return &option.DaemonConfig{
					EnableSRv6: true,
				}
			},
		),
		cell.Invoke(func(in in) {
			// Test DI works
			require.NotNil(t, in.Map)

			merged := defines.Map{}
			for _, def := range in.NodeExtraDefines {
				require.NoError(t, merged.Merge(def))
			}

			require.Contains(t, merged, "SRV6_SID_MAP_SIZE")

			// Setup cleanup
			t.Cleanup(func() {
				in.Map.Unpin()
			})
		}),
	)

	logger := hivetest.Logger(t)

	require.NoError(t, hive.Start(logger, context.TODO()))

	// Test map creation
	require.FileExists(t, bpf.MapPath(logger, sidMapName))

	// Test map iteration
	k := &SIDKey{
		SID: netip.MustParseAddr("fd00::1").As16(),
	}

	v := &SIDValue{
		VRFID: 1,
	}

	m, err := OpenSIDMap(logger)
	require.NoError(t, err)

	require.NoError(t, m.Map.Update(k, v))

	var (
		keys []*SIDKey
		vals []*SIDValue
	)
	require.NoError(t, m.IterateWithCallback(func(k *SIDKey, v *SIDValue) {
		keys = append(keys, k)
		vals = append(vals, v)
	}))

	require.Contains(t, keys, k)
	require.Contains(t, vals, v)

	require.NoError(t, hive.Stop(logger, context.TODO()))

	// Map should be pinned even after stopping the hive
	require.FileExists(t, bpf.MapPath(logger, sidMapName))
}
