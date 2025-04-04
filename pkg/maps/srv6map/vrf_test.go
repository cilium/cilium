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

func TestVRFMapsHive(t *testing.T) {
	testutils.PrivilegedTest(t)

	type in struct {
		cell.In

		Map4             *VRFMap4
		Map6             *VRFMap6
		NodeExtraDefines []defines.Map `group:"header-node-defines"`
	}

	var (
		m4 *VRFMap4
		m6 *VRFMap6
	)

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

			require.Contains(t, merged, "SRV6_VRF_MAP_SIZE")

			// Setup cleanup
			t.Cleanup(func() {
				in.Map4.Unpin()
				in.Map6.Unpin()
			})

			m4 = in.Map4
			m6 = in.Map6
		}),
	)

	logger := hivetest.Logger(t)

	require.NoError(t, hive.Start(logger, context.TODO()))

	// Test map creation
	require.FileExists(t, bpf.MapPath(logger, vrfMapName4))
	require.FileExists(t, bpf.MapPath(logger, vrfMapName6))

	// Test map iteration
	k4 := &VRFKey4{
		PrefixLen: vrf4StaticPrefixBits + 8,
		SourceIP:  netip.MustParseAddr("192.168.0.1").As4(),
		DestCIDR:  netip.MustParseAddr("10.0.0.0").As4(),
	}

	k6 := &VRFKey6{
		PrefixLen: vrf6StaticPrefixBits + 16,
		SourceIP:  netip.MustParseAddr("fd01::1").As16(),
		DestCIDR:  netip.MustParseAddr("fd00::").As16(),
	}

	v0 := &VRFValue{
		ID: 1,
	}

	v1 := &VRFValue{
		ID: 2,
	}

	m4, m6, err := OpenVRFMaps(logger)
	require.NoError(t, err)

	require.NoError(t, m4.Map.Update(k4, v0))
	require.NoError(t, m6.Map.Update(k6, v1))

	var (
		keys []VRFKey
		vals []VRFValue
	)

	require.NoError(t, m4.IterateWithCallback(func(k *VRFKey, v *VRFValue) {
		keys = append(keys, *k)
		vals = append(vals, *v)
	}))

	require.NoError(t, m6.IterateWithCallback(func(k *VRFKey, v *VRFValue) {
		keys = append(keys, *k)
		vals = append(vals, *v)
	}))

	require.Contains(t, keys, VRFKey{
		SourceIP: netip.MustParseAddr("192.168.0.1"),
		DestCIDR: netip.MustParsePrefix("10.0.0.0/8"),
	})
	require.Contains(t, keys, VRFKey{
		SourceIP: netip.MustParseAddr("fd01::1"),
		DestCIDR: netip.MustParsePrefix("fd00::/16"),
	})
	require.Contains(t, vals, VRFValue{ID: 1})
	require.Contains(t, vals, VRFValue{ID: 2})

	require.NoError(t, hive.Stop(logger, context.TODO()))

	// Map should be pinned even after stopping the hive
	require.FileExists(t, bpf.MapPath(logger, vrfMapName4))
	require.FileExists(t, bpf.MapPath(logger, vrfMapName6))
}
