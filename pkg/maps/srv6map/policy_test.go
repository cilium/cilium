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

func TestPolicyMapsHive(t *testing.T) {
	testutils.PrivilegedTest(t)

	type in struct {
		cell.In

		Map4             *PolicyMap4
		Map6             *PolicyMap6
		NodeExtraDefines []defines.Map `group:"header-node-defines"`
	}

	hive := hive.New(
		cell.Provide(
			newPolicyMaps,
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

			require.Contains(t, merged, "SRV6_POLICY_MAP_SIZE")

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
	require.FileExists(t, bpf.MapPath(logger, policyMapName4))
	require.FileExists(t, bpf.MapPath(logger, policyMapName6))

	// Test map iteration
	k4 := &PolicyKey4{
		PrefixLen: policyStaticPrefixBits + 8,
		VRFID:     1,
		DestCIDR:  netip.MustParseAddr("10.0.0.0").As4(),
	}

	k6 := &PolicyKey6{
		PrefixLen: policyStaticPrefixBits + 16,
		VRFID:     1,
		DestCIDR:  netip.MustParseAddr("fd00::").As16(),
	}

	v0 := &PolicyValue{
		SID: netip.MustParseAddr("fd00:0:0:0:1::").As16(),
	}

	v1 := &PolicyValue{
		SID: netip.MustParseAddr("fd00:0:0:0:2::").As16(),
	}

	m4, m6, err := OpenPolicyMaps(logger)
	require.NoError(t, err)

	require.NoError(t, m4.Map.Update(k4, v0))
	require.NoError(t, m6.Map.Update(k6, v1))

	var (
		keys []PolicyKey
		vals []PolicyValue
	)

	require.NoError(t, m4.IterateWithCallback(func(k *PolicyKey, v *PolicyValue) {
		keys = append(keys, *k)
		vals = append(vals, *v)
	}))

	require.NoError(t, m6.IterateWithCallback(func(k *PolicyKey, v *PolicyValue) {
		keys = append(keys, *k)
		vals = append(vals, *v)
	}))

	require.Contains(t, keys, PolicyKey{VRFID: 1, DestCIDR: netip.MustParsePrefix("10.0.0.0/8")})
	require.Contains(t, keys, PolicyKey{VRFID: 1, DestCIDR: netip.MustParsePrefix("fd00::/16")})
	require.Contains(t, vals, PolicyValue{SID: netip.MustParseAddr("fd00:0:0:0:1::").As16()})
	require.Contains(t, vals, PolicyValue{SID: netip.MustParseAddr("fd00:0:0:0:2::").As16()})

	// Stop hive
	require.NoError(t, hive.Stop(logger, context.TODO()))

	// Map should be pinned even after stopping the hive
	require.FileExists(t, bpf.MapPath(logger, policyMapName4))
	require.FileExists(t, bpf.MapPath(logger, policyMapName6))
}
