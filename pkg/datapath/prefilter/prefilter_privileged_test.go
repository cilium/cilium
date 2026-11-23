// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package prefilter

import (
	"context"
	"net"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/bpf"
	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/testutils"
)

func TestPrivilegedPrefilterMaps(t *testing.T) {
	testutils.PrivilegedTest(t)

	const (
		maxLKeys = 1024 * 64
		maxHKeys = 1024 * 1024 * 20
	)

	type in struct {
		cell.In

		PreFilter PreFilter
	}

	daemonConfig := option.DaemonConfig{EnableXDPPrefilter: true}
	var preFilter PreFilter
	h := hive.New(
		registry.Cell,
		Cell,
		cell.Provide(func() *option.DaemonConfig { return &daemonConfig }),
		cell.Invoke(func(in in) {
			preFilter = in.PreFilter
		}),
	)

	ctx := context.Background()
	logger := hivetest.Logger(t)
	require.NoError(t, h.Start(logger, ctx))
	t.Cleanup(func() {
		require.NoError(t, h.Stop(logger, ctx))
		for _, name := range []string{
			datapathmaps.CiliumCIDRV4Dyn,
			datapathmaps.CiliumCIDRV4Fix,
			datapathmaps.CiliumCIDRV6Dyn,
			datapathmaps.CiliumCIDRV6Fix,
		} {
			require.NoError(t, bpf.Remove(bpf.MapPath(logger, name)))
		}
	})

	for _, tt := range []struct {
		name       string
		mapType    ebpf.MapType
		keySize    uint32
		maxEntries uint32
	}{
		{datapathmaps.CiliumCIDRV4Dyn, ebpf.LPMTrie, 8, maxLKeys},
		{datapathmaps.CiliumCIDRV4Fix, ebpf.Hash, 8, maxHKeys},
		{datapathmaps.CiliumCIDRV6Dyn, ebpf.LPMTrie, 20, maxLKeys},
		{datapathmaps.CiliumCIDRV6Fix, ebpf.Hash, 20, maxHKeys},
	} {
		t.Run(tt.name, func(t *testing.T) {
			m, err := ebpf.LoadPinnedMap(bpf.MapPath(logger, tt.name), nil)
			require.NoError(t, err)
			t.Cleanup(func() {
				require.NoError(t, m.Close())
			})

			require.Equal(t, tt.mapType, m.Type())
			require.Equal(t, tt.keySize, m.KeySize())
			require.Equal(t, tt.maxEntries, m.MaxEntries())
		})
	}

	cidrs := make([]net.IPNet, 0, 4)
	for _, cidr := range []string{
		"192.0.2.0/24",
		"192.0.2.1/32",
		"2001:db8::/64",
		"2001:db8::1/128",
	} {
		_, parsed, err := net.ParseCIDR(cidr)
		require.NoError(t, err)
		cidrs = append(cidrs, *parsed)
	}

	require.NoError(t, preFilter.Insert(1, cidrs))
	dump, revision := preFilter.Dump(nil)
	require.Equal(t, int64(2), revision)
	require.ElementsMatch(t, []string{
		"192.0.2.0/24",
		"192.0.2.1/32",
		"2001:db8::/64",
		"2001:db8::1/128",
	}, dump)

	require.NoError(t, preFilter.Delete(revision, cidrs))
	dump, revision = preFilter.Dump(nil)
	require.Equal(t, int64(3), revision)
	require.Empty(t, dump)
}
