// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"context"
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/maps"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

// newTestRegistry returns a started MapRegistry with the policy maps configured
// the way the agent does it.
func newTestRegistry(tb testing.TB, maxEntries uint32) (*registry.MapRegistry, *StatsMap) {
	var reg *registry.MapRegistry
	var stats *StatsMap
	h := hive.New(
		registry.Cell,
		cell.Config(PolicyConfig{
			BpfPolicyMapMax:      int(maxEntries),
			BpfPolicyStatsMapMax: int(maxEntries),
		}),
		cell.Provide(newStatsMap),
		cell.Provide(createFactory),
		cell.Invoke(configurePolicyMaps),
		cell.Invoke(func(r *registry.MapRegistry, s *StatsMap) {
			reg = r
			stats = s
		}),
	)

	logger := hivetest.Logger(tb)
	require.NoError(tb, h.Start(logger, context.TODO()))
	tb.Cleanup(func() { require.NoError(tb, h.Stop(logger, context.TODO())) })

	return reg, stats
}

func setupPolicyMapPrivilegedTestSuite(tb testing.TB) PolicyMap {
	testutils.PrivilegedTest(tb)

	logger := hivetest.Logger(tb)
	bpf.CheckOrMountFS(logger, "")

	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatal(err)
	}

	const testMapSize uint32 = 1024
	reg, stats := newTestRegistry(tb, testMapSize)
	require.NotNil(tb, stats)

	policySpec, err := reg.Get(maps.CiliumPolicy)
	require.NoError(tb, err)
	require.Equal(tb, testMapSize, policySpec.MaxEntries)
	statsSpec, err := reg.Get(maps.CiliumPolicystats)
	require.NoError(tb, err)
	require.Equal(tb, testMapSize, statsSpec.MaxEntries)

	testMap, err := newPolicyMap(0, reg, stats)
	require.NoError(tb, err)
	require.NotNil(tb, testMap)

	_ = os.RemoveAll(bpf.LocalMapPath(logger, MapName, 0))
	err = testMap.CreateUnpinned()
	require.NoError(tb, err)

	tb.Cleanup(func() {
		err := testMap.DeleteAll()
		require.NoError(tb, err)
	})

	return testMap
}

func TestPrivilegedPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := newKey(1, 1, 1, 1, SinglePortPrefixLen)
	entry := newAllowEntry(fooKey, 42, 0)
	err := testMap.Update(&fooKey, &entry)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.Equal(t, fooKey, dump[0].Key)

	require.Equal(t, policyTypes.Precedence(42), dump[0].PolicyEntry.Precedence)

	// Special case: allow-all entry
	barKey := newKey(0, 0, 0, 0, 0)
	barEntry := newAllowEntry(barKey, 0, 0)
	err = testMap.Update(&barKey, &barEntry)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}

func TestPrivilegedDeleteNonexistentKey(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)
	key := newKey(trafficdirection.Ingress, 27, u8proto.TCP, 80, SinglePortPrefixLen)
	err := testMap.DeleteKey(key)
	require.Error(t, err)
	var errno unix.Errno
	require.ErrorAs(t, err, &errno)
	require.Equal(t, unix.ENOENT, errno)
}

func TestPrivilegedDenyPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := newKey(1, 1, 1, 1, SinglePortPrefixLen)
	fooEntry := newDenyEntry(fooKey, 321)
	err := testMap.Update(&fooKey, &fooEntry)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.Equal(t, fooKey, dump[0].Key)
	require.Equal(t, fooEntry, dump[0].PolicyEntry)

	// Special case: deny-all entry
	barKey := newKey(0, 0, 0, 0, 0)
	barEntry := newDenyEntry(barKey, 0)
	err = testMap.Update(&barKey, &barEntry)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}
