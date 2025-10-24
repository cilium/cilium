// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policymap

import (
	"os"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/maps/registry"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	policyTypes "github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/u8proto"
)

const (
	testMapSize = 1024
)

func createStatsMapForTest(tb testing.TB, maxStatsEntries int) (*StatsMap, error) {
	lc := cell.NewDefaultLifecycle(nil, 0, 0)
	reg, err := registry.NewMapSpecRegistry(lc)
	require.NoError(tb, err)

	log := hivetest.Logger(tb)
	require.NoError(tb, err)

	err = reg.ModifyMapSpec(StatsMapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(calcMaxStatsEntries(testMapSize, log))
		return nil
	})
	require.NoError(tb, err)

	err = lc.Start(log, tb.Context())
	require.NoError(tb, err)

	spec, err := reg.Get(StatsMapName)
	if err != nil {
		return nil, err
	}
	m := &StatsMap{Map: ebpf.NewMap(log, spec), log: log}
	return m, m.OpenOrCreate()
}

func setupPolicyMapPrivilegedTestSuite(tb testing.TB) *PolicyMap {
	testutils.PrivilegedTest(tb)

	logger := hivetest.Logger(tb)
	bpf.CheckOrMountFS(logger, "")

	if err := rlimit.RemoveMemlock(); err != nil {
		tb.Fatal(err)
	}

	stats, err := createStatsMapForTest(tb, testMapSize)
	require.NoError(tb, err)
	require.NotNil(tb, stats)

	lc := cell.NewDefaultLifecycle(nil, 0, 0)
	reg, err := registry.NewMapSpecRegistry(lc)
	require.NoError(tb, err)

	err = reg.ModifyMapSpec(MapName, func(spec *ebpf.MapSpec) error {
		spec.MaxEntries = uint32(testMapSize)
		spec.Flags = bpf.GetMapMemoryFlags(spec.Type)
		return nil
	})

	err = lc.Start(logger, tb.Context())
	require.NoError(tb, err)

	testMap, err := newPolicyMap(logger, reg, 0, stats)
	require.NoError(tb, err)
	require.NotNil(tb, testMap)

	_ = os.RemoveAll(bpf.LocalMapPath(logger, MapNamePrefix, 0))
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
	entry := newAllowEntry(fooKey, 42, policyTypes.AuthTypeSpire.AsDerivedRequirement(), 0)
	// err := testMap.AllowKey(fooKey, 42, policyTypes.AuthTypeSpire.AsDerivedRequirement(), 0)
	err := testMap.Update(&fooKey, &entry)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.Equal(t, fooKey, dump[0].Key)

	require.False(t, dump[0].PolicyEntry.AuthRequirement.IsExplicit())
	require.Equal(t, policyTypes.AuthType(1), dump[0].PolicyEntry.AuthRequirement.AuthType())
	require.Equal(t, policyTypes.ProxyPortPriority(42), dump[0].PolicyEntry.ProxyPortPriority)

	// Special case: allow-all entry
	barKey := newKey(0, 0, 0, 0, 0)
	barEntry := newAllowEntry(barKey, 0, policyTypes.AuthRequirement(0), 0)
	err = testMap.Update(&barKey, &barEntry)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}

func TestPrivilegedDeleteNonexistentKey(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)
	key := newKey(trafficdirection.Ingress, 27, u8proto.TCP, 80, SinglePortPrefixLen)
	err := testMap.Map.Delete(&key)
	require.Error(t, err)
	var errno unix.Errno
	require.ErrorAs(t, err, &errno)
	require.Equal(t, unix.ENOENT, errno)
}

func TestPrivilegedDenyPolicyMapDumpToSlice(t *testing.T) {
	testMap := setupPolicyMapPrivilegedTestSuite(t)

	fooKey := newKey(1, 1, 1, 1, SinglePortPrefixLen)
	fooEntry := newDenyEntry(fooKey)
	err := testMap.Update(&fooKey, &fooEntry)
	require.NoError(t, err)

	dump, err := testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 1)

	require.Equal(t, fooKey, dump[0].Key)
	require.Equal(t, fooEntry, dump[0].PolicyEntry)

	// Special case: deny-all entry
	barKey := newKey(0, 0, 0, 0, 0)
	barEntry := newDenyEntry(barKey)
	err = testMap.Update(&barKey, &barEntry)
	require.NoError(t, err)

	dump, err = testMap.DumpToSlice()
	require.NoError(t, err)
	require.Len(t, dump, 2)
}
