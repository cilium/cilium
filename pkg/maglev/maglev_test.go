// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maglev

import (
	"encoding/binary"
	"fmt"
	"slices"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func TestPermutations(t *testing.T) {
	lc := hivetest.Lifecycle(t)
	getExpectedPermutation := func(backends []BackendInfo, m uint64, seedMurmur uint32) []uint64 {
		if len(backends) == 0 {
			return nil
		}
		perm := make([]uint64, len(backends)*int(m))
		for i, backend := range backends {
			offset, skip := getOffsetAndSkip([]byte(backend.hashString), m, seedMurmur)
			perm[i*int(m)] = offset % m
			for j := uint64(1); j < m; j++ {
				perm[i*int(m)+int(j)] = (perm[i*int(m)+int(j-1)] + skip) % m
			}
		}
		return perm
	}
	for _, bCount := range []int{0, 1, 2, 5, 111, 222, 333, 1001} {
		backends := make([]BackendInfo, bCount)
		for i := range backends {
			backends[i] = BackendInfo{
				Addr:   mkAddr(int32(i)),
				ID:     loadbalancer.BackendID(i),
				Weight: 1,
			}
			backends[i].setHashString()
		}
		for _, m := range []uint64{251, 509, 1021} {
			cfg, err := UserConfig{
				TableSize: uint(m),
				HashSeed:  DefaultHashSeed,
			}.ToConfig()
			require.NoError(t, err, "ToConfig")
			ml := New(cfg, lc)
			require.NoError(t, err, "New")
			expectedPerm := getExpectedPermutation(backends, m, ml.SeedMurmur)
			for _, numCPU := range []int{1, 2, 3, 4, 8, 100} {
				testPerm := ml.getPermutation(backends, numCPU)
				require.Equal(t, expectedPerm, testPerm)
			}
		}
	}
}

func mkAddr(i int32) loadbalancer.L3n4Addr {
	intToAddr := func(i int32) cmtypes.AddrCluster {
		var addr [4]byte
		binary.BigEndian.PutUint32(addr[:], uint32(i))
		addrCluster, _ := cmtypes.AddrClusterFromIP(addr[:])
		return addrCluster
	}
	a := *loadbalancer.NewL3n4Addr(
		loadbalancer.TCP,
		intToAddr(i),
		uint16(i%65535),
		0)
	return a
}

func runLengthEncodeIDs(ids []loadbalancer.BackendID) string {
	if len(ids) == 0 {
		return ""
	}
	count := 1
	current := ids[0]
	var runs string
	for _, id := range ids[1:] {
		if id == current {
			count++
		} else {
			runs += fmt.Sprintf("%d(%d),", current, count)
			count = 1
			current = id
		}
	}
	runs += fmt.Sprintf("%d(%d)", current, count)
	return runs
}

func TestReproducible(t *testing.T) {
	// Use the smallest table size to keep the expected output
	// small.
	m := uint64(251)

	cfg, err := UserConfig{
		TableSize: uint(m),
		HashSeed:  DefaultHashSeed,
	}.ToConfig()
	require.NoError(t, err, "ToConfig")
	ml := New(cfg, hivetest.Lifecycle(t))

	// Run-length-encoded expected maglev table in format <id>(<count>),...
	expected := "2(5),3(1),2(3),1(1),2(2),0(1),2(1),3(1),2(1),3(1),2(1),1(1),2(7),1(1),2(14),3(1),2(1)," +
		"1(2),2(12),3(1),2(3),1(1),2(4),3(1),2(8),3(1),2(2),1(1),2(16),1(2),2(3),3(1),2(11),1(2),2(4),3(1),2(3)," +
		"1(1),2(4),3(1),2(1),0(1),1(1),2(8),1(1),2(7),1(1),2(4),3(1),2(1),3(1),2(9),1(2),2(5),1(1),2(7),3(1),2(1)," +
		"3(1),1(1),2(8),1(1),2(4),0(1),2(1),1(1),2(5),3(1),2(3),1(1),2(4),3(1),2(3),1(1),2(12),0(1),3(1),2(3),3(1)," +
		"2(4),3(1),2(2),1(1),2(7)"

	backends := []BackendInfo{
		{Addr: mkAddr(1), Weight: 2, ID: 0},
		{Addr: mkAddr(3), Weight: 13, ID: 1},
		{Addr: mkAddr(4), Weight: 111, ID: 2},
		{Addr: mkAddr(5), Weight: 10, ID: 3},
	}
	actual := runLengthEncodeIDs(ml.GetLookupTable(slices.Values(backends)))

	require.Equal(t, expected, actual)
}

func TestBackendRemoval(t *testing.T) {
	m := uint(1021) // 3 (backends) * 100 should be less than M
	cfg, err := UserConfig{
		TableSize: uint(m),
		HashSeed:  DefaultHashSeed,
	}.ToConfig()
	require.NoError(t, err, "ToConfig")
	ml := New(cfg, hivetest.Lifecycle(t))
	require.NoError(t, err, "New")
	changesInExistingBackends := 0

	backends := []BackendInfo{
		{ID: 1, Weight: 1, Addr: mkAddr(1)},
		{ID: 2, Weight: 1, Addr: mkAddr(2)},
		{ID: 3, Weight: 1, Addr: mkAddr(3)},
	}
	before := ml.GetLookupTable(slices.Values(backends))

	// Remove the last backend
	backends = backends[:2]

	after := ml.GetLookupTable(slices.Values(backends))

	for pos, backend := range before {
		if (backend == 1 || backend == 2) && after[pos] != before[pos] {
			changesInExistingBackends++
		} else {
			// Check that backend 3 was now replaced by either 1 or 2.
			require.True(t, after[pos] == 1 || after[pos] == 2)
		}
	}

	// Check that count of changes of existing backends is less than
	// 1% (should be guaranteed by |backends| * 100 < M)
	require.Less(t, float64(changesInExistingBackends)/float64(m)*float64(100), 1.0)
}

func TestWeightedBackendWithRemoval(t *testing.T) {
	m := uint(1021) // 4 (backends) * 100 is still less than M
	cfg, err := UserConfig{
		TableSize: uint(m),
		HashSeed:  DefaultHashSeed,
	}.ToConfig()
	ml := New(cfg, hivetest.Lifecycle(t))
	require.NoError(t, err, "New")

	changesInExistingBackends := 0
	// using following formula we can get the approximate number of times
	// the backendID is found in the computed lut
	// m / len(weightSum) * backend.Weight
	backends := []BackendInfo{
		{ID: 1, Weight: 2, Addr: mkAddr(1)},
		{ID: 2, Weight: 13, Addr: mkAddr(2)},
		{ID: 3, Weight: 111, Addr: mkAddr(3)},
		{ID: 4, Weight: 10, Addr: mkAddr(4)},
	}

	backendsCounter := make(map[loadbalancer.BackendID]uint64, len(backends))

	before := ml.GetLookupTable(slices.Values(backends))

	// Again without first backend. It's weight is
	// 2 / (2+13+111+10) = 0.014 ~= 1.4% of total weight.
	after := ml.GetLookupTable(slices.Values(backends[1:]))

	for pos, backend := range before {
		// count how many times backend position changed, take into consideration
		// that IDs are decreased by 1 in the "after" lut
		if (backend == 2 || backend == 3 || backend == 4) && after[pos] != before[pos] {
			changesInExistingBackends++
		} else {
			require.True(t, after[pos] == 2 || after[pos] == 3 || after[pos] == 4)
		}
		backendsCounter[backend]++
	}

	// Check that count of changes of existing backends is less than
	// 1% (should be guaranteed by |backends| * 100 < M)
	require.Less(t, float64(changesInExistingBackends)/float64(m)*float64(100), 1.0)

	// Check that each backend is present x times using following formula:
	// m / len(weightSum) * backend.Weight; e.g. 1021 / (2+13+111+10) * 13 = 97.6 => 98
	require.EqualValues(t, 16, backendsCounter[1])
	require.EqualValues(t, 98, backendsCounter[2])
	require.EqualValues(t, 832, backendsCounter[3])
	require.EqualValues(t, 75, backendsCounter[4])
}

func BenchmarkGetMaglevTable(b *testing.B) {
	for _, m := range []uint64{2039, 4093, 16381, 131071} {
		b.Run(fmt.Sprintf("%d", m), func(b *testing.B) {
			benchmarkGetMaglevTable(b, m)
		})
	}
}

func benchmarkGetMaglevTable(b *testing.B, m uint64) {
	backendCount := 1000
	cfg, err := UserConfig{
		TableSize: uint(m),
		HashSeed:  DefaultHashSeed,
	}.ToConfig()
	require.NoError(b, err, "ToConfig")
	ml := New(cfg, hivetest.Lifecycle(b))

	// Preallocate the info buffer to not skew the allocation count.
	ml.backendInfosBuffer = make([]BackendInfo, 0, 1024)

	backends := make([]BackendInfo, backendCount)
	for i := range backendCount {
		backends[i] = BackendInfo{ID: loadbalancer.BackendID(i), Weight: 1, Addr: mkAddr(int32(i))}
		// Already compute hash string so we compare apples-to-apples to prev benchmarks. Previously
		// the backends were passed in as map[string]*Backend so these strings precomputed.
		backends[i].setHashString()
	}

	for b.Loop() {
		table := ml.GetLookupTable(slices.Values(backends))
		require.Len(b, table, int(m))
	}
	b.StopTimer()
}
