// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maglev

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

type MaglevTestSuite struct{}

func setupMaglevTestSuite(tb testing.TB) *MaglevTestSuite {
	s := &MaglevTestSuite{}

	err := Init(DefaultHashSeed, DefaultTableSize)
	require.NoError(tb, err)

	return s
}

func TestPermutations(t *testing.T) {
	setupMaglevTestSuite(t)

	getExpectedPermutation := func(backends []string, m uint64) []uint64 {
		perm := make([]uint64, len(backends)*int(m))
		for i, backend := range backends {
			offset, skip := getOffsetAndSkip(backend, m)
			perm[i*int(m)] = offset % m
			for j := uint64(1); j < m; j++ {
				perm[i*int(m)+int(j)] = (perm[i*int(m)+int(j-1)] + skip) % m
			}
		}
		return perm
	}
	for _, bCount := range []int{0, 1, 2, 5, 111, 222, 333, 1001} {
		backends := make([]string, bCount)
		for i := 0; i < len(backends); i++ {
			backends[i] = strconv.Itoa(i)
		}
		for _, m := range []uint64{251, 509, 1021} {
			expectedPerm := getExpectedPermutation(backends, m)
			for _, numCPU := range []int{1, 2, 3, 4, 8, 100} {
				testPerm := getPermutation(backends, m, numCPU)
				require.EqualValues(t, expectedPerm, testPerm)
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

func runLengthEncodeIDs(ids []int) string {
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
	setupMaglevTestSuite(t)

	// Run-length-encoded expected maglev table in format <id>(<count>),...
	expected := "2(5),3(1),2(3),1(1),2(2),0(1),2(1),3(1),2(1),3(1),2(1),1(1),2(7),1(1),2(14),3(1),2(1)," +
		"1(2),2(12),3(1),2(3),1(1),2(4),3(1),2(8),3(1),2(2),1(1),2(16),1(2),2(3),3(1),2(11),1(2),2(4),3(1),2(3)," +
		"1(1),2(4),3(1),2(1),0(1),1(1),2(8),1(1),2(7),1(1),2(4),3(1),2(1),3(1),2(9),1(2),2(5),1(1),2(7),3(1),2(1)," +
		"3(1),1(1),2(8),1(1),2(4),0(1),2(1),1(1),2(5),3(1),2(3),1(1),2(4),3(1),2(3),1(1),2(12),0(1),3(1),2(3),3(1)," +
		"2(4),3(1),2(2),1(1),2(7)"

	// Use the smallest table size to keep the expected output
	// small.
	m := uint64(251)

	backends := []*loadbalancer.Backend{
		{L3n4Addr: mkAddr(1), Weight: 2, ID: 0},
		{L3n4Addr: mkAddr(3), Weight: 13, ID: 1},
		{L3n4Addr: mkAddr(4), Weight: 111, ID: 2},
		{L3n4Addr: mkAddr(5), Weight: 10, ID: 3},
	}
	backendsMap := map[string]*loadbalancer.Backend{}
	for _, be := range backends {
		backendsMap[be.String()] = be
	}

	actual := runLengthEncodeIDs(GetLookupTable(backendsMap, m))

	require.Equal(t, expected, actual)
}

func TestBackendRemoval(t *testing.T) {
	setupMaglevTestSuite(t)

	m := uint64(1021) // 3 (backends) * 100 should be less than M
	changesInExistingBackends := 0

	backendsMap := map[string]*loadbalancer.Backend{
		"one":   {Weight: 1, ID: 0},
		"three": {Weight: 1, ID: 1},
		"two":   {Weight: 1, ID: 2},
	}
	before := GetLookupTable(backendsMap, m)

	// Remove backend "two"
	delete(backendsMap, "two")
	after := GetLookupTable(backendsMap, m)

	for pos, backend := range before {
		if (backend == 0 || backend == 1) && after[pos] != before[pos] {
			changesInExistingBackends++
		} else {
			// Check that "three" placement was overridden by "one" or "two"
			require.True(t, after[pos] == 0 || after[pos] == 1)
		}
	}

	// Check that count of changes of existing backends is less than
	// 1% (should be guaranteed by |backends| * 100 < M)
	require.Less(t, float64(changesInExistingBackends)/float64(m)*float64(100), 1.0)
}

func TestWeightedBackendWithRemoval(t *testing.T) {
	setupMaglevTestSuite(t)

	m := uint64(1021) // 4 (backends) * 100 is still less than M
	changesInExistingBackends := 0

	// using following formula we can get the approximate number of times
	// the backendID is found in the computed lut
	// m / len(weightSum) * backend.Weight
	backendsMap := map[string]*loadbalancer.Backend{
		"one":   {Weight: 2, ID: 0},   // approx. 15x times
		"three": {Weight: 13, ID: 1},  // approx. 97.5x times
		"two":   {Weight: 111, ID: 2}, // approx. 833x times
		"tzwe":  {Weight: 10, ID: 3},  // approx. 75x times
	}

	backendsCounter := make(map[int]uint64, len(backendsMap))

	before := GetLookupTable(backendsMap, m)

	// Remove the backend "one"
	delete(backendsMap, "one")
	after := GetLookupTable(backendsMap, m)

	for pos, backend := range before {
		// count how many times backend position changed, take into consideration
		// that IDs are decreased by 1 in the "after" lut
		if (backend == 1 || backend == 2 || backend == 3) && after[pos] != before[pos] {
			changesInExistingBackends++
		} else {
			// Check that there is no ID 0 as backend "one" with ID 0 has been removed
			require.True(t, after[pos] == 1 || after[pos] == 2 || after[pos] == 3)
		}
		backendsCounter[backend]++
	}

	// Check that count of changes of existing backends is less than
	// 1% (should be guaranteed by |backends| * 100 < M)
	require.Less(t, float64(changesInExistingBackends)/float64(m)*float64(100), 1.0)

	// Check that each backend is present x times using following formula:
	// m / len(weightSum) * backend.Weight; e.g. 1021 / (2+13+111+10) * 13 = 97.6 => 98
	require.EqualValues(t, 16, backendsCounter[0])
	require.EqualValues(t, 98, backendsCounter[1])
	require.EqualValues(t, 832, backendsCounter[2])
	require.EqualValues(t, 75, backendsCounter[3])
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

	if err := Init(DefaultHashSeed, m); err != nil {
		b.Fatal(err)
	}

	backends := make(map[string]*loadbalancer.Backend, backendCount)
	for i := 0; i < backendCount; i++ {
		backends[fmt.Sprintf("backend-%d", i)] = &loadbalancer.Backend{Weight: 1}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		table := GetLookupTable(backends, m)
		require.Len(b, table, int(m))
	}
	b.StopTimer()
}
