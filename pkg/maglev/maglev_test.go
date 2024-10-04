// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maglev

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

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
	backendCount := 1000
	m := uint64(131071)

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
