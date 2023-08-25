// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maglev

import (
	"fmt"
	"strconv"
	"testing"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/loadbalancer"
)

func Test(t *testing.T) { TestingT(t) }

type MaglevTestSuite struct{}

var _ = Suite(&MaglevTestSuite{})

func (s *MaglevTestSuite) SetUpTest(c *C) {
	if err := Init(DefaultHashSeed, DefaultTableSize); err != nil {
		c.Fatal(err)
	}
}

func (s *MaglevTestSuite) TestPermutations(c *C) {
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
				c.Assert(testPerm, checker.DeepEquals, expectedPerm)
			}
		}
	}
}

func (s *MaglevTestSuite) TestBackendRemoval(c *C) {
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
			c.Assert(after[pos] == 0 || after[pos] == 1, Equals, true)
		}
	}

	// Check that count of changes of existing backends is less than
	// 1% (should be guaranteed by |backends| * 100 < M)
	c.Assert(float64(changesInExistingBackends)/float64(m)*float64(100) < 1.0, Equals, true)
}

func (s *MaglevTestSuite) TestWeightedBackendWithRemoval(c *C) {
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
			c.Assert(after[pos] == 1 || after[pos] == 2 || after[pos] == 3, Equals, true)
		}
		backendsCounter[backend]++
	}

	// Check that count of changes of existing backends is less than
	// 1% (should be guaranteed by |backends| * 100 < M)
	c.Assert(float64(changesInExistingBackends)/float64(m)*float64(100) < 1.0, Equals, true)

	// Check that each backend is present x times using following formula:
	// m / len(weightSum) * backend.Weight; e.g. 1021 / (2+13+111+10) * 13 = 97.6 => 98
	c.Assert(backendsCounter[0] == 16, Equals, true)
	c.Assert(backendsCounter[1] == 98, Equals, true)
	c.Assert(backendsCounter[2] == 832, Equals, true)
	c.Assert(backendsCounter[3] == 75, Equals, true)
}

func (s *MaglevTestSuite) BenchmarkGetMaglevTable(c *C) {
	backendCount := 1000
	m := uint64(131071)

	if err := Init(DefaultHashSeed, m); err != nil {
		c.Fatal(err)
	}

	backends := make(map[string]*loadbalancer.Backend, backendCount)
	for i := 0; i < backendCount; i++ {
		backends[fmt.Sprintf("backend-%d", i)] = &loadbalancer.Backend{Weight: 1}
	}

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		table := GetLookupTable(backends, m)
		c.Assert(len(table), Equals, int(m))
	}
	c.StopTimer()
}
