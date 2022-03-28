// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package maglev

import (
	"fmt"
	"strconv"
	"testing"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/checker"
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
		for i := 0; i < bCount; i++ {
			backends = append(backends, strconv.Itoa(i))
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
	backends := []string{"one", "two", "three"}
	changesInExistingBackends := 0

	before := GetLookupTable(backends, m)
	// Remove backend "three"
	after := GetLookupTable(backends[:len(backends)-1], m)

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

func (s *MaglevTestSuite) BenchmarkGetMaglevTable(c *C) {
	backendCount := 1000
	m := uint64(131071)

	if err := Init(DefaultHashSeed, m); err != nil {
		c.Fatal(err)
	}

	backends := make([]string, 0, backendCount)
	for i := 0; i < backendCount; i++ {
		backends = append(backends, fmt.Sprintf("backend-%d", i))
	}

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		table := GetLookupTable(backends, m)
		c.Assert(len(table), Equals, int(m))
	}
	c.StopTimer()
}
