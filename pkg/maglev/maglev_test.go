// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package maglev

import (
	"fmt"
	"strconv"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
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
