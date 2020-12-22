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

package murmur3

import (
	"math/rand"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type MM3Suite struct{}

var _ = Suite(&MM3Suite{})

// TestMurmur3_128_x64 tests against the reference implementation of
// the murmur3 128-bit x64.
func (s *MM3Suite) TestMurmur3_128_x64(c *C) {
	for len := 0; len < 1000; len++ {
		for i := 0; i < 100; i++ {
			seed := rand.Uint32()
			data := make([]byte, len)
			rand.Read(data)
			h1, h2 := Hash128(data, seed)
			h1Ref, h2Ref := hash128Ref(data, seed)
			if h1 != h1Ref || h2 != h2Ref {
				c.Errorf("Hash mismatch %v %x %x!=%x || %x!=%x\n", data, seed,
					h1, h1Ref, h2, h2Ref)
			}
		}
	}
}
