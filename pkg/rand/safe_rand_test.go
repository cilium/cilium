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

package rand

import (
	"testing"
	"time"
)

func TestIntn(t *testing.T) {
	r0 := NewSafeRand(1)
	r1 := NewSafeRand(1)

	n := 10
	for i := 0; i < 100; i++ {
		v0 := r0.Intn(n)
		v1 := r1.Intn(n)

		if v0 != v1 {
			t.Errorf("Intn() returned different values at iteration %d: %d != %d", i, v0, v1)
		}
	}
}

func TestShuffle(t *testing.T) {
	r0 := NewSafeRand(time.Now().UnixNano())

	s1 := []string{"1", "2", "3", "4", "5"}
	s2 := make([]string, len(s1))
	copy(s2, s1)

	var same int
	for retry := 0; retry < 10; retry++ {
		same = 0

		r0.Shuffle(len(s2), func(i, j int) {
			s2[i], s2[j] = s2[j], s2[i]
		})

		if len(s1) != len(s2) {
			t.Errorf("Shuffle() resulted in slices of inequal length")
		}

		for i := range s1 {
			if s1[i] == s2[i] {
				same++
			}
		}
		if same != len(s1) {
			break
		}
	}
	if same == len(s1) {
		t.Errorf("Shuffle() did not modify s2 in 10 retries")
	}
}
