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
