// Copyright 2019 Authors of Cilium
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

package lbmap

import (
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"sort"
	"testing"
)

func TestMaglevHash(t *testing.T) {
	var (
		nreals    = 400
		endpoints []*lb.BackendMeta
		freq      = make([]int, nreals)
	)

	for i := 0; i < nreals; i++ {
		endpoints = append(endpoints, &lb.BackendMeta{
			ID: lb.BackendID(i),
			BackendMaglev: &lb.BackendMaglev{
				Hash:   uint64(i),
				Weight: 1,
			},
		})
	}

	maglevRing := generateMaglevHash(endpoints, DefaultMaglevRingSize)

	for i := range maglevRing {
		// test that we have changed all points inside ch ring
		if maglevRing[i] == -1 {
			t.Fatalf("maglevRing[%v] is -1", i)
		}
		freq[maglevRing[i]]++
	}

	sort.Ints(freq)

	diff := freq[len(freq)-1] - freq[0]
	// testing that when weights are equal and = 1 the diff
	// between max and min frequency is 1 as maglev's doc
	// promised
	if diff != 1 {
		t.Fatalf("diff %v is not 1", diff)
	}
	t.Logf("freq %v", freq)
}
