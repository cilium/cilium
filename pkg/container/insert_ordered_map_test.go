// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"math/rand/v2"
	"slices"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/require"
)

func TestInsertOrderedMap_Insert(t *testing.T) {
	err := quick.Check(func(keys []int) bool {
		if len(keys) < 1 {
			// We need some keys to test with.
			return true
		}

		m := NewInsertOrderedMap[int, int](len(keys))
		for _, k := range keys {
			m.Insert(k, k)
		}
		// Update the keys in random order. This does not affect the
		// iteration order.
		randomized := slices.Clone(keys)
		rand.Shuffle(len(randomized), func(i, j int) {
			randomized[i], randomized[j] = randomized[j], randomized[i]
		})
		for _, k := range randomized {
			m.Insert(k, k*2)
		}
		keysCopy := slices.Clone(keys)
		for k, v := range m.All() {
			expected := keys[0]
			keys = keys[1:]
			if k != expected || v != expected*2 {
				t.Logf("Unexpected order or value: key=%v (expected %v), value=%v (expected %v)",
					k, expected, v, expected*2)
				return false
			}

			v, found := m.Get(k)
			if !found {
				t.Logf("%v not found", k)
				return false
			}
			if v != k*2 {
				t.Logf("value %v not the expected %v", v, k*2)
			}
		}
		keys = keysCopy

		// Delete a random key. Ordering should not be affected and all keys are found.
		if !m.Delete(randomized[0]) {
			t.Logf("Delete did not return true")
		}
		for i, k := range keys {
			if k == randomized[0] {
				keys = slices.Delete(keys, i, i+1)
				break
			}
		}

		t.Logf("keys: %v, in map: %v\n", keys, slices.Collect(m.Keys()))

		for k := range m.Keys() {
			v, found := m.Get(k)
			if !found {
				t.Logf("%v not found", k)
				return false
			}
			expected := keys[0]
			keys = keys[1:]
			if k != expected || v != expected*2 {
				t.Logf("Unexpected order or value: key=%v (expected %v), value=%v (expected %v)",
					k, expected, v, expected*2)
				return false
			}
		}
		return true
	}, nil)
	require.NoError(t, err)
}
