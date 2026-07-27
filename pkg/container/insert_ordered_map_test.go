// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"maps"
	"math/rand/v2"
	"slices"
	"testing"
	"testing/quick"

	"github.com/stretchr/testify/require"
)

func TestInsertOrderedMap_Empty(t *testing.T) {
	m := NewInsertOrderedMap[int, int]()
	require.Empty(t, maps.Collect(m.All()), "All()")
	require.Empty(t, slices.Collect(m.Keys()), "Keys()")
	require.Empty(t, slices.Collect(m.Values()), "Values()")
	_, found := m.Get(0)
	require.False(t, found, "Get")
	found = m.Delete(0)
	require.False(t, found, "Delete")
	m.Clear()
}

func TestInsertOrderedMap_Insert(t *testing.T) {
	m := NewInsertOrderedMap[int, string]()
	m.Insert(1, "1")
	m.Insert(2, "2")
	m.Insert(3, "3")
	m.Insert(3, "3-3")
	m.Insert(2, "2-2")
	m.Insert(1, "1-1")
	require.Equal(t, []int{1, 2, 3}, slices.Collect(m.Keys()))
	require.Equal(t, []string{"1-1", "2-2", "3-3"}, slices.Collect(m.Values()))
	require.Equal(t, 3, m.Len(), "Len()")
	m.Clear()
}

func TestInsertOrderedMap_Quick(t *testing.T) {
	err := quick.Check(func(keys []int) bool {
		if len(keys) < 1 {
			// We need some keys to test with.
			return true
		}

		m := NewInsertOrderedMap[int, int]()
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
		numUnique := 0
		for k, v := range m.All() {
			numUnique++
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
		if m.Len() != numUnique {
			t.Logf("Len() returned %d, expected %d", m.Len(), numUnique)
			return false
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
