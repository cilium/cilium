// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestImmSetFunc(t *testing.T) {
	// Test the ImmSet with netip.Addr.
	a1, a2, a3 := netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("2.2.2.2"), netip.MustParseAddr("3.3.3.3")

	// Empty set
	s := NewImmSetFunc[netip.Addr](netip.Addr.Compare)
	assert.Equal(t, 0, s.Len(), "expected 0 len for empty set")
	assert.True(t, s.Equal(s), "expected empty set to equal itself")

	s = s.Insert(a1)
	assert.Equal(t, 1, s.Len(), "expected length of 1 after Insert")
	s = s.Insert(a2)
	assert.Equal(t, 2, s.Len(), "expected length of 2 after second Insert")
	assert.ElementsMatch(t, s.AsSlice(), []netip.Addr{a1, a2})

	s1 := s.Delete(a2)
	assert.Equal(t, 2, s.Len(), "expected length of 2 for original")
	assert.Equal(t, 1, s1.Len(), "expected length of 1 after Delete")

	// Initialized set
	s2 := NewImmSetFunc[netip.Addr](netip.Addr.Compare, a1, a2, a3)
	assert.Equal(t, 3, s2.Len(), "expected length of 3 for initialized set")

	s2 = s2.Difference(s)
	assert.Equal(t, 1, s2.Len(), "expected length of 1 after diff")
	assert.ElementsMatch(t, s2.AsSlice(), []netip.Addr{a3})

	s2 = s2.Delete(a2 /* no-op */, a3)
	assert.Equal(t, 0, s2.Len(), "expected length of 0 after final delete")

	s2 = s2.Delete(a3)
	assert.Equal(t, 0, s2.Len(), "expected no change in length after nop delete")
}

func TestImmSet(t *testing.T) {
	// Empty set
	s := NewImmSet[int]()
	assert.Equal(t, 0, s.Len(), "expected 0 len for empty set")
	assert.True(t, s.Equal(s), "expected empty set to equal itself")

	s = s.Insert(1)
	assert.Equal(t, 1, s.Len(), "expected length of 1 after Insert")
	s = s.Insert(2)
	assert.Equal(t, 2, s.Len(), "expected length of 2 after second Insert")
	assert.ElementsMatch(t, s.AsSlice(), []int{1, 2})

	s1 := s.Delete(2)
	assert.Equal(t, 2, s.Len(), "expected length of 2 for original")
	assert.Equal(t, 1, s1.Len(), "expected length of 1 after Delete")

	// Initialized set
	s2 := NewImmSet[int](1, 2, 3)
	assert.Equal(t, 3, s2.Len(), "expected length of 3 for initialized set")

	s2 = s2.Difference(s)
	assert.Equal(t, 1, s2.Len(), "expected length of 1 after diff")
	assert.ElementsMatch(t, s2.AsSlice(), []int{3})

	s2 = s2.Delete(2 /* no-op */, 3)
	assert.Equal(t, 0, s2.Len(), "expected length of 0 after final delete")

	s2 = s2.Delete(3)
	assert.Equal(t, 0, s2.Len(), "expected no change in length after nop delete")
}

func benchmarkImmSetInsert(b *testing.B, numItems int) {
	s := NewImmSet[int]()
	for i := 0; i < numItems; i++ {
		s = s.Insert(i)
	}
	for n := 0; n < b.N; n++ {
		s.Insert(numItems)
	}
}

func BenchmarkImmSetInsert_100(b *testing.B)   { benchmarkImmSetInsert(b, 100) }
func BenchmarkImmSetInsert_1000(b *testing.B)  { benchmarkImmSetInsert(b, 1000) }
func BenchmarkImmSetInsert_10000(b *testing.B) { benchmarkImmSetInsert(b, 10000) }

func benchmarkImmSetDelete(b *testing.B, numItems int) {
	s := NewImmSet[int]()
	for i := 0; i < numItems; i++ {
		s = s.Insert(i)
	}
	idx := rand.IntN(numItems)
	b.ResetTimer()

	for n := 0; n < b.N; n++ {
		s.Delete(idx)
	}
}

func BenchmarkImmSetDelete_100(b *testing.B)   { benchmarkImmSetDelete(b, 100) }
func BenchmarkImmSetDelete_1000(b *testing.B)  { benchmarkImmSetDelete(b, 1000) }
func BenchmarkImmSetDelete_10000(b *testing.B) { benchmarkImmSetDelete(b, 10000) }
