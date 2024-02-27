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

func TestImmSetUnion(t *testing.T) {
	// Overlapping sets
	s1 := NewImmSet(1, 2, 3)
	assert.Equal(t, 3, s1.Len(), "expected length of 3 for initialized set")
	assert.True(t, s1.Has(1), "expected value 1 to be in the set")
	assert.True(t, s1.Has(2), "expected value 2 to be in the set")
	assert.True(t, s1.Has(3), "expected value 3 to be in the set")
	assert.False(t, s1.Has(4), "expected value 4 to not be in the set")

	s2 := NewImmSet(3, 4, 5)
	assert.Equal(t, 3, s2.Len(), "expected length of 3 for initialized set")
	assert.False(t, s2.Has(1), "expected value 1 to not be in the set")
	assert.True(t, s2.Has(3), "expected value 3 to be in the set")
	assert.True(t, s2.Has(4), "expected value 4 to be in the set")
	assert.True(t, s2.Has(5), "expected value 5 to be in the set")

	s3 := s1.Union(s2)
	assert.Equal(t, 5, s3.Len(), "expected length of 5 for the union set")
	assert.True(t, s3.Has(1), "expected value 1 to be in the set")
	assert.True(t, s3.Has(2), "expected value 2 to be in the set")
	assert.True(t, s3.Has(3), "expected value 3 to be in the set")
	assert.True(t, s3.Has(4), "expected value 4 to be in the set")
	assert.True(t, s3.Has(5), "expected value 5 to be in the set")

	// Disjoint sets
	s4 := NewImmSet(1, 2)
	assert.Equal(t, 2, s4.Len(), "expected length of 2 for initialized set")
	assert.True(t, s4.Has(1), "expected value 1 to be in the set")
	assert.True(t, s4.Has(2), "expected value 2 to be in the set")
	assert.False(t, s4.Has(3), "expected value 3 to not be in the set")

	s5 := NewImmSet(3, 4)
	assert.Equal(t, 2, s5.Len(), "expected length of 2 for initialized set")
	assert.False(t, s5.Has(1), "expected value 1 to not be in the set")
	assert.True(t, s5.Has(3), "expected value 3 to be in the set")
	assert.True(t, s5.Has(4), "expected value 4 to be in the set")

	s6 := s4.Union(s5)
	assert.Equal(t, 4, s6.Len(), "expected length of 4 for the union set")
	assert.True(t, s6.Has(1), "expected value 1 to be in the set")
	assert.True(t, s6.Has(2), "expected value 2 to be in the set")
	assert.True(t, s6.Has(3), "expected value 3 to be in the set")
	assert.True(t, s6.Has(4), "expected value 4 to be in the set")
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
