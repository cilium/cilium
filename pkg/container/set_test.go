// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package container

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/exp/slices"
)

func TestSet(t *testing.T) {
	assertSlice := func(s Set[int], items []int) {
		xs := s.Slice()
		slices.Sort(xs)
		assert.True(t, slices.Equal(xs, items))
	}

	s1 := NewSet[int]() // []

	assert.True(t, s1.Empty())
	assert.Zero(t, s1.Len())
	assert.False(t, s1.Contains(1))

	s1.Add(1) // [1]
	assert.False(t, s1.Empty())
	assert.Equal(t, 1, s1.Len())
	assert.True(t, s1.Contains(1))

	s2 := s1.Clone() // [1]
	s2.Delete(1)     // []
	assert.False(t, s2.Contains(1))
	assert.True(t, s1.Contains(1))

	s3 := NewSet(1, 2, 3) // [1,2,3]
	assert.Equal(t, 3, s3.Len())
	assertSlice(s3, []int{1, 2, 3})

	for i := 1; i <= 3; i++ {
		assert.True(t, s3.Contains(i))
	}

	s2.Add(4)    // [4]
	s2.Union(s3) // [4] U [1,2,3] => [1,2,3,4]
	assertSlice(s2, []int{1, 2, 3, 4})

	s2.Sub(s1) // [1,2,3,4] -- [1] => [2,3,4]
	assertSlice(s2, []int{2, 3, 4})
}
