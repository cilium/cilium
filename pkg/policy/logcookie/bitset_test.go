// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package logcookie

import (
	"fmt"
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitset(t *testing.T) {
	b := newBitset(math.MaxUint32)

	assert.Equal(t, b.Count(), uint(0))
	assert.Equal(t, b.Cap(), uint(math.MaxUint32))

	seenBits := make(map[uint]struct{})

	for i := range 100 {
		bit, ok := b.Allocate()
		assert.True(t, ok)
		assert.Equal(t, b.Count(), uint(i+1))
		assert.Equal(t, b.Cap(), uint(math.MaxUint32-i-1))

		_, seen := seenBits[bit]
		assert.False(t, seen, fmt.Sprintf("seen bit %d more than once", bit))
		seenBits[bit] = struct{}{}
	}
}
