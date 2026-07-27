// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitmap(t *testing.T) {
	b := NewBitmap(100)

	for i := range uint64(100) {
		b.Set(i, i%2 == 0)
	}

	for i := range uint64(100) {
		expected := i%2 == 0
		assert.Equal(t, expected, b.Get(i))
	}

	b.Set(200, true)
	assert.False(t, b.Get(200))
}
