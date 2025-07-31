// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package analyze

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBitmap(t *testing.T) {
	b := newBitmap(100)

	for i := range uint64(100) {
		b.set(i, i%2 == 0)
	}

	for i := range uint64(100) {
		expected := i%2 == 0
		assert.Equal(t, expected, b.get(i))
	}

	b.set(200, true)
	assert.False(t, b.get(200))
}
