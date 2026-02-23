// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cookie

import (
	"fmt"
	"math"
	"math/rand/v2"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
)

func TestBakery(t *testing.T) {
	b := NewBakery[uint32, string](hivetest.Logger(t))
	assert.Equal(t, 0, b.Count())

	value, ok := b.Get(rand.Uint32())
	assert.False(t, ok)
	assert.Empty(t, value)

	key1 := "foo"
	cookie1, ok := b.Allocate(key1)
	assert.NotZero(t, cookie1)
	assert.True(t, ok)
	assert.Equal(t, 1, b.Count())

	value, ok = b.Get(cookie1)
	assert.True(t, ok)
	assert.Equal(t, value, key1)

	sameCookie, ok := b.Allocate(key1)
	assert.NotZero(t, cookie1)
	assert.True(t, ok)
	assert.Equal(t, sameCookie, cookie1)
	assert.Equal(t, 1, b.Count())

	key2 := "bar"
	cookie2, ok := b.Allocate(key2)
	assert.NotZero(t, cookie2)
	assert.True(t, ok)
	assert.NotEqual(t, cookie2, cookie1)
	assert.Equal(t, 2, b.Count())

	// 1. Generation
	b.Sweep()
	value, ok = b.Get(cookie1)
	assert.True(t, ok)
	assert.Equal(t, value, key1)
	value, ok = b.Get(cookie2)
	assert.True(t, ok)
	assert.Equal(t, value, key2)

	b.MarkInUse(cookie2)

	// 2. Generation
	b.Sweep()
	value, ok = b.Get(cookie1)
	assert.False(t, ok)
	assert.Empty(t, value)
	value, ok = b.Get(cookie2)
	assert.True(t, ok)
	assert.Equal(t, value, key2)
	assert.Equal(t, 1, b.Count())

	// 3. Generation
	b.Sweep()
	value, ok = b.Get(cookie1)
	assert.False(t, ok)
	assert.Empty(t, value)
	value, ok = b.Get(cookie2)
	assert.False(t, ok)
	assert.Empty(t, value)
	assert.Equal(t, 0, b.Count())
}

func TestBakeryAllocationBounds(t *testing.T) {
	b := NewBakery[uint8, string](hivetest.Logger(t))

	for i := range math.MaxUint8 {
		cookie, ok := b.Allocate(fmt.Sprintf("key%d", i))
		assert.NotZero(t, cookie, "could not allocate %dth cookie", i)
		assert.True(t, ok)
	}

	cookie, ok := b.Allocate(fmt.Sprintf("key%d", math.MaxUint8))
	assert.Zero(t, cookie)
	assert.False(t, ok)
}
