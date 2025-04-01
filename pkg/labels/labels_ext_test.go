// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestMerge(t *testing.T) {
	// Just left
	l := NewLabels(NewLabel(
		"k1", "v2", "s1",
	))
	res := Merge(l, NewLabels())
	assert.True(t, l.Equal(res))

	// Just right
	res = Merge(NewLabels(), l)
	assert.True(t, l.Equal(res))

	// Overlaps
	left := NewLabels(
		NewLabel("key1", "value1", "source1"),
		NewLabel("key2", "value3", "source4"),
	)
	right := NewLabels(
		NewLabel("key1", "value3", "source4"),
	)
	want := NewLabels(
		NewLabel("key1", "value3", "source4"),
		NewLabel("key2", "value3", "source4"),
	)
	res = Merge(left, right)
	assert.True(t, want.Equal(res))
}
