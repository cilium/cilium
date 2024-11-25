// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLabels_Small(t *testing.T) {
	testNewLabels(t, smallLabelsSize)
}

func TestNewLabels_Large(t *testing.T) {
	testNewLabels(t, 3*smallLabelsSize)
}

func testNewLabels(t *testing.T, n int) {
	testLabels := []Label{}
	mapLabels := map[string]string{}
	expectedStrings := []string{}
	for i := range n {
		s := fmt.Sprintf("%04d", i) // pad with zeros for sorted order
		k := "key" + s
		v := "value" + s
		l := NewLabel(k, v, "source"+s)
		mapLabels[k] = v
		testLabels = append(testLabels, l)
		expectedStrings = append(expectedStrings, l.String())
	}
	expectedString := strings.Join(expectedStrings, ",")

	// Test NewLabels, with the labels in sorted and unsorted order.
	lbls1 := NewLabels(testLabels...)
	assert.Equal(t, n, lbls1.Len())
	slices.Reverse(testLabels)
	lbls2 := NewLabels(testLabels...)
	assert.Equal(t, n, lbls2.Len())
	assert.True(t, lbls1.Equal(lbls2), "Equal")

	for _, l := range testLabels {
		lx, found := lbls1.Get(l.Key())
		assert.True(t, found, "lbls1.Get(%s)", l.Key())
		assert.Equal(t, l, lx)

		lx, found = lbls2.Get(l.Key())
		assert.True(t, found, "lbls2.Get(%s)", l.Key())
		assert.Equal(t, l, lx)
	}
	assert.Equal(t, expectedString, lbls1.String(), "lbls1.String")
	assert.Equal(t, expectedString, lbls2.String(), "lbls2.String")

	// Test Map2Labels
	lbls3 := Map2Labels(mapLabels, "src")
	assert.Equal(t, n, lbls3.Len())
	for _, l := range testLabels {
		lx, found := lbls3.Get(l.Key())
		assert.True(t, found, "lbls3.Get(%s)", l.Key())
		assert.Equal(t, l.Key(), lx.Key())
		assert.Equal(t, l.Value(), lx.Value())
		assert.Equal(t, "src", lx.Source())
	}
	// Test StringMap
	strmap := lbls3.StringMap()
	assert.Equal(t, len(strmap), n)
	for l := range lbls3.All() {
		v, found := strmap[l.Source()+":"+l.Key()]
		assert.True(t, found, "strmap[%s]", l.String())
		assert.Equal(t, l.Value(), v, "values equal")
	}
}

func BenchmarkNewLabels_Small(b *testing.B) {
	testLabels := []Label{}
	for i := range smallLabelsSize - 1 {
		s := strconv.FormatInt(int64(i), 10)
		testLabels = append(testLabels,
			NewLabel("key"+s, "value"+s, "source"+s))
	}
	b.ResetTimer()
	for range b.N {
		NewLabels(testLabels...)
	}
}

func BenchmarkNewLabels_Small_Combined(b *testing.B) {
	for range b.N {
		NewLabels(
			NewLabel("key1", "value1", "source1"),
			NewLabel("key2", "value2", "source2"),
			NewLabel("key3", "value3", "source3"),
			NewLabel("key4", "value4", "source4"),
			NewLabel("key5", "value5", "source5"),
		)
	}
}

func BenchmarkGet_Small(b *testing.B) {
	testLabels := []Label{}
	for i := range smallLabelsSize - 1 {
		s := strconv.FormatInt(int64(i), 10)
		testLabels = append(testLabels,
			NewLabel("key"+s, "value"+s, "source"+s))
	}
	lbls := NewLabels(testLabels...)
	b.ResetTimer()
	for range b.N {
		lbls.Get("key1")
	}
}

func BenchmarkNewLabels_Large(b *testing.B) {
	testLabels := []Label{}
	for i := range 3 * smallLabelsSize {
		s := strconv.FormatInt(int64(i), 10)
		testLabels = append(testLabels,
			NewLabel("key"+s, "value"+s, "source"+s))
	}
	b.ResetTimer()
	for range b.N {
		NewLabels(testLabels...)
	}
}

func BenchmarkGet_Large(b *testing.B) {
	testLabels := []Label{}
	lastKey := ""
	for i := range 3 * smallLabelsSize {
		s := strconv.FormatInt(int64(i), 10)
		testLabels = append(testLabels,
			NewLabel("key"+s, "value"+s, "source"+s))
		lastKey = "key" + s
	}
	lbls := NewLabels(testLabels...)
	b.ResetTimer()
	for range b.N {
		// Worst case is Get() the last one
		lbls.Get(lastKey)
	}
}
