// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package v2

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		l := MakeLabel(k, v, "source"+s)
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
		lx, found := lbls1.GetLabel(l.Key())
		assert.True(t, found, "lbls1.Get(%s)", l.Key())
		assert.Equal(t, l, lx)

		lx, found = lbls2.GetLabel(l.Key())
		assert.True(t, found, "lbls2.Get(%s)", l.Key())
		assert.Equal(t, l, lx)
	}
	assert.Equal(t, expectedString, lbls1.String(), "lbls1.String")
	assert.Equal(t, expectedString, lbls2.String(), "lbls2.String")

	// Test Map2Labels
	lbls3 := Map2Labels(mapLabels, "src")
	assert.Equal(t, n, lbls3.Len())
	for _, l := range testLabels {
		lx, found := lbls3.GetLabel(l.Key())
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
			MakeLabel("key"+s, "value"+s, "source"+s))
	}
	b.ResetTimer()
	for range b.N {
		NewLabels(testLabels...)
	}
}

func BenchmarkNewLabels_Small_Combined(b *testing.B) {
	for range b.N {
		NewLabels(
			MakeLabel("key1", "value1", "source1"),
			MakeLabel("key2", "value2", "source2"),
			MakeLabel("key3", "value3", "source3"),
			MakeLabel("key4", "value4", "source4"),
			MakeLabel("key5", "value5", "source5"),
		)
	}
}

func BenchmarkGet_Small(b *testing.B) {
	testLabels := []Label{}
	for i := range smallLabelsSize - 1 {
		s := strconv.FormatInt(int64(i), 10)
		testLabels = append(testLabels,
			MakeLabel("key"+s, "value"+s, "source"+s))
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
			MakeLabel("key"+s, "value"+s, "source"+s))
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
			MakeLabel("key"+s, "value"+s, "source"+s))
		lastKey = "key" + s
	}
	lbls := NewLabels(testLabels...)
	b.ResetTimer()
	for range b.N {
		// Worst case is Get() the last one
		lbls.Get(lastKey)
	}
}

func TestLabelsJSON(t *testing.T) {
	// Empty labels
	{
		lbls := NewLabels()
		b, err := json.Marshal(lbls)
		require.NoError(t, err, "Marshal")

		var lbls2 Labels
		err = json.Unmarshal(b, &lbls2)
		require.NoError(t, err, "Unmarshal")
		require.True(t, lbls.Equal(lbls2), "Equal")
		require.Equal(t, lbls.String(), lbls2.String(), "Equal strings")
	}

	// Non-empty
	{
		lbls := NewLabels(
			NewLabel("key1", "value1", "source1"),
			NewLabel("key3", "value3", "source3"),
			NewLabel("key2", "value2", "source2"),
		)
		b, err := json.Marshal(lbls)
		require.NoError(t, err, "Marshal")

		var lbls2 Labels
		err = json.Unmarshal(b, &lbls2)
		require.NoError(t, err, "Unmarshal")
		require.True(t, lbls.Equal(lbls2), "Equal")
		require.Equal(t, lbls.String(), lbls2.String(), "Equal strings")
	}
}

func TestCompactSortedLabels(t *testing.T) {
	// Empty
	lbls := []Label{}
	assert.Empty(t, compactSortedLabels(lbls))

	// Singleton
	lbls = []Label{NewLabel("k", "v", "s")}
	assert.Len(t, compactSortedLabels(lbls), 1)

	// 2 different
	lbls = []Label{NewLabel("a", "a", "a"), NewLabel("b", "b", "b")}
	assert.Len(t, compactSortedLabels(lbls), 2)

	// 2 with same key
	lbls = []Label{NewLabel("a", "a", "a"), NewLabel("a", "b", "b")}
	assert.Len(t, compactSortedLabels(lbls), 1)
	assert.Equal(t, "b", lbls[0].Value())

	// 3 with 2 having the same key
	lbls = []Label{NewLabel("a", "a", "a"), NewLabel("a", "b", "b"), NewLabel("c", "c", "c")}
	assert.Len(t, compactSortedLabels(lbls), 2)
	assert.Equal(t, "b", lbls[0].Value())
	assert.Equal(t, "c", lbls[1].Value())

	// 4 with 2 having the same key
	lbls = []Label{NewLabel("d", "d", "d"), NewLabel("a", "a", "a"), NewLabel("a", "b", "b"), NewLabel("c", "c", "c")}
	assert.Len(t, compactSortedLabels(lbls), 3)
	assert.Equal(t, "d", lbls[0].Value())
	assert.Equal(t, "b", lbls[1].Value())
	assert.Equal(t, "c", lbls[2].Value())
}

func TestLess(t *testing.T) {
	a := NewLabels(NewLabel("a", "a", "a"))
	b := NewLabels(NewLabel("b", "b", "b"))
	assert.True(t, a.Less(b), "%s < %s", a, b)
	assert.False(t, b.Less(a), "%s < %s", b, a)
	assert.False(t, a.Less(a), "%s < %s", a, a)
	assert.False(t, a.Less(Labels{}), "%s < %s", a, Labels{})
	assert.False(t, a.Less(NewLabels()), "%s < %s", a, NewLabels())
	c := Merge(a, NewLabels(NewLabel("c", "c", "c")))
	assert.True(t, a.Less(c), "%s < %s", a, c)
	assert.True(t, c.Less(b), "%s < %s", c, b)
	assert.False(t, c.Less(c), "%s < %s", c, c)
}
