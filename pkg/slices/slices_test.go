// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slices

import (
	"fmt"
	"math"
	"math/rand/v2"
	"slices"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testCases = [...]struct {
	name     string
	input    []int
	expected []int
}{
	{
		name:     "nil slice",
		input:    nil,
		expected: nil,
	},
	{
		name:     "empty slice",
		input:    []int{},
		expected: []int{},
	},
	{
		name:     "single element",
		input:    []int{1},
		expected: []int{1},
	},
	{
		name:     "all uniques",
		input:    []int{1, 3, 4, 2, 9, 7, 6, 10, 5, 8},
		expected: []int{1, 3, 4, 2, 9, 7, 6, 10, 5, 8},
	},
	{
		name:     "all duplicates",
		input:    []int{1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		expected: []int{1},
	},
	{
		name:     "uniques and duplicates",
		input:    []int{1, 2, 2, 1, 1, 3, 1, 3, 1, 4},
		expected: []int{1, 2, 3, 4},
	},
}

func TestUnique(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Clone(tc.input)
			got := Unique(input)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestUniqueFunc(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Clone(tc.input)
			got := UniqueFunc(
				input,
				func(i int) int {
					return input[i]
				},
			)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestSortedUnique(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Clone(tc.input)
			got := SortedUnique(input)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestSortedUniqueFunc(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Clone(tc.input)
			got := SortedUniqueFunc(
				input,
				func(i, j int) bool {
					return input[i] < input[j]
				},
				func(a, b int) bool {
					return a == b
				},
			)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestUniqueKeepOrdering(t *testing.T) {
	input := []string{"test-4", "test-1", "test-3", "test-4", "test-4", "test-3", "test-5"}
	expected := []*string{&input[0], &input[1], &input[2], &input[3]}

	got := Unique(input)

	if len(got) != len(expected) {
		t.Fatalf("expected slice of %d elements, got %d", len(expected), len(got))
	}

	for i := 0; i < len(expected); i++ {
		if got[i] != *expected[i] {
			t.Fatalf("expected value %q at index %d, got %q", *expected[i], i, got[i])
		}

		if &got[i] != expected[i] {
			t.Fatalf("expected address of value at index %d to be %x, got %x", i, expected[i], &got[i])
		}
	}
}

func TestDiff(t *testing.T) {
	testCases := []struct {
		name     string
		a        []string
		b        []string
		expected []string
	}{
		{
			name:     "empty second slice",
			a:        []string{"foo"},
			b:        []string{},
			expected: []string{"foo"},
		},
		{
			name:     "empty first slice",
			a:        []string{},
			b:        []string{"foo"},
			expected: nil,
		},
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			expected: nil,
		},
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: nil,
		},
		{
			name:     "subset",
			a:        []string{"foo", "bar"},
			b:        []string{"foo", "bar", "baz"},
			expected: nil,
		},
		{
			name:     "equal",
			a:        []string{"foo", "bar"},
			b:        []string{"foo", "bar"},
			expected: nil,
		},
		{
			name:     "same size not equal",
			a:        []string{"foo", "bar"},
			b:        []string{"foo", "baz"},
			expected: []string{"bar"},
		},
		{
			name:     "smaller size",
			a:        []string{"baz"},
			b:        []string{"foo", "bar"},
			expected: []string{"baz"},
		},
		{
			name:     "larger size",
			a:        []string{"foo", "bar", "fizz"},
			b:        []string{"fizz", "buzz"},
			expected: []string{"foo", "bar"},
		},
		{
			name:     "subset with duplicates",
			a:        []string{"foo", "foo", "bar"},
			b:        []string{"foo", "bar"},
			expected: nil,
		},
		{
			name:     "subset with more duplicates",
			a:        []string{"foo", "foo", "foo", "bar", "bar"},
			b:        []string{"foo", "foo", "bar"},
			expected: nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			diff := Diff(tc.a, tc.b)
			assert.Equal(t, tc.expected, diff)
		})
	}
}

func TestSubsetOf(t *testing.T) {
	testCases := []struct {
		name     string
		a        []string
		b        []string
		isSubset bool
		diff     []string
	}{
		{
			name:     "empty second slice",
			a:        []string{"foo"},
			b:        []string{},
			isSubset: false,
			diff:     []string{"foo"},
		},
		{
			name:     "empty first slice",
			a:        []string{},
			b:        []string{"foo"},
			isSubset: true,
			diff:     nil,
		},
		{
			name:     "both empty",
			a:        []string{},
			b:        []string{},
			isSubset: true,
			diff:     nil,
		},
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			isSubset: true,
			diff:     nil,
		},
		{
			name:     "subset",
			a:        []string{"foo", "bar"},
			b:        []string{"foo", "bar", "baz"},
			isSubset: true,
			diff:     nil,
		},
		{
			name:     "equal",
			a:        []string{"foo", "bar"},
			b:        []string{"foo", "bar"},
			isSubset: true,
			diff:     nil,
		},
		{
			name:     "same size not equal",
			a:        []string{"foo", "bar"},
			b:        []string{"foo", "baz"},
			isSubset: false,
			diff:     []string{"bar"},
		},
		{
			name:     "smaller size",
			a:        []string{"baz"},
			b:        []string{"foo", "bar"},
			isSubset: false,
			diff:     []string{"baz"},
		},
		{
			name:     "larger size",
			a:        []string{"foo", "bar", "fizz"},
			b:        []string{"fizz", "buzz"},
			isSubset: false,
			diff:     []string{"foo", "bar"},
		},
		{
			name:     "subset with duplicates",
			a:        []string{"foo", "foo", "bar"},
			b:        []string{"foo", "bar"},
			isSubset: true,
			diff:     nil,
		},
		{
			name:     "subset with more duplicates",
			a:        []string{"foo", "foo", "foo", "bar", "bar"},
			b:        []string{"foo", "foo", "bar"},
			isSubset: true,
			diff:     nil,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			isSubset, diff := SubsetOf(tc.a, tc.b)
			assert.Equal(t, tc.isSubset, isSubset)
			assert.Equal(t, tc.diff, diff)
		})
	}
}

func TestXorNil(t *testing.T) {
	testCases := []struct {
		name     string
		a        []string
		b        []string
		expected bool
	}{
		{
			name:     "both nil",
			a:        nil,
			b:        nil,
			expected: false,
		},
		{
			name:     "first is nil",
			a:        nil,
			b:        []string{},
			expected: true,
		},
		{
			name:     "second is nil",
			a:        []string{},
			b:        nil,
			expected: true,
		},
		{
			name:     "both non-nil",
			a:        []string{},
			b:        []string{},
			expected: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, XorNil(tc.a, tc.b))
		})
	}
}

// BenchmarkUnique runs the Unique function on a slice of size elements, where each element
// has a probability of 20% of being a duplicate.
// At each iteration the slice is restored to its original status and reshuffled, in order
// to benchmark the average time needed to deduplicate the elements whatever their specific order.
//
// This benchmark has been used to experimentally derive the size limit for Unique beyond which
// the algorithm changes from a O(N^2) search to a map based approach.
// Forcing Unique to rely only on a single algorithm at a time and running the benchmark with count=5,
// the compared results extracted with benchstat are the following:
//
// name          old time/op    new time/op    delta
// Unique/96-8     3.17µs ± 9%    4.83µs ±15%  +52.50%  (p=0.008 n=5+5)
// Unique/128-8    4.97µs ± 5%    5.95µs ± 2%  +19.83%  (p=0.008 n=5+5)
// Unique/160-8    7.20µs ±12%    7.33µs ± 1%     ~     (p=0.690 n=5+5)
// Unique/192-8    9.29µs ± 3%    9.07µs ± 2%     ~     (p=0.151 n=5+5)
// Unique/256-8    15.4µs ± 4%    11.2µs ± 2%  -27.56%  (p=0.008 n=5+5)

// name          old alloc/op   new alloc/op   delta
// Unique/96-8      0.00B       1474.00B ± 2%    +Inf%  (p=0.008 n=5+5)
// Unique/128-8     0.00B       3100.00B ± 0%    +Inf%  (p=0.008 n=5+5)
// Unique/160-8     0.00B       3113.20B ± 0%    +Inf%  (p=0.008 n=5+5)
// Unique/192-8     0.00B       3143.20B ± 0%    +Inf%  (p=0.008 n=5+5)
// Unique/256-8     0.00B       6178.00B ± 0%    +Inf%  (p=0.008 n=5+5)

// name          old allocs/op  new allocs/op  delta
// Unique/96-8       0.00           3.20 ±38%    +Inf%  (p=0.008 n=5+5)
// Unique/128-8      0.00           2.00 ± 0%    +Inf%  (p=0.008 n=5+5)
// Unique/160-8      0.00           3.00 ± 0%    +Inf%  (p=0.016 n=5+4)
// Unique/192-8      0.00           4.00 ± 0%    +Inf%  (p=0.008 n=5+5)
// Unique/256-8      0.00           2.00 ± 0%    +Inf%  (p=0.008 n=5+5)
//
// After 192 elements, the map based approach becomes more efficient.
// Regarding the memory, the number of allocations for the double loop algorithm is always 0,
// that's why benchstat is reporting "+Inf%" in the delta column.
// The relevant differences between the two approaches in terms of memory are shown in the previous
// two columns.
func BenchmarkUnique(b *testing.B) {
	benchmarkUnique(b, false)
}

func BenchmarkUniqueFunc(b *testing.B) {
	benchmarkUnique(b, true)
}

func benchmarkUnique(b *testing.B, benchUniqueFunc bool) {
	var benchCases = [...]int{96, 128, 160, 192, 256, 512, 1024}

	for _, sz := range benchCases {
		b.Run(strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()

			orig := make([]int, 0, sz)
			orig = append(orig, rand.IntN(math.MaxInt))
			for i := 1; i < sz; i++ {
				var next int
				if rand.IntN(100) < 20 {
					next = orig[rand.IntN(len(orig))]
				} else {
					next = rand.IntN(math.MaxInt)
				}
				orig = append(orig, next)
			}
			values := make([]int, len(orig))

			key := func(i int) int {
				return values[i]
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				values = values[:cap(values)]
				copy(values, orig)
				rand.Shuffle(len(orig), func(i, j int) {
					orig[i], orig[j] = orig[j], orig[i]
				})
				if benchUniqueFunc {
					b.StartTimer()
					UniqueFunc(values, key)
				} else {
					b.StartTimer()
					Unique(values)
				}
			}
		})
	}
}

func BenchmarkSubsetOf(b *testing.B) {
	var benchCases = [...]struct {
		subsetSz   int
		supersetSz int
	}{
		{64, 512}, {128, 512},
		{256, 2048}, {512, 2048},
		{1024, 8192}, {2048, 8192},
	}

	for _, bc := range benchCases {
		b.Run(
			fmt.Sprintf("%d-%d", bc.subsetSz, bc.supersetSz),
			func(b *testing.B) {
				b.ReportAllocs()

				subset := make([]string, 0, bc.subsetSz)
				for i := 0; i < bc.subsetSz; i++ {
					subset = append(subset, strconv.Itoa(rand.IntN(bc.subsetSz)))
				}

				superset := make([]string, 0, bc.supersetSz)
				for i := 0; i < bc.supersetSz; i++ {
					superset = append(superset, strconv.Itoa(rand.IntN(bc.subsetSz)))
				}

				b.ResetTimer()

				for i := 0; i < b.N; i++ {
					_, _ = SubsetOf(subset, superset)
				}
			},
		)
	}
}
