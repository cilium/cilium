// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package slices

import (
	"math"
	"math/rand"
	"strconv"
	"testing"
	"time"

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
			got := Unique(tc.input)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestSortedUnique(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := SortedUnique(tc.input)
			assert.ElementsMatch(t, tc.expected, got)
		})
	}
}

func TestSortedUniqueFunc(t *testing.T) {
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := SortedUniqueFunc(
				tc.input,
				func(i, j int) bool {
					return tc.input[i] < tc.input[j]
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
	var benchCases = [...]int{96, 128, 160, 192, 256, 512, 1024}

	r := rand.New(rand.NewSource(time.Now().Unix()))
	for _, sz := range benchCases {
		b.Run(strconv.Itoa(sz), func(b *testing.B) {
			b.ReportAllocs()

			orig := make([]int, 0, sz)
			orig = append(orig, r.Intn(math.MaxInt))
			for i := 1; i < sz; i++ {
				var next int
				if r.Intn(100) < 20 {
					next = orig[r.Intn(len(orig))]
				} else {
					next = r.Intn(math.MaxInt)
				}
				orig = append(orig, next)
			}
			values := make([]int, len(orig))
			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				b.StopTimer()
				values = values[:cap(values)]
				copy(values, orig)
				rand.Shuffle(len(orig), func(i, j int) {
					orig[i], orig[j] = orig[j], orig[i]
				})
				b.StartTimer()

				Unique(values)
			}
		})
	}
}
