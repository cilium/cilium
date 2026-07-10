// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetHistogramQuantile(t *testing.T) {
	assertAlmostEqual := func(expected, actual float64) {
		diff := math.Abs(expected - actual)
		assert.Less(t, diff, 0.1, "expected %f to be within 10% of %f", actual, expected)
	}

	// Empty backets
	example := []histogramBucket{}
	actual := getHistogramQuantile(example, 0.5)
	assert.Equal(t, 0.0, actual)

	// Single bucket
	example = []histogramBucket{
		{3, 3.0},
	}
	actual = getHistogramQuantile(example, 0.0)
	assertAlmostEqual(0.0, actual)
	actual = getHistogramQuantile(example, 0.5)
	assertAlmostEqual(1.5, actual)
	actual = getHistogramQuantile(example, 1.0)
	assertAlmostEqual(3.0, actual)

	// Multiple buckets
	example = []histogramBucket{
		// 25% of samples fall between 0..1
		{5, 1.0},
		// 25% of samples fall between 1..3
		{10, 3.0},
		// 25% of samples fall between 3..9
		{20, 9},
	}

	testCases := []struct{ quantile, value float64 }{
		{0.1, 0.4},
		{0.5, 3.0},
		{0.90, 7.8},
		{0.99, 8.9},
	}
	for _, tc := range testCases {
		actual := getHistogramQuantile(example, tc.quantile)
		diff := math.Abs(tc.value - actual)
		assert.Less(t, diff, 0.1, "unexpected value %f for quantile %f", actual, tc.quantile)
	}
}
