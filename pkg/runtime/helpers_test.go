// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runtime

import (
	"runtime/metrics"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestComputeMedian(t *testing.T) {
	uu := map[string]struct {
		h metrics.Float64Histogram
		e float64
	}{
		"empty": {},

		"zeros": {
			h: metrics.Float64Histogram{
				Buckets: []float64{10, 0, 30},
				Counts:  []uint64{10, 0, 30},
			},
			e: 30,
		},

		"plain": {
			h: metrics.Float64Histogram{
				Buckets: []float64{10, 20, 30},
				Counts:  []uint64{10, 20, 30},
			},
			e: 20,
		},

		"sparse": {
			h: metrics.Float64Histogram{
				Buckets: []float64{0.000000, 0.000001, 0.000002, 0.000003, 0.000004, 0.000006, 0.000007, 0.000008, 0.000010, 0.000012, 0.000014, 0.000016, 0.000020, 0.000025, 0.000029, 0.000033, 0.000041, 0.000049, 0.000057, 0.000066, 0.000082, 0.000098, 0.000115, 0.000131, 0.000164, 0.000197, 0.000229, 0.000262, 0.000328, 0.000393},
				Counts:  []uint64{257, 1, 0, 2, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 4, 2, 2, 1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1},
			},
			e: 0.000041,
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			assert.Equal(t, u.e, computeMedian(&u.h))
		})
	}
}

func TestCompact(t *testing.T) {
	uu := map[string]struct {
		h, e metrics.Float64Histogram
	}{
		"empty": {
			e: metrics.Float64Histogram{
				Buckets: []float64{},
				Counts:  []uint64{},
			},
		},

		"zeros": {
			h: metrics.Float64Histogram{
				Buckets: []float64{10, 0, 30},
				Counts:  []uint64{10, 0, 30},
			},
			e: metrics.Float64Histogram{
				Buckets: []float64{10, 30},
				Counts:  []uint64{10, 30},
			},
		},

		"plain": {
			h: metrics.Float64Histogram{
				Buckets: []float64{10, 20, 30},
				Counts:  []uint64{10, 20, 30},
			},
			e: metrics.Float64Histogram{
				Buckets: []float64{10, 20, 30},
				Counts:  []uint64{10, 20, 30},
			},
		},

		"sparse": {
			h: metrics.Float64Histogram{
				Buckets: []float64{0.000000, 0.000001, 0.000002, 0.000003, 0.000004, 0.000006, 0.000007, 0.000008, 0.000010, 0.000012, 0.000014, 0.000016, 0.000020, 0.000025, 0.000029, 0.000033, 0.000041, 0.000049, 0.000057, 0.000066, 0.000082, 0.000098, 0.000115, 0.000131, 0.000164, 0.000197, 0.000229, 0.000262, 0.000328, 0.000393},
				Counts:  []uint64{257, 1, 0, 2, 2, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 4, 2, 2, 1, 2, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1},
			},
			e: metrics.Float64Histogram{
				Buckets: []float64{0.000001, 0.000003, 0.000004, 0.000012, 0.000025, 0.000029, 0.000033, 0.000041, 0.000049, 0.000057, 0.000066, 0.000082, 0.000164},
				Counts:  []uint64{1, 2, 2, 1, 1, 1, 1, 4, 2, 2, 1, 2, 1},
			},
		},
	}

	for k := range uu {
		u := uu[k]
		t.Run(k, func(t *testing.T) {
			compact(&u.h)
			assert.Equal(t, u.e, u.h)
		})
	}
}
