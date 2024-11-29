// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"cmp"
	"math"
	"slices"
	"sort"

	dto "github.com/prometheus/client_model/go"
)

type histogramBucket struct {
	cumulativeCount uint64
	upperBound      float64
}

func convertHistogram(h *dto.Histogram) []histogramBucket {
	histogram := make([]histogramBucket, len(h.GetBucket()))
	for i, b := range h.GetBucket() {
		histogram[i] = histogramBucket{b.GetCumulativeCount(), b.GetUpperBound()}
	}
	slices.SortFunc(histogram,
		func(a, b histogramBucket) int {
			return cmp.Compare(a.upperBound, b.upperBound)
		})
	return histogram
}

// subtractHistogram removes from 'a' the observations from 'b'.
func subtractHistogram(a, b []histogramBucket) {
	if len(a) != len(b) {
		panic("impossible: histogram bucket sizes do not match")
	}
	for i := range a {
		if a[i].upperBound != b[i].upperBound {
			panic("impossible: different upper bounds")
		}
		a[i].cumulativeCount -= b[i].cumulativeCount
	}
}

func histogramSampleCount(histogram []histogramBucket) uint64 {
	if len(histogram) == 0 {
		return 0
	}
	return histogram[len(histogram)-1].cumulativeCount
}

// getHistogramQuantile calculates quantile from the Prometheus Histogram message.
// For example: getHistogramQuantile(h, 0.95) returns the 95th quantile.
func getHistogramQuantile(histogram []histogramBucket, quantile float64) float64 {
	if len(histogram) < 1 {
		return 0.0
	}
	if quantile < 0.0 {
		return math.Inf(-1)
	} else if quantile > 1.0 {
		return math.Inf(+1)
	}

	totalCount := histogram[len(histogram)-1].cumulativeCount
	if totalCount == 0 {
		return 0.0
	}

	// Find the bucket onto which the quantile falls
	rank := quantile * float64(totalCount)
	index := sort.Search(
		len(histogram)-1,
		func(i int) bool {
			return float64(histogram[i].cumulativeCount) >= rank
		})

	if index == 0 {
		// Sample in first bucket, interpolate between 0.0..UpperBound within the bucket.
		return histogram[0].upperBound * (rank / float64(histogram[0].cumulativeCount))
	}

	// Return the linearly interpolated value between the upper bounds of the
	// two buckets in between which the quantile falls.
	start := histogram[index-1].upperBound
	end := histogram[index].upperBound
	relativeCount := float64(histogram[index].cumulativeCount - histogram[index-1].cumulativeCount)
	relativeRank := rank - float64(histogram[index-1].cumulativeCount)
	return start + (end-start)*(relativeRank/relativeCount)
}
