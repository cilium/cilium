// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/time"
)

// debugCollector runs periodically and samples all metrics. It keeps
// a snapshot of the metrics in the past 15 minutes, sampled at 1 minute
// intervals.
type debugCollector struct {
	reg     *Registry
	log     *slog.Logger
	mu      lock.Mutex
	samples map[debugKey]*debugSamples
}

type debugKey struct {
	name  string
	label string
}

func newDebugCollector(log *slog.Logger, reg *Registry, jg job.Group) *debugCollector {
	dc := &debugCollector{
		log:     log,
		reg:     reg,
		samples: make(map[debugKey]*debugSamples),
	}
	jg.Add(job.OneShot("collect", dc.collectLoop))
	return dc
}

// debugSamples are the samples measured every minute. 0th entry is
// the latest measurement.
type debugSamples struct {
	labels  []*dto.LabelPair
	samples [15]float64
}

func (dc *debugCollector) collectLoop(ctx context.Context, health cell.Health) error {
	const interval = time.Minute
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		health.OK("Collecting metrics")
		n, err := dc.collect()
		if err != nil {
			health.Degraded("Failed to collect metrics", err)
		} else {
			health.OK(fmt.Sprintf("Sampled %d metrics. Collecting again in %s", n, interval))
		}

		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (dc *debugCollector) collect() (numSamples int, err error) {
	dc.mu.Lock()
	defer dc.mu.Unlock()

	metrics, err := dc.reg.inner.Gather()
	if err != nil {
		return 0, err
	}

	for _, val := range metrics {
		metricName := val.GetName()
		metricType := val.GetType()
		for _, metricLabel := range val.Metric {
			key := newDebugKey(metricName, metricLabel.GetLabel())
			bucket := dc.samples[key]
			if bucket == nil {
				bucket = &debugSamples{labels: metricLabel.GetLabel()}
				dc.samples[key] = bucket
			}
			copy(bucket.samples[1:], bucket.samples[:])

			value, _ := getMetricValue(metricName, metricType, metricLabel)
			bucket.samples[0] = value
			numSamples++
		}
	}
	return
}

func newDebugKey(name string, labels []*dto.LabelPair) debugKey {
	var b strings.Builder
	for i, lp := range labels {
		b.WriteString(lp.GetName())
		b.WriteByte('=')
		b.WriteString(lp.GetValue())
		if i < len(labels)-1 {
			b.WriteByte(' ')
		}
	}
	return debugKey{
		name:  name,
		label: b.String(),
	}
}

func getHistogramQuantile(histogram *dto.Histogram, quantile float64) float64 {
	if len(histogram.GetBucket()) < 2 {
		return 0.0
	}

	// Sort the samples by the bounds
	buckets :=
		slices.SortedFunc(
			slices.Values(histogram.Bucket),
			func(a, b *dto.Bucket) int {
				return cmp.Compare(a.GetUpperBound(), b.GetUpperBound())
			})

	// Find the bucket holding the requested quantile
	totalCount := buckets[len(buckets)-1].GetCumulativeCount()
	if totalCount == 0 {
		return 0.0
	}
	rank := quantile * float64(totalCount)
	index := sort.Search(
		len(buckets)-1,
		func(i int) bool {
			return buckets[i].GetCumulativeCountFloat() >= rank
		})
	if index == len(buckets)-1 {
		return buckets[len(buckets)-2].GetUpperBound()
	} else if index == 0 && buckets[0].GetUpperBound() <= 0 {
		return buckets[0].GetUpperBound()
	}
	bucketStart := 0.0
	bucketEnd := buckets[index].GetUpperBound()
	count := buckets[index].GetCumulativeCountFloat()
	if index > 0 {
		bucketStart = buckets[index-1].GetUpperBound()
		count -= buckets[index-1].GetCumulativeCountFloat()
		rank -= buckets[index-1].GetCumulativeCountFloat()
	}
	return bucketStart + (bucketEnd-bucketStart)*(rank/count)
}
