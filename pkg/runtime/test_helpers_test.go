// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runtime

import (
	"runtime/metrics"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type testRTMetrics struct {
	hits int
	hist *metrics.Float64Histogram
}

func newTestRTMetrics(h *metrics.Float64Histogram) *testRTMetrics {
	return &testRTMetrics{hist: h}
}

// GetSchedulerLatency fetch GORs scheduling latencies from GO runtime.
func (tmx *testRTMetrics) GetSchedulerLatency() *metrics.Float64Histogram {
	tmx.hits++

	return tmx.hist
}

func getMetricValue(col prometheus.Collector) float64 {
	var acc float64
	gather(col, func(m dto.Metric) {
		switch {
		case m.GetHistogram() != nil:
			acc += float64(m.GetHistogram().GetSampleCount())
		case m.GetSummary() != nil:
			acc += float64(m.GetSummary().GetSampleCount())
		case m.GetGauge() != nil:
			acc += m.GetGauge().GetValue()
		case m.GetCounter() != nil:
			acc += m.GetCounter().GetValue()
		}
	})

	return acc
}

func gather(c prometheus.Collector, f func(dto.Metric)) {
	out := make(chan prometheus.Metric)
	go func(c prometheus.Collector, out chan prometheus.Metric) {
		c.Collect(out)
		close(out)
	}(c, out)

	for x := range out {
		var m dto.Metric
		if err := x.Write(&m); err == nil {
			f(m)
		}
	}
}
