// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package runtime

import "runtime/metrics"

const schedLatencyMX = "/sched/latencies:seconds"

type goRuntimeMetrics struct {
	samples []metrics.Sample
}

func newGORuntimeMetrics() *goRuntimeMetrics {
	return &goRuntimeMetrics{
		samples: []metrics.Sample{
			{Name: schedLatencyMX},
		},
	}
}

// GetSchedulerLatency fetches GORs scheduling latencies from GO runtime.
func (g goRuntimeMetrics) GetSchedulerLatency() *metrics.Float64Histogram {
	metrics.Read(g.samples)
	for _, s := range g.samples {
		if s.Name == schedLatencyMX {
			return s.Value.Float64Histogram()
		}
	}

	return nil
}
