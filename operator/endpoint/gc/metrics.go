// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package gc

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	// EndpointGCObjects records the number of times endpoint objects have been
	// garbage-collected.
	EndpointGCObjects metric.Vec[metric.Counter]
}

func newMetrics() Metrics {
	return Metrics{
		EndpointGCObjects: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_endpoint_gc_objects",
			Namespace:  metrics.Namespace,
			Subsystem:  "cilium-endpoints-gc",
			Name:       "endpoint_gc_objects",
			Help:       "The number of times endpoint objects have been garbage-collected",
		}, []string{metrics.LabelOutcome}),
	}
}
