// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelWorkqueue indicates workqueues that the metrics are attributed to.
	LabelWorkqueue = "workqueue"

	// LabelPhase indicates the phases the metrics are attributed to.
	LabelPhase = "period"

	// Label values

	LabelValueCIDWorkqueue = "cilium-identity"

	LabelValuePodWorkqueue = "pod"

	LabelValueEnqueuedLatency = "enqueued"

	LabelValueProcessingLatency = "processing"

	LabelValueRateLimitLatency = "rate-limit"
)

func NewMetrics() *Metrics {
	return &Metrics{
		CIDControllerWorkqueueEventCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_workqueue_event_count",
			Help:      "Number processed successful and failed events by Cilium Identity controller workqueues",
		}, []string{LabelWorkqueue, metrics.LabelOutcome}),

		CIDControllerWorkqueueLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_workqueue_latency",
			Help:      "Duration of Cilium Identity controller workqueues enqueuing and processing latencies in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}, []string{LabelWorkqueue, LabelPhase}),
	}
}

type Metrics struct {
	CIDControllerWorkqueueEventCount metric.Vec[metric.Counter]
	CIDControllerWorkqueueLatency    metric.Vec[metric.Observer]
}
