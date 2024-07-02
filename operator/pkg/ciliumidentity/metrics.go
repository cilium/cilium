// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelWorkQueue indicates work queues that the metrics are attributed to.
	LabelWorkQueue = "work-queue"
	// LabelPhase indicates the phases the metrics are attributed to.
	LabelPhase = "period"

	LabelValueCIDWorkQueue      = "cilium-identity"
	LabelValuePodWorkQueue      = "pod"
	LabelValueEnqueuedLatency   = "enqueued"
	LabelValueProcessingLatency = "processing"
)

func NewMetrics() *Metrics {
	return &Metrics{
		CIDControllerWorkQueueEventCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_work_queue_event_count",
			Help:      "Counts processed events by CID controller work queues labeled by outcome",
		}, []string{LabelWorkQueue, metrics.LabelOutcome}),

		CIDControllerWorkQueueLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_work_queue_latency",
			Help:      "Duration of CID controller work queues enqueuing and processing latencies in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}, []string{LabelWorkQueue, LabelPhase}),
	}
}

type Metrics struct {
	CIDControllerWorkQueueEventCount metric.Vec[metric.Counter]
	CIDControllerWorkQueueLatency    metric.Vec[metric.Observer]
}

func (m Metrics) meterLatency(label string, startTime time.Time, exists bool, enqueueTime time.Time) {
	if exists {
		enqueuedLatency := startTime.Sub(enqueueTime).Seconds()
		m.CIDControllerWorkQueueLatency.WithLabelValues(label, LabelValueEnqueuedLatency).Observe(enqueuedLatency)
	}
	processingLatency := time.Since(startTime).Seconds()
	m.CIDControllerWorkQueueLatency.WithLabelValues(label, LabelValueProcessingLatency).Observe(processingLatency)
}

func (m Metrics) markEvent(label string, isSuccess bool) {
	var labelValue string
	if isSuccess {
		labelValue = metrics.LabelValueOutcomeSuccess
	} else {
		labelValue = metrics.LabelValueOutcomeFail
	}

	m.CIDControllerWorkQueueEventCount.WithLabelValues(label, labelValue).Inc()

}
