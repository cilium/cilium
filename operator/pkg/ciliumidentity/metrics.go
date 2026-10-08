// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumidentity

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/utils/clock"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelResource indicates resources that the metrics are attributed to.
	LabelResource = "resource"
	// LabelPhase indicates the phases the metrics are attributed to.
	LabelPhase = "phase"

	LabelValueCID               = "cid"
	LabelValuePod               = "pod"
	LabelValueEnqueuedLatency   = "enqueued"
	LabelValueProcessingLatency = "processing"
)

func NewMetrics() *Metrics {
	return &Metrics{
		EventCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_work_queue_event_count",
			Help:      "Counts processed events by CID controller work queues labeled by outcome",
		}, []string{LabelResource, metrics.LabelOutcome}),

		QueueLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "cid_controller_work_queue_latency",
			Help:      "Duration of CID controller work queues enqueuing and processing latencies in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}, []string{LabelResource, LabelPhase}),
	}
}

type Metrics struct {
	EventCount   metric.Vec[metric.Counter]
	QueueLatency metric.Vec[metric.Observer]
}

func (m Metrics) meterLatency(label string, enqueuedLatency float64, processingLatency float64) {
	m.QueueLatency.WithLabelValues(label, LabelValueEnqueuedLatency).Observe(enqueuedLatency)
	m.QueueLatency.WithLabelValues(label, LabelValueProcessingLatency).Observe(processingLatency)
}

func (m Metrics) markEvent(label string, isErr bool) {
	var labelValue string
	if isErr {
		labelValue = metrics.LabelValueOutcomeFail
	} else {
		labelValue = metrics.LabelValueOutcomeSuccess
	}

	m.EventCount.WithLabelValues(label, labelValue).Inc()

}

// EnqueueTimeTracker provides a thread safe mechanism to record
// and manage the time when items are enqueued.
type EnqueueTimeTracker struct {
	enqueuedAt map[string]time.Time
	mu         lock.Mutex
	clock      clock.Clock
}

func (e *EnqueueTimeTracker) Track(item string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.enqueuedAt[item].IsZero() {
		e.enqueuedAt[item] = e.clock.Now()
	}
}

func (e *EnqueueTimeTracker) GetAndReset(item string) (time.Time, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	enqueuedTime, exists := e.enqueuedAt[item]
	if !exists {
		return time.Time{}, false
	}

	delete(e.enqueuedAt, item)
	return enqueuedTime, true
}
