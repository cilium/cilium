// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package identitycachecell

import (
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/time"
)

type identityCacheMetrics struct {
	TriggerLatency metric.Vec[metric.Observer]
	TriggerFolds   metric.Vec[metric.Observer]
	TimerDuration  metric.Vec[metric.Observer]
}

var _ job.Metrics = &identityCacheMetrics{}

const subsystem = "identity_cache"

func newIdentityCacheMetrics() *identityCacheMetrics {
	return &identityCacheMetrics{
		TriggerLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "timer_trigger_latency",
			Help:      "The total time spent waiting for a timer to be ready to start",
		}, []string{"name"}),
		TriggerFolds: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "timer_trigger_folds",
			Help:      "The number of pending requests served by a single timer invocation",
		}, []string{"name"}),
		TimerDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name:      "timer_duration",
			Help:      "The execution duration for a timer",
		}, []string{"name"}),
	}
}

func (m *identityCacheMetrics) TimerRunDuration(name string, duration time.Duration) {
	m.TimerDuration.WithLabelValues(name).Observe(duration.Seconds())
}

func (m *identityCacheMetrics) TimerTriggerStats(name string, latency time.Duration, folds int) {
	m.TriggerLatency.WithLabelValues(name).Observe(latency.Seconds())
	m.TriggerFolds.WithLabelValues(name).Observe(float64(folds))
}

func (m *identityCacheMetrics) JobError(name string, err error) {
}

func (m *identityCacheMetrics) ObserverRunDuration(name string, duration time.Duration) {
}

func (m *identityCacheMetrics) OneShotRunDuration(name string, duration time.Duration) {
}
