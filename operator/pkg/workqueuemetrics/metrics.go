// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package workqueuemetrics

import (
	"k8s.io/client-go/util/workqueue"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	// LabelQueueName denotes which queue the metric is for
	LabelQueueName = "queue_name"
)

// Metrics implements the workqueue.MetricsProvider interface
type Metrics struct {
	WorkQueueDepth                   metric.Vec[metric.Gauge]
	WorkQueueAddsTotal               metric.Vec[metric.Counter]
	WorkQueueLatency                 metric.Vec[metric.Observer]
	WorkQueueDuration                metric.Vec[metric.Observer]
	WorkQueueUnfinishedWork          metric.Vec[metric.Gauge]
	WorkQueueLongestRunningProcessor metric.Vec[metric.Gauge]
	WorkQueueRetries                 metric.Vec[metric.Counter]
}

func NewMetrics() *Metrics {
	return &Metrics{
		WorkQueueDepth: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_depth",
			Help:      "Current depth of the workqueue",
		}, []string{LabelQueueName}),

		WorkQueueAddsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_adds_total",
			Help:      "Total number of adds handled by the workqueue",
		}, []string{LabelQueueName}),

		WorkQueueLatency: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_queue_duration_seconds",
			Help:      "Duration in seconds an item stays in workqueue prior to request",
			Buckets:   []float64{.01, .05, .1, .5, 1, 5, 10, 30, 60},
		}, []string{LabelQueueName}),

		WorkQueueDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_work_duration_seconds",
			Help:      "Duration in seconds to process an item from workqueue",
			Buckets:   []float64{.01, .05, .1, .5, 1, 5, 10, 30, 60},
		}, []string{LabelQueueName}),

		WorkQueueUnfinishedWork: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_unfinished_work_seconds",
			Help:      "Duration in seconds of work in progress that hasn't been observed by work_duration",
		}, []string{LabelQueueName}),

		WorkQueueLongestRunningProcessor: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_longest_running_processor_seconds",
			Help:      "Duration in seconds of the longest running processor for workqueue",
		}, []string{LabelQueueName}),

		WorkQueueRetries: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "workqueue_retries_total",
			Help:      "Total number of retries handled by workqueue",
		}, []string{LabelQueueName}),
	}
}

func (m *Metrics) NewDepthMetric(queueName string) workqueue.GaugeMetric {
	return m.WorkQueueDepth.WithLabelValues(queueName)
}

func (m *Metrics) NewAddsMetric(queueName string) workqueue.CounterMetric {
	return m.WorkQueueAddsTotal.WithLabelValues(queueName)
}

func (m *Metrics) NewLatencyMetric(queueName string) workqueue.HistogramMetric {
	return m.WorkQueueLatency.WithLabelValues(queueName)
}

func (m *Metrics) NewWorkDurationMetric(queueName string) workqueue.HistogramMetric {
	return m.WorkQueueDuration.WithLabelValues(queueName)
}

func (m *Metrics) NewUnfinishedWorkSecondsMetric(queueName string) workqueue.SettableGaugeMetric {
	return m.WorkQueueUnfinishedWork.WithLabelValues(queueName)
}

func (m *Metrics) NewLongestRunningProcessorSecondsMetric(queueName string) workqueue.SettableGaugeMetric {
	return m.WorkQueueLongestRunningProcessor.WithLabelValues(queueName)
}

func (m *Metrics) NewRetriesMetric(queueName string) workqueue.CounterMetric {
	return m.WorkQueueRetries.WithLabelValues(queueName)
}
