// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package node

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/util/workqueue"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = metrics.Metric(NewWorkqueuePrometheusMetricsProvider)

const workqueueSubsystem = "workqueue"

type WorkqueuePrometheusMetricsProvider struct {
	Retries                 metric.Vec[metric.Counter]
	Depth                   metric.Vec[metric.Gauge]
	Adds                    metric.Vec[metric.Counter]
	Latency                 metric.Vec[metric.Observer]
	WorkDuration            metric.Vec[metric.Observer]
	UnfinishedWorkSeconds   metric.Vec[metric.Gauge]
	LongestRunningProcessor metric.Vec[metric.Gauge]
}

func NewWorkqueuePrometheusMetricsProvider() *WorkqueuePrometheusMetricsProvider {
	// If neither kvstore or node manager watchers are enabled (i.e. if the
	// operator does not need to watch for them in the specified ipam mode
	// then we just provide a noop metric set that we expect to never be used.
	if !option.Config.IsNodeManagerEnabled() && !operatorOption.Config.IsKVstoreEnabled() {
		return &WorkqueuePrometheusMetricsProvider{
			Retries:                 metrics.NoOpCounterVec,
			Depth:                   metrics.NoOpGaugeVec,
			Adds:                    metrics.NoOpCounterVec,
			Latency:                 metrics.NoOpObserverVec,
			WorkDuration:            metrics.NoOpObserverVec,
			UnfinishedWorkSeconds:   metrics.NoOpGaugeVec,
			LongestRunningProcessor: metrics.NoOpGaugeVec,
		}

	}

	names := []string{}
	if operatorOption.Config.IsKVstoreEnabled() {
		names = append(names, "kvstore")
	}
	if option.Config.IsNodeManagerEnabled() {
		names = append(names, "node_manager")
	}

	namespace := metrics.CiliumOperatorNamespace
	subsystem := workqueueSubsystem
	labels := metric.Labels{
		{Name: "queue_name", Values: metric.NewValues(names...)},
	}

	return &WorkqueuePrometheusMetricsProvider{
		Retries: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "retries_total",
			Help:      "Total number of retries handled by workqueue",
		}, labels),
		Depth: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "depth",
			Help:      "Current depth of the workqueue",
		}, labels),
		Adds: metric.NewCounterVecWithLabels(metric.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "adds_total",
			Help:      "Total number of adds handled by the workqueue",
		}, labels),
		Latency: metric.NewHistogramVecWithLabels(metric.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "latency",
			Help:      "How long in seconds an item stays in workqueue before being requested",
			Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
		}, labels),
		WorkDuration: metric.NewHistogramVecWithLabels(metric.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "work_duration",
			Help:      "How long in seconds processing an item from workqueue takes",
			Buckets:   prometheus.ExponentialBuckets(10e-9, 10, 10),
		}, labels),
		UnfinishedWorkSeconds: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "unfinished_work_seconds",
			Help: "How many seconds of work has been done that " +
				"is in progress and hasn't been observed by work_duration. Large " +
				"values indicate stuck threads. One can deduce the number of stuck " +
				"threads by observing the rate at which this increases.",
		}, labels),
		LongestRunningProcessor: metric.NewGaugeVecWithLabels(metric.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "longest_running_processor_seconds",
			Help: "How many seconds has the longest running " +
				"processor for workqueue been running",
		}, labels),
	}
}

func (p WorkqueuePrometheusMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	return p.Retries.WithLabelValues(name)
}

func (p WorkqueuePrometheusMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	return p.Depth.WithLabelValues(name)
}

func (p WorkqueuePrometheusMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	return p.Adds.WithLabelValues(name)
}

func (p WorkqueuePrometheusMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	return p.Latency.WithLabelValues(name)
}

func (p WorkqueuePrometheusMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	return p.WorkDuration.WithLabelValues(name)
}

func (p WorkqueuePrometheusMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return p.UnfinishedWorkSeconds.WithLabelValues(name)
}

func (p WorkqueuePrometheusMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	return p.LongestRunningProcessor.WithLabelValues(name)
}
