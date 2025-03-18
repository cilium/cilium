// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/util/workqueue"

	operatorMetrics "github.com/cilium/cilium/operator/metrics"
	"github.com/cilium/cilium/pkg/metrics"
)

const workqueueSubsystem = "workqueue"

type WorkqueuePrometheusMetricsProvider struct {
	registry  prometheus.Registerer
	namespace string
	subsystem string
}

func NewWorkqueuePrometheusMetricsProvider() *WorkqueuePrometheusMetricsProvider {
	return &WorkqueuePrometheusMetricsProvider{
		registry:  operatorMetrics.Registry,
		namespace: metrics.CiliumOperatorNamespace,
		subsystem: workqueueSubsystem,
	}
}

func (p WorkqueuePrometheusMetricsProvider) NewDepthMetric(name string) workqueue.GaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace:   p.namespace,
		Subsystem:   p.subsystem,
		Name:        "depth",
		Help:        "Current depth of the workqueue",
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewAddsMetric(name string) workqueue.CounterMetric {
	metric := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   p.namespace,
		Subsystem:   p.subsystem,
		Name:        "adds_total",
		Help:        "Total number of adds handled by the workqueue",
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewLatencyMetric(name string) workqueue.HistogramMetric {
	metric := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   p.namespace,
		Subsystem:   p.subsystem,
		Name:        "latency",
		Help:        "How long in seconds an item stays in workqueue before being requested",
		Buckets:     prometheus.ExponentialBuckets(10e-9, 10, 10),
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewWorkDurationMetric(name string) workqueue.HistogramMetric {
	metric := prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace:   p.namespace,
		Subsystem:   p.subsystem,
		Name:        "work_duration",
		Help:        "How long in seconds processing an item from workqueue takes",
		Buckets:     prometheus.ExponentialBuckets(10e-9, 10, 10),
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewUnfinishedWorkSecondsMetric(name string) workqueue.SettableGaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      "unfinished_work_seconds",
		Help: "How many seconds of work has been done that " +
			"is in progress and hasn't been observed by work_duration. Large " +
			"values indicate stuck threads. One can deduce the number of stuck " +
			"threads by observing the rate at which this increases.",
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewLongestRunningProcessorSecondsMetric(name string) workqueue.SettableGaugeMetric {
	metric := prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: p.namespace,
		Subsystem: p.subsystem,
		Name:      "longest_running_processor_seconds",
		Help: "How many seconds has the longest running " +
			"processor for workqueue been running",
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}

func (p WorkqueuePrometheusMetricsProvider) NewRetriesMetric(name string) workqueue.CounterMetric {
	metric := prometheus.NewCounter(prometheus.CounterOpts{
		Namespace:   p.namespace,
		Subsystem:   p.subsystem,
		Name:        "retries_total",
		Help:        "Total number of retries handled by workqueue",
		ConstLabels: prometheus.Labels{"queue_name": name},
	})
	p.registry.MustRegister(metric)
	return metric
}
