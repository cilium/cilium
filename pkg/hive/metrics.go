// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"time"

	"github.com/cilium/hive"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	hiveSubsystem = "hive"
)

type hiveCiliumMetrics struct {
	StartDuration    metric.Vec[metric.Gauge]
	StopDuration     metric.Vec[metric.Gauge]
	PopulateDuration metric.Vec[metric.Gauge]
}

func newHiveCiliumMetrics() *hiveCiliumMetrics {
	return &hiveCiliumMetrics{
		StartDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveSubsystem,
			Name:      "start_duration",
			Help:      "Hive start duration",
		}, []string{}),
		StopDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: hiveSubsystem,
			Name:      "stop_duration",
			Help:      "Hive stop duration",
		}, []string{}),
		PopulateDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveSubsystem,
			Name:      "populate_duration",
			Help:      "Hive populate duration",
		}, []string{}),
	}
}

var _ hive.Metrics = &hiveMetricsImpl{}

type hiveMetricsImpl struct {
	metrics *hiveCiliumMetrics
}

func (m *hiveMetricsImpl) StartDuration(duration time.Duration) {
	m.metrics.StartDuration.WithLabelValues().Set(duration.Seconds())
}

func (m *hiveMetricsImpl) StopDuration(duration time.Duration) {
	m.metrics.StopDuration.WithLabelValues().Set(duration.Seconds())
}

func (m *hiveMetricsImpl) PopulateDuration(duration time.Duration) {
	m.metrics.PopulateDuration.WithLabelValues().Set(duration.Seconds())
}

func hiveMetrics(metrics *hiveCiliumMetrics) hive.Metrics {
	return &hiveMetricsImpl{
		metrics: metrics,
	}
}
