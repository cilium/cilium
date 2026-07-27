// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	hiveJobsSubsystem = "hive_jobs"
)

const (
	labelJobModuleID = "module_id"
	labelJobName     = "job_name"
)

type hiveJobsCiliumMetrics struct {
	RunsTotal               metric.Vec[metric.Counter]
	RunsFailed              metric.Vec[metric.Counter]
	OneShotLastRunDuration  metric.Vec[metric.Gauge]
	ObserverLastRunDuration metric.Vec[metric.Gauge]
	ObserverRunDuration     metric.Vec[metric.Observer]
	TimerLastRunDuration    metric.Vec[metric.Gauge]
	TimerRunDuration        metric.Vec[metric.Observer]
}

func newHiveJobsCiliumMetrics() *hiveJobsCiliumMetrics {
	return &hiveJobsCiliumMetrics{
		RunsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "runs_total",
			Help:      "Total number of runs",
		}, []string{labelJobModuleID, labelJobName}),
		RunsFailed: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "runs_failed",
			Help:      "Number of failed runs (returned error)",
		}, []string{labelJobModuleID, labelJobName}),
		OneShotLastRunDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "oneshot_last_run_duration_seconds",
			Help:      "Duration of the last run of a oneshot job in seconds",
		}, []string{labelJobModuleID, labelJobName}),
		ObserverLastRunDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "observer_last_run_duration_seconds",
			Help:      "Duration of the last run of an observer job in seconds",
		}, []string{labelJobModuleID, labelJobName}),
		ObserverRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "observer_run_duration_seconds",
			Help:      "Duration of a run of an observer job in seconds",
			// Use buckets in the 0.5ms-1.0s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}, []string{labelJobModuleID, labelJobName}),
		TimerLastRunDuration: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "timer_last_run_duration_seconds",
			Help:      "Duration of the last run of a timer job in seconds",
		}, []string{labelJobModuleID, labelJobName}),
		TimerRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: hiveJobsSubsystem,
			Name:      "timer_run_duration_seconds",
			Help:      "Duration of a run of a timer job in seconds",
			// Use buckets in the 0.5ms-1.0s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}, []string{labelJobModuleID, labelJobName}),
	}
}

var _ job.Metrics = &hiveJobsMetricsImpl{}

type hiveJobsMetricsImpl struct {
	metrics  *hiveJobsCiliumMetrics
	moduleID string
}

func (m *hiveJobsMetricsImpl) JobError(name string, err error) {
	m.metrics.RunsFailed.WithLabelValues(m.moduleID, name).Inc()
}

func (m *hiveJobsMetricsImpl) TimerRunDuration(name string, duration time.Duration) {
	m.metrics.RunsTotal.WithLabelValues(m.moduleID, name).Inc()
	m.metrics.TimerLastRunDuration.WithLabelValues(m.moduleID, name).Set(duration.Seconds())
	m.metrics.TimerRunDuration.WithLabelValues(m.moduleID, name).Observe(duration.Seconds())
}

func (m *hiveJobsMetricsImpl) TimerTriggerStats(name string, latency time.Duration, folds int) {
	// not implemented
}

func (m *hiveJobsMetricsImpl) ObserverRunDuration(name string, duration time.Duration) {
	m.metrics.RunsTotal.WithLabelValues(m.moduleID, name).Inc()
	m.metrics.ObserverLastRunDuration.WithLabelValues(m.moduleID, name).Set(duration.Seconds())
	m.metrics.ObserverRunDuration.WithLabelValues(m.moduleID, name).Observe(duration.Seconds())
}

func (m *hiveJobsMetricsImpl) OneShotRunDuration(name string, duration time.Duration) {
	m.metrics.RunsTotal.WithLabelValues(m.moduleID, name).Inc()
	m.metrics.OneShotLastRunDuration.WithLabelValues(m.moduleID, name).Set(duration.Seconds())
}

func jobMetricsFor(metrics *hiveJobsCiliumMetrics, moduleID cell.ModuleID) *hiveJobsMetricsImpl {
	return &hiveJobsMetricsImpl{
		metrics:  metrics,
		moduleID: string(moduleID),
	}
}
