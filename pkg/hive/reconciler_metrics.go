// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package hive

import (
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/statedb/reconciler"

	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type ReconcilerMetrics struct {
	ReconciliationCount         metric.Vec[metric.Counter]
	ReconciliationDuration      metric.Vec[metric.Observer]
	ReconciliationTotalErrors   metric.Vec[metric.Counter]
	ReconciliationCurrentErrors metric.Vec[metric.Gauge]

	PruneCount       metric.Vec[metric.Counter]
	PruneTotalErrors metric.Vec[metric.Counter]
	PruneDuration    metric.Vec[metric.Observer]
}

const (
	labelModuleId  = "module_id"
	labelName      = "name"
	labelOperation = "op"
)

func NewStateDBReconcilerMetrics() ReconcilerMetrics {
	m := ReconcilerMetrics{
		ReconciliationCount: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "count",
			Help:      "Number of reconciliation rounds performed",
		}, []string{labelModuleId, labelName}),

		ReconciliationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "duration_seconds",
			Help:      "Histogram of per-operation duration during reconciliation",
			// Use buckets in the 0.5ms-1s range.
			Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, 0.1, 0.25, 0.5, 1.0},
		}, []string{labelModuleId, labelName, labelOperation}),

		ReconciliationTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "errors_total",
			Help:      "Total number of errors encountered during reconciliation",
		}, []string{labelModuleId, labelName}),

		ReconciliationCurrentErrors: metric.NewGaugeVec(metric.GaugeOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "errors_current",
			Help:      "The number of objects currently failing to be reconciled",
		}, []string{labelModuleId, labelName}),

		PruneCount: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "prune_count",
			Help:      "Number of prunes performed",
		}, []string{labelModuleId, labelName}),

		PruneTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "prune_errors_total",
			Help:      "Total number of errors encountered during pruning",
		}, []string{labelModuleId, labelName}),

		PruneDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "prune_duration_seconds",
			Help:      "Histogram of pruning duration",
		}, []string{labelModuleId, labelName}),
	}
	return m
}

func NewStateDBReconcilerMetricsImpl(m ReconcilerMetrics) reconciler.Metrics {
	return &reconcilerMetricsImpl{m}
}

type reconcilerMetricsImpl struct {
	m ReconcilerMetrics
}

// PruneDuration implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) PruneDuration(moduleID cell.FullModuleID, name string, duration time.Duration) {
	m.m.PruneDuration.WithLabelValues(moduleID.String(), name).
		Observe(duration.Seconds())
}

// FullReconciliationErrors implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) PruneError(moduleID cell.FullModuleID, name string, err error) {
	mod := moduleID.String()
	m.m.PruneCount.WithLabelValues(mod, name).Inc()
	if err != nil {
		m.m.PruneTotalErrors.WithLabelValues(mod, name).Add(1)
	}
}

// ReconciliationDuration implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) ReconciliationDuration(moduleID cell.FullModuleID, name string, operation string, duration time.Duration) {
	mod := moduleID.String()
	m.m.ReconciliationCount.WithLabelValues(mod, name).Inc()
	m.m.ReconciliationDuration.WithLabelValues(mod, name, operation).
		Observe(duration.Seconds())
}

// ReconciliationErrors implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) ReconciliationErrors(moduleID cell.FullModuleID, name string, new, current int) {
	mod := moduleID.String()
	m.m.ReconciliationCurrentErrors.WithLabelValues(mod, name).Set(float64(current))
	m.m.ReconciliationCurrentErrors.WithLabelValues(mod, name).Add(float64(new))
}

var _ reconciler.Metrics = &reconcilerMetricsImpl{}
