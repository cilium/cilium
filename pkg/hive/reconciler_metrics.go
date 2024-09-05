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
		}, []string{labelModuleId}),

		ReconciliationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "duration_seconds",
			Help:      "Histogram of per-operation duration during reconciliation",
		}, []string{labelModuleId, labelOperation}),

		ReconciliationTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "errors_total",
			Help:      "Total number of errors encountered during reconciliation",
		}, []string{labelModuleId}),

		ReconciliationCurrentErrors: metric.NewGaugeVec(metric.GaugeOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "errors_current",
			Help:      "The number of objects currently failing to be reconciled",
		}, []string{labelModuleId}),

		PruneCount: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "prune_count",
			Help:      "Number of prunes performed",
		}, []string{labelModuleId}),

		PruneTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "prune_errors_total",
			Help:      "Total number of errors encountered during pruning",
		}, []string{labelModuleId}),

		PruneDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Disabled:  true,
			Namespace: metrics.Namespace,
			Subsystem: "reconciler",
			Name:      "prune_duration_seconds",
			Help:      "Histogram of pruning duration",
		}, []string{labelModuleId}),
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
func (m *reconcilerMetricsImpl) PruneDuration(moduleID cell.FullModuleID, duration time.Duration) {
	if m.m.PruneDuration.IsEnabled() {
		m.m.PruneDuration.WithLabelValues(moduleID.String()).
			Observe(duration.Seconds())
	}
}

// FullReconciliationErrors implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) PruneError(moduleID cell.FullModuleID, err error) {
	if m.m.PruneCount.IsEnabled() {
		m.m.PruneCount.WithLabelValues(moduleID.String()).Inc()
	}
	if err != nil && m.m.PruneTotalErrors.IsEnabled() {
		m.m.PruneTotalErrors.WithLabelValues(moduleID.String()).Add(1)
	}
}

// ReconciliationDuration implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) ReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration) {
	if m.m.ReconciliationCount.IsEnabled() {
		m.m.ReconciliationCount.WithLabelValues(moduleID.String()).Inc()
	}
	if m.m.ReconciliationDuration.IsEnabled() {
		m.m.ReconciliationDuration.WithLabelValues(moduleID.String(), operation).
			Observe(duration.Seconds())
	}
}

// ReconciliationErrors implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) ReconciliationErrors(moduleID cell.FullModuleID, new, current int) {
	if m.m.ReconciliationCurrentErrors.IsEnabled() {
		m.m.ReconciliationCurrentErrors.WithLabelValues(moduleID.String()).Set(float64(current))
	}
	if m.m.ReconciliationTotalErrors.IsEnabled() {
		m.m.ReconciliationCurrentErrors.WithLabelValues(moduleID.String()).Add(float64(new))
	}
}

var _ reconciler.Metrics = &reconcilerMetricsImpl{}
