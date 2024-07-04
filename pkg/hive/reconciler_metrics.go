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
	LabelModuleId  = "module_id"
	LabelOperation = "op"
)

func NewStateDBReconcilerMetrics() (ReconcilerMetrics, reconciler.Metrics) {
	m := ReconcilerMetrics{
		ReconciliationCount: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_count",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "count",
			Help:       "Number of reconciliation rounds performed",
		}, []string{LabelModuleId}),

		ReconciliationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "_reconciler_duration_seconds",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "duration_seconds",
			Help:       "Histogram of per-operation duration during reconciliation",
		}, []string{LabelModuleId, LabelOperation}),

		ReconciliationTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_errors_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "errors_total",
			Help:       "Total number of errors encountered during reconciliation",
		}, []string{LabelModuleId}),

		ReconciliationCurrentErrors: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_reconciler_errors_current",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "errors_current",
			Help:       "The number of objects currently failing to be reconciled",
		}, []string{LabelModuleId}),

		PruneCount: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_prune_count",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "prune_count",
			Help:       "Number of prunes performed",
		}, []string{LabelModuleId}),

		PruneTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_prune_errors_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "full_errors_total",
			Help:       "Total number of errors encountered during full reconciliation",
		}, []string{LabelModuleId}),

		PruneDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "_reconciler_prune_duration_seconds",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "full_duration_seconds",
			Help:       "Histogram of per-operation duration during full reconciliation",
		}, []string{LabelModuleId, LabelOperation}),
	}
	return m, &reconcilerMetricsImpl{m}
}

type reconcilerMetricsImpl struct {
	m ReconcilerMetrics
}

// PruneDuration implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) PruneDuration(moduleID cell.FullModuleID, duration time.Duration) {
	if m.m.PruneDuration.IsEnabled() {
		m.m.PruneDuration.WithLabelValues(LabelModuleId, moduleID.String()).
			Observe(duration.Seconds())
	}
}

// FullReconciliationErrors implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) PruneError(moduleID cell.FullModuleID, err error) {
	if m.m.PruneCount.IsEnabled() {
		m.m.PruneCount.WithLabelValues(LabelModuleId, moduleID.String())
	}
	if m.m.PruneTotalErrors.IsEnabled() {
		m.m.PruneTotalErrors.WithLabelValues(moduleID.String()).Add(1)
	}
}

// ReconciliationDuration implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) ReconciliationDuration(moduleID cell.FullModuleID, operation string, duration time.Duration) {
	if m.m.ReconciliationCount.IsEnabled() {
		m.m.ReconciliationCount.WithLabelValues(LabelModuleId, moduleID.String()).Inc()
	}
	if m.m.ReconciliationDuration.IsEnabled() {
		m.m.ReconciliationDuration.WithLabelValues(LabelModuleId, moduleID.String(), LabelOperation, operation).
			Observe(duration.Seconds())
	}
}

// ReconciliationErrors implements reconciler.Metrics.
func (m *reconcilerMetricsImpl) ReconciliationErrors(moduleID cell.FullModuleID, new, current int) {
	if m.m.ReconciliationCurrentErrors.IsEnabled() {
		m.m.ReconciliationCurrentErrors.WithLabelValues(LabelModuleId, moduleID.String()).Set(float64(current))
	}
	if m.m.ReconciliationTotalErrors.IsEnabled() {
		m.m.ReconciliationCurrentErrors.WithLabelValues(LabelModuleId, moduleID.String()).Add(float64(new))
	}
}

var _ reconciler.Metrics = &reconcilerMetricsImpl{}
