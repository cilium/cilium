// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type Metrics struct {
	IncrementalReconciliationCount         metric.Vec[metric.Counter]
	IncrementalReconciliationDuration      metric.Vec[metric.Observer]
	IncrementalReconciliationTotalErrors   metric.Vec[metric.Counter]
	IncrementalReconciliationCurrentErrors metric.Vec[metric.Gauge]

	FullReconciliationCount          metric.Vec[metric.Counter]
	FullReconciliationOutOfSyncCount metric.Vec[metric.Counter]
	FullReconciliationTotalErrors    metric.Vec[metric.Counter]
	FullReconciliationDuration       metric.Vec[metric.Observer]
}

const (
	LabelModuleId  = "module_id"
	LabelOperation = "op"

	OpUpdate = "update"
	OpDelete = "delete"
	OpPrune  = "prune"
)

func newMetrics() *Metrics {
	return &Metrics{
		IncrementalReconciliationCount: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_incremental_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "incremental_total",
			Help:       "Number of incremental reconciliations performed",
		}, []string{LabelModuleId}),

		IncrementalReconciliationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "_reconciler_incremental_duration_seconds",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "incremental_duration_seconds",
			Help:       "Histogram of per-operation duration during incremental reconciliation",
		}, []string{LabelModuleId, LabelOperation}),

		IncrementalReconciliationTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_incremental_errors_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "incremental_errors_total",
			Help:       "Total number of errors encountered during incremental reconciliation",
		}, []string{LabelModuleId}),

		IncrementalReconciliationCurrentErrors: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: metrics.Namespace + "_reconciler_incremental_errors_current",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "incremental_errors_current",
			Help:       "The number of objects currently failing to be reconciled",
		}, []string{LabelModuleId}),

		FullReconciliationCount: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_full_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "full_total",
			Help:       "Number of full reconciliations performed",
		}, []string{LabelModuleId}),

		FullReconciliationOutOfSyncCount: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_full_out_of_sync_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "full_out_of_sync_total",
			Help:       "Number of times full reconciliation found objects to reconcile",
		}, []string{LabelModuleId}),

		FullReconciliationTotalErrors: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: metrics.Namespace + "_reconciler_full_errors_total",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "full_errors_total",
			Help:       "Total number of errors encountered during full reconciliation",
		}, []string{LabelModuleId}),

		FullReconciliationDuration: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: metrics.Namespace + "_reconciler_full_duration_seconds",
			Disabled:   true,
			Namespace:  metrics.Namespace,
			Subsystem:  "reconciler",
			Name:       "full_duration_seconds",
			Help:       "Histogram of per-operation duration during full reconciliation",
		}, []string{LabelModuleId, LabelOperation}),
	}
}
