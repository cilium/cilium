// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package manager

import (
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type BGPManagerMetrics struct {
	// ReconcileErrorsTotal is the number of errors during reconciliation of the BGP manager.
	ReconcileErrorsTotal metric.Vec[metric.Counter]

	// ReconcileRunDuration measures the duration of the reconciliation run. Histogram can
	// be used to observe the total number of reconciliation runs and distribution of the run
	// duration.
	ReconcileRunDuration metric.Vec[metric.Observer]
}

func NewBGPManagerMetrics() *BGPManagerMetrics {
	return &BGPManagerMetrics{
		ReconcileErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileErrorsTotal,
			Help:      "The number of errors during reconciliation of the BGP manager",
		}, []string{types.LabelVRouter}),
		ReconcileRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileRunDurationSeconds,
			Help:      "The duration of the BGP manager reconciliation run",
		}, []string{types.LabelVRouter}),
	}
}
