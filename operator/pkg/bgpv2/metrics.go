// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package bgpv2

import (
	"github.com/cilium/cilium/pkg/bgpv1/types"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// BGPOperatorMetrics contains all metrics for the BGP control plane operator.
type BGPOperatorMetrics struct {
	// ReconcileErrorsTotal is the number of errors during reconciliation of BGP configuration.
	ReconcileErrorsTotal metric.Vec[metric.Counter]

	// ReconcileRunDuration measures the duration of the reconciliation run. Histogram can
	// be used to observe the total number of reconciliation runs and distribution of the run duration.
	ReconcileRunDuration metric.Vec[metric.Observer]
}

// NewBGPOperatorMetrics returns a new BGPOperatorMetrics with all metrics initialized.
func NewBGPOperatorMetrics() *BGPOperatorMetrics {
	return &BGPOperatorMetrics{
		ReconcileErrorsTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileErrorsTotal,
			Help:      "The number of errors during reconciliation of the cluster configuration.",
		}, []string{types.LabelResourceKind, types.LabelResourceName}),
		ReconcileRunDuration: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.Namespace,
			Subsystem: types.MetricsSubsystem,
			Name:      types.MetricReconcileRunDurationSeconds,
			Help:      "The duration of the BGP reconciliation run",
		}, nil),
	}
}
