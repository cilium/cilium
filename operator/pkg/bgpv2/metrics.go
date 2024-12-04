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
	// BGPClusterConfigErrorCount is the number of errors during reconciliation of the cluster
	// configuration.
	BGPClusterConfigErrorCount metric.Vec[metric.Counter]
}

// NewBGPOperatorMetrics returns a new BGPOperatorMetrics with all metrics initialized.
func NewBGPOperatorMetrics() *BGPOperatorMetrics {
	return &BGPOperatorMetrics{
		BGPClusterConfigErrorCount: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: types.MetricsSubsystem,
			Name:      "cluster_config_error_count",
			Help:      "The number of errors during reconciliation of the cluster configuration.",
		}, []string{types.LabelClusterConfig}),
	}
}
