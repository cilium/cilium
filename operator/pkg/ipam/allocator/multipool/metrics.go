// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package multipool

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	multiPoolSubsystem = "ipam_multipool"

	labelPoolName = "pool"
	labelIPFamily = "family"
)

type Metrics struct {
	// TotalBlocks is the total number of CIDR blocks in the pool.
	TotalBlocks metric.DeletableVec[metric.Gauge]
}

// NewMetrics returns a new Metrics instance.
func NewMetrics() Metrics {
	return Metrics{
		TotalBlocks: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Subsystem: multiPoolSubsystem,
			Name:      "total_blocks",
			Help:      "Total number of CIDR blocks in the multi-pool IPAM pool",
		}, []string{labelPoolName, labelIPFamily}),
	}
}

// enabled reports whether a Metrics was injected.
// When no Metrics is provided (e.g. tests) the vec is nil and metric operations no-op.
func (m Metrics) enabled() bool {
	return m.TotalBlocks != nil
}

// setPool sets the total-blocks gauge for a given pool and family.
// No-op when no Metrics was injected (see enabled).
func (m Metrics) setPool(pool string, family ipam.Family, total int) {
	if !m.enabled() {
		return
	}
	m.TotalBlocks.WithLabelValues(pool, string(family)).Set(float64(total))
}

// deletePool drops both families' series for a pool once it is deleted.
// No-op when no Metrics was injected (see enabled).
func (m Metrics) deletePool(pool string) {
	if !m.enabled() {
		return
	}
	m.TotalBlocks.DeletePartialMatch(prometheus.Labels{labelPoolName: pool})
}
