// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package reconciler

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

const (
	subsystem = "loadbalancer"
	typeLabel = "type"
	TypeLabelService TypeLabel = "service"
	TypeLabelBackend TypeLabel = "backend"
)

type TypeLabel string

type LBMetrics struct {
	// IDKeysAllocated is the number of keys currently allocated
	IDKeysAllocated metric.Vec[metric.Gauge]

	// IDKeysLimit is the maximum number of keys that can be allocated
	IDKeysLimit metric.Vec[metric.Gauge]

	// IDKeyspacePressure is the pressure on the ID keyspace
	IDKeyspacePressure metric.Vec[metric.Gauge]
}

type Metrics interface {
	SetKeysAllocated(typeLabel TypeLabel, current uint32)
	SetKeysLimit(typeLabel TypeLabel, limit uint32)
	SetKeyspacePressure(typeLabel TypeLabel, pressure float64)
}

var _ Metrics = (*LBMetrics)(nil)

func NewLBMetrics() *LBMetrics {
	return &LBMetrics{
		IDKeysAllocated: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name: "id_keys_allocated",
		}, []string{typeLabel}),
		IDKeysLimit: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name: "id_keys_limit",
		}, []string{typeLabel}),
		IDKeyspacePressure: metric.NewGaugeVec(metric.GaugeOpts{
			Namespace: metrics.Namespace,
			Subsystem: subsystem,
			Name: "id_keyspace_pressure",
		}, []string{typeLabel}),
	}
}

func (lb *LBMetrics) SetKeysAllocated(idType TypeLabel, allocated uint32) {
	lb.IDKeysAllocated.WithLabelValues(string(idType)).Set(float64(allocated))
}

func (lb *LBMetrics) SetKeysLimit(idType TypeLabel, limit uint32) {
	lb.IDKeysLimit.WithLabelValues(string(idType)).Set(float64(limit))
}

func (lb *LBMetrics) SetKeyspacePressure(idType TypeLabel, pressure float64) {
	lb.IDKeyspacePressure.WithLabelValues(string(idType)).Set(pressure)
}

