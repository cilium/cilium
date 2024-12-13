// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func NewMetrics() *Metrics {
	return &Metrics{
		IdentityCRDTotal: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_crd_total",
			Help:      "The total number of CRD identities (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityKVStoreTotal: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_kvstore_total",
			Help:      "The total number of identities in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityCRDOnlyTotal: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_crd_only_total",
			Help:      "The number of CRD identities not present in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityKVStoreOnlyTotal: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_kvstore_only_total",
			Help:      "The number of identities in the KVStore not present as a CRD (Requires the Double-Write Identity allocation mode to be enabled)",
		}),
	}
}

type Metrics struct {
	// IdentityCRDTotal records the total number of CRD identities
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityCRDTotal metric.Gauge

	// IdentityKVStoreTotal records the total number of identities in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityKVStoreTotal metric.Gauge

	// IdentityCRDOnlyTotal records the number of CRD identities not present in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityCRDOnlyTotal metric.Gauge

	// IdentityKVStoreOnlyTotal records the number of identities in the KVStore not present as a CRD
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityKVStoreOnlyTotal metric.Gauge
}
