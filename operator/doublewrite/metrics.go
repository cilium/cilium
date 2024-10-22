// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func NewMetrics() *Metrics {
	return &Metrics{
		IdentityCRDTotalCount: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_crd_total_count",
			Help:      "The total number of CRD identities (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityKVStoreTotalCount: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_kvstore_total_count",
			Help:      "The total number of identities in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityCRDOnlyCount: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_crd_only_count",
			Help:      "The number of CRD identities not present in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityKVStoreOnlyCount: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_identity_kvstore_only_count",
			Help:      "The number of identities in the KVStore not present as a CRD (Requires the Double-Write Identity allocation mode to be enabled)",
		}),
	}
}

type Metrics struct {
	// IdentityCRDTotalCount records the total number of CRD identities
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityCRDTotalCount metric.Gauge

	// IdentityKVStoreTotalCount records the total number of identities in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityKVStoreTotalCount metric.Gauge

	// IdentityCRDOnlyCount records the number of CRD identities not present in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityCRDOnlyCount metric.Gauge

	// IdentityKVStoreOnlyCount records the number of identities in the KVStore not present as a CRD
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityKVStoreOnlyCount metric.Gauge
}
