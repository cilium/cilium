// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

func NewMetrics() *Metrics {
	return &Metrics{
		IdentityCRDTotalCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "identity_crd_total_count",
			Help:      "The total number of CRD identities (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityKVStoreTotalCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "identity_kvstore_total_count",
			Help:      "The total number of identities in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityCRDOnlyCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "identity_crd_only_count",
			Help:      "The number of CRD identities not present in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		IdentityKVStoreOnlyCount: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "identity_kvstore_only_count",
			Help:      "The number of identities in the KVStore not present as a CRD (Requires the Double-Write Identity allocation mode to be enabled)",
		}),
	}
}

type Metrics struct {
	// IdentityCRDTotalCount records the total number of CRD identities
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityCRDTotalCount prometheus.Gauge

	// IdentityKVStoreTotalCount records the total number of identities in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityKVStoreTotalCount prometheus.Gauge

	// IdentityCRDOnlyCount records the number of CRD identities not present in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityCRDOnlyCount prometheus.Gauge

	// IdentityKVStoreOnlyCount records the number of identities in the KVStore not present as a CRD
	// Requires the Double-Write Identity allocation mode to be enabled
	IdentityKVStoreOnlyCount prometheus.Gauge
}
