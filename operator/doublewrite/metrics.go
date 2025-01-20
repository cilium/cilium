// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package doublewrite

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func NewMetrics() *Metrics {
	return &Metrics{
		CRDIdentities: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_crd_identities",
			Help:      "The total number of CRD identities (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		KVStoreIdentities: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_kvstore_identities",
			Help:      "The total number of identities in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		CRDOnlyIdentities: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_crd_only_identities",
			Help:      "The number of CRD identities not present in the KVStore (Requires the Double-Write Identity allocation mode to be enabled)",
		}),

		KVStoreOnlyIdentities: metric.NewGauge(metric.GaugeOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "doublewrite_kvstore_only_identities",
			Help:      "The number of identities in the KVStore not present as a CRD (Requires the Double-Write Identity allocation mode to be enabled)",
		}),
	}
}

type Metrics struct {
	// CRDIdentities records the total number of CRD identities
	// Requires the Double-Write Identity allocation mode to be enabled
	CRDIdentities metric.Gauge

	// KVStoreIdentities records the total number of identities in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	KVStoreIdentities metric.Gauge

	// CRDOnlyIdentities records the number of CRD identities not present in the KVStore
	// Requires the Double-Write Identity allocation mode to be enabled
	CRDOnlyIdentities metric.Gauge

	// KVStoreOnlyIdentities records the number of identities in the KVStore not present as a CRD
	// Requires the Double-Write Identity allocation mode to be enabled
	KVStoreOnlyIdentities metric.Gauge
}
