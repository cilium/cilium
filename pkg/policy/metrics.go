// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/policy/types"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	selectorCacheMetricsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metrics.CiliumAgentNamespace, "policy_selector", "match_count_max"),
		"The maximum number of identities selected by a network policy peer selector",
		[]string{types.LabelSelectorClass},
		nil,
	)

	selectorCacheSelectorCount = prometheus.NewDesc(
		prometheus.BuildFQName(metrics.CiliumAgentNamespace, "policy_selector_cache", "selectors"),
		"The number of selectors in the selector cache",
		[]string{metrics.LabelType},
		nil,
	)

	selectorCacheIdentityCount = prometheus.NewDesc(
		prometheus.BuildFQName(metrics.CiliumAgentNamespace, "policy_selector_cache", "identities"),
		"The number of identities in the selector cache",
		[]string{metrics.LabelType},
		nil,
	)

	selectorCacheOperationDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: metrics.CiliumAgentNamespace,
		Subsystem: "policy_selector_cache",
		Name:      "operation_duration_seconds",
		Help:      "The latency of selector cache operations",
		Buckets:   []float64{0.0005, 0.001, 0.005, 0.025, 0.05, 0.1, 0.2, 0.4},
	}, []string{metrics.LabelOperation, metrics.LabelScope, metrics.LabelType})
)

type selectorStats struct {
	maxCardinalityByClass map[string]int
	selectors             int
	identities            int
}

func newSelectorStats() selectorStats {
	return selectorStats{
		maxCardinalityByClass: map[string]int{
			types.LabelValueSCFQDN:    0,
			types.LabelValueSCCluster: 0,
			types.LabelValueSCWorld:   0,
			types.LabelValueSCOther:   0,
		},
	}
}

type selectorStatsCollector interface {
	Stats() selectorStats
}

type selectorCacheMetrics struct {
	prometheus.Collector
	selectorStatsCollector
}

func newSelectorCacheMetrics(sc selectorStatsCollector) prometheus.Collector {
	return &selectorCacheMetrics{
		selectorStatsCollector: sc,
	}
}

func (scm *selectorCacheMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- selectorCacheMetricsDesc
	ch <- selectorCacheSelectorCount
	ch <- selectorCacheIdentityCount
}

func (scm *selectorCacheMetrics) Collect(ch chan<- prometheus.Metric) {
	stats := scm.selectorStatsCollector.Stats()

	for class, stat := range stats.maxCardinalityByClass {
		ch <- prometheus.MustNewConstMetric(
			selectorCacheMetricsDesc, prometheus.GaugeValue, float64(stat), class,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		selectorCacheSelectorCount, prometheus.GaugeValue, float64(stats.selectors), types.LabelValueSCTypePeer)
	ch <- prometheus.MustNewConstMetric(
		selectorCacheIdentityCount, prometheus.GaugeValue, float64(stats.identities), types.LabelValueSCTypePeer)
}
