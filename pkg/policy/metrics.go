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
)

type selectorStats struct {
	maxCardinalityByClass map[string]int
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
	return &selectorCacheMetrics{selectorStatsCollector: sc}
}

func (scm *selectorCacheMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- selectorCacheMetricsDesc
}

func (scm *selectorCacheMetrics) Collect(ch chan<- prometheus.Metric) {
	stats := scm.selectorStatsCollector.Stats()

	for class, stat := range stats.maxCardinalityByClass {
		ch <- prometheus.MustNewConstMetric(
			selectorCacheMetricsDesc, prometheus.GaugeValue, float64(stat), class,
		)
	}
}
