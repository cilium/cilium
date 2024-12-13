// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"github.com/cilium/cilium/pkg/metrics"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// LabelSelectorClass indicates the class of selector being measured
	LabelSelectorClass = "class"

	// LabelValueSCFQDN is used for regular security identities
	// shared between all nodes in the cluster.
	LabelValueSCFQDN = "fqdn"

	// LabelValueSCCluster is used for the cluster entity.
	LabelValueSCCluster = "cluster"

	// LabelValueSCWorld is used for the world entity.
	LabelValueSCWorld = "world"

	// LabelValueSCOther is used for security identities allocated locally
	// on the current node.
	LabelValueSCOther = "other"
)

var (
	selectorCacheMetricsDesc = prometheus.NewDesc(
		prometheus.BuildFQName(metrics.CiliumAgentNamespace, "policy_selector", "match_count_max"),
		"The maximum number of identities selected by a network policy peer selector",
		[]string{LabelSelectorClass},
		nil,
	)
)

type selectorStats struct {
	maxCardinalityByClass map[string]int
}

func newSelectorStats() selectorStats {
	return selectorStats{
		maxCardinalityByClass: map[string]int{
			LabelValueSCFQDN:    0,
			LabelValueSCCluster: 0,
			LabelValueSCWorld:   0,
			LabelValueSCOther:   0,
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
