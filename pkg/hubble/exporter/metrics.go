// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package exporter

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/hubble/metrics/api"
	"github.com/cilium/cilium/pkg/time"
)

var (
	labelExporterStatus = "status"
	exportersDesc       = prometheus.NewDesc(
		prometheus.BuildFQName(api.DefaultPrometheusNamespace, "dynamic_exporter", "exporters_total"),
		"Number of configured exporters",
		[]string{labelExporterStatus},
		nil,
	)

	labelExporterName       = "name"
	individualExportersDesc = prometheus.NewDesc(
		prometheus.BuildFQName(api.DefaultPrometheusNamespace, "dynamic_exporter", "up"),
		"Status of individual exporters",
		[]string{labelExporterName},
		nil,
	)

	labelReconfigurationOperation   = "op"
	DynamicExporterReconfigurations = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Subsystem: "dynamic_exporter",
		Name:      "reconfigurations_total",
		Help:      "Number of dynamic exporters reconfigurations",
	}, []string{labelReconfigurationOperation})

	DynamicExporterConfigHash = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Subsystem: "dynamic_exporter",
		Name:      "config_hash",
		Help:      "Hash of last applied config",
	}, []string{})

	DynamicExporterConfigLastApplied = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: api.DefaultPrometheusNamespace,
		Subsystem: "dynamic_exporter",
		Name:      "config_last_applied",
		Help:      "Timestamp of last applied config",
	}, []string{})
)

func registerMetrics(exp *DynamicExporter) {
	metrics.Registry.MustRegister(&dynamicExporterGaugeCollector{exporter: exp})
	metrics.Registry.MustRegister(DynamicExporterReconfigurations)
	metrics.Registry.MustRegister(DynamicExporterConfigHash)
	metrics.Registry.MustRegister(DynamicExporterConfigLastApplied)
}

type dynamicExporterGaugeCollector struct {
	prometheus.Collector
	exporter *DynamicExporter
}

// Describe sends the super-set of all possible descriptors of metrics
// collected by this Collector to the provided channel and returns once
// the last descriptor has been sent. The sent descriptors fulfill the
// consistency and uniqueness requirements described in the Desc
// documentation.
func (d *dynamicExporterGaugeCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- exportersDesc
	ch <- individualExportersDesc
}

// Collect is called by the Prometheus registry when collecting
// metrics. The implementation sends each collected metric via the
// provided channel and returns once the last metric has been sent. The
// descriptor of each sent metric is one of those returned by Describe.
// Returned metrics that share the same descriptor must differ in their
// variable label values.
func (d *dynamicExporterGaugeCollector) Collect(ch chan<- prometheus.Metric) {
	var activeExporters, inactiveExporters float64

	for name, me := range d.exporter.managedExporters {
		var value float64
		if me.config.End == nil || me.config.End.After(time.Now()) {
			value = 1
			activeExporters++
		} else {
			inactiveExporters++
		}
		ch <- prometheus.MustNewConstMetric(
			individualExportersDesc, prometheus.GaugeValue, value, name,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		exportersDesc, prometheus.GaugeValue, activeExporters, "active",
	)
	ch <- prometheus.MustNewConstMetric(
		exportersDesc, prometheus.GaugeValue, inactiveExporters, "inactive",
	)
}
