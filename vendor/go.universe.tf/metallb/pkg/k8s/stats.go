package k8s

import "github.com/prometheus/client_golang/prometheus"

var (
	updates = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "metallb",
		Subsystem: "k8s_client",
		Name:      "updates_total",
		Help:      "Number of k8s object updates that have been processed.",
	})

	updateErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "metallb",
		Subsystem: "k8s_client",
		Name:      "update_errors_total",
		Help:      "Number of k8s object updates that failed for some reason.",
	})

	configLoaded = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "metallb",
		Subsystem: "k8s_client",
		Name:      "config_loaded_bool",
		Help:      "1 if the MetalLB configuration was successfully loaded at least once.",
	})

	configStale = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "metallb",
		Subsystem: "k8s_client",
		Name:      "config_stale_bool",
		Help:      "1 if running on a stale configuration, because the latest config failed to load.",
	})
)

func init() {
	prometheus.MustRegister(updates)
	prometheus.MustRegister(updateErrors)
	prometheus.MustRegister(configLoaded)
	prometheus.MustRegister(configStale)
}
