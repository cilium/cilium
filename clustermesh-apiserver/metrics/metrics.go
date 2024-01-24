// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"metrics",
	"Metrics",

	cell.Config(MetricsConfig{}),
	cell.Invoke(registerMetricsManager),
)

type MetricsConfig struct {
	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr string
}

func (def MetricsConfig) Flags(flags *pflag.FlagSet) {
	flags.String(option.PrometheusServeAddr, def.PrometheusServeAddr, "Address to serve Prometheus metrics")
}

type metricsManager struct {
	logger   logrus.FieldLogger
	registry *prometheus.Registry
	server   http.Server

	metrics []metric.WithMetadata
}

type params struct {
	cell.In
	Logger logrus.FieldLogger

	MetricsConfig
	Metrics []metric.WithMetadata `group:"hive-metrics"`
}

func registerMetricsManager(lc cell.Lifecycle, params params) error {
	manager := metricsManager{
		logger:   params.Logger,
		registry: prometheus.NewPedanticRegistry(),
		server:   http.Server{Addr: params.PrometheusServeAddr},
		metrics:  params.Metrics,
	}

	if params.PrometheusServeAddr != "" {
		lc.Append(&manager)
	} else {
		manager.logger.Info("Prometheus metrics are disabled")
	}

	return nil
}

func (mm *metricsManager) Start(cell.HookContext) error {
	mm.logger.Info("Registering metrics")

	mm.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mm.registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: regexp.MustCompile(`^/sched/latencies:seconds`)},
		),
	))
	// Constructing the legacy metrics and register them at the metrics global variable.
	// This is a hack until we can unify this metrics manager with the metrics.Registry.
	metrics.NewLegacyMetrics()
	mm.registry.MustRegister(
		metrics.VersionMetric,
		metrics.KVStoreOperationsDuration,
		metrics.KVStoreEventsQueueDuration,
		metrics.KVStoreQuorumErrors,
		metrics.APILimiterProcessingDuration,
		metrics.APILimiterWaitDuration,
		metrics.APILimiterRequestsInFlight,
		metrics.APILimiterRateLimit,
		metrics.APILimiterProcessedRequests,
	)

	for _, metric := range mm.metrics {
		mm.registry.MustRegister(metric.(prometheus.Collector))
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(mm.registry, promhttp.HandlerOpts{}))
	mm.server.Handler = mux

	go func() {
		mm.logger.WithField("address", mm.server.Addr).Info("Starting metrics server")
		if err := mm.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			mm.logger.WithError(err).Fatal("Unable to start metrics server")
		}
	}()

	return nil
}

func (mm *metricsManager) Stop(ctx cell.HookContext) error {
	mm.logger.Info("Stopping metrics server")

	if err := mm.server.Shutdown(ctx); err != nil {
		mm.logger.WithError(err).Error("Shutdown metrics server failed")
		return err
	}

	return nil
}
