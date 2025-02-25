// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	controllerRuntimeMetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// goCustomCollectorsRX tracks enabled go runtime metrics.
var goCustomCollectorsRX = regexp.MustCompile(`^/sched/latencies:seconds`)

type params struct {
	cell.In

	Logger     *slog.Logger
	Lifecycle  cell.Lifecycle
	Shutdowner hive.Shutdowner

	Cfg       Config
	SharedCfg SharedConfig

	Metrics []metric.WithMetadata `group:"hive-metrics"`
}

type metricsManager struct {
	logger     *slog.Logger
	shutdowner hive.Shutdowner

	server http.Server

	metrics []metric.WithMetadata
}

func (mm *metricsManager) Start(ctx cell.HookContext) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	mm.server.Handler = mux

	go func() {
		mm.logger.Info("Starting metrics server", logfields.Address, mm.server.Addr)
		if err := mm.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			mm.logger.Error("Unable to start metrics server", logfields.Error, err)
			mm.shutdowner.Shutdown()
		}
	}()

	return nil
}

func (mm *metricsManager) Stop(ctx cell.HookContext) error {
	if err := mm.server.Shutdown(ctx); err != nil {
		mm.logger.Error("Shutdown operator metrics server failed", logfields.Error, err)
		return err
	}
	return nil
}

func registerMetricsManager(p params) {
	if !p.SharedCfg.EnableMetrics {
		return
	}

	mm := &metricsManager{
		logger:     p.Logger,
		shutdowner: p.Shutdowner,
		server:     http.Server{Addr: p.Cfg.OperatorPrometheusServeAddr},
		metrics:    p.Metrics,
	}

	// Use the same Registry as controller-runtime, so that we don't need
	// to expose multiple metrics endpoints or servers.
	//
	// Ideally, we should use our own Registry instance, but the metrics
	// registration is done by init() functions, which are executed before
	// this function is called.
	Registry = controllerRuntimeMetrics.Registry

	// Unregister default Go collector that is added by default by the controller-runtime library.
	// This is necessary to be able to register a Go collector with additional runtime metrics
	// without any clashes with the existing Go collector.
	Registry.Unregister(collectors.NewGoCollector())

	Registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		),
	))

	Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: metrics.CiliumOperatorNamespace}))

	for _, metric := range mm.metrics {
		Registry.MustRegister(metric.(prometheus.Collector))
	}

	// Constructing the legacy metrics and register them at the metrics global variable.
	// This is a hack until we can unify this metrics manager with the metrics.Registry.
	metrics.NewLegacyMetrics()
	Registry.MustRegister(
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

	metrics.InitOperatorMetrics()
	Registry.MustRegister(metrics.ErrorsWarnings)
	metrics.FlushLoggingMetrics()

	p.Lifecycle.Append(mm)
}
