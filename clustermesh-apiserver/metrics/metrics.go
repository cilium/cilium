// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/option"
)

var Cell = cell.Module(
	"clustermesh-apiserver-metrics",
	"ClusterMesh apiserver metrics",

	cell.Config(MetricsConfig{}),
	cell.Invoke(registerMetricsManager),
)

var log = logging.DefaultLogger.WithField(logfields.LogSubsys, "metrics")

type MetricsConfig struct {
	// PrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	PrometheusServeAddr string
}

func (def MetricsConfig) Flags(flags *pflag.FlagSet) {
	flags.String(option.PrometheusServeAddr, def.PrometheusServeAddr, "Address to serve Prometheus metrics")
}

type metricsManager struct {
	registry *prometheus.Registry
	server   http.Server
}

func registerMetricsManager(lc hive.Lifecycle, cfg MetricsConfig) error {
	manager := metricsManager{
		registry: prometheus.NewPedanticRegistry(),
		server:   http.Server{Addr: cfg.PrometheusServeAddr},
	}

	if cfg.PrometheusServeAddr != "" {
		lc.Append(&manager)
	} else {
		log.Info("Prometheus metrics are disabled")
	}

	return nil
}

func (mm *metricsManager) Start(hive.HookContext) error {
	log.Info("Registering metrics")

	mm.registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))
	mm.registry.MustRegister(collectors.NewGoCollector())
	mm.registry.MustRegister(
		metrics.KVStoreOperationsDuration,
		metrics.KVStoreEventsQueueDuration,
		metrics.KVStoreQuorumErrors,
		metrics.KVStoreSyncQueueSize,
		metrics.KVStoreInitialSyncCompleted,
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(mm.registry, promhttp.HandlerOpts{}))
	mm.server.Handler = mux

	go func() {
		log.WithField("address", mm.server.Addr).Info("Starting metrics server")
		if err := mm.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			log.WithError(err).Fatal("Unable to start metrics server")
		}
	}()

	return nil
}

func (mm *metricsManager) Stop(ctx hive.HookContext) error {
	log.Info("Stopping metrics server")

	if err := mm.server.Shutdown(ctx); err != nil {
		log.WithError(err).Error("Shutdown metrics server failed")
		return err
	}

	return nil
}
