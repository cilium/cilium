// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	controllerRuntimeMetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

type params struct {
	cell.In

	Logger     logrus.FieldLogger
	Lifecycle  cell.Lifecycle
	Shutdowner hive.Shutdowner

	Cfg       Config
	SharedCfg SharedConfig

	Metrics []metric.WithMetadata `group:"hive-metrics"`
}

type metricsManager struct {
	logger     logrus.FieldLogger
	shutdowner hive.Shutdowner

	server http.Server

	metrics []metric.WithMetadata
}

func (mm *metricsManager) Start(ctx cell.HookContext) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	mm.server.Handler = mux

	go func() {
		mm.logger.WithField("address", mm.server.Addr).Info("Starting metrics server")
		if err := mm.server.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			mm.logger.WithError(err).Error("Unable to start metrics server")
			mm.shutdowner.Shutdown()
		}
	}()

	return nil
}

func (mm *metricsManager) Stop(ctx cell.HookContext) error {
	if err := mm.server.Shutdown(ctx); err != nil {
		mm.logger.WithError(err).Error("Shutdown operator metrics server failed")
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

	if p.SharedCfg.EnableGatewayAPI {
		// Use the same Registry as controller-runtime, so that we don't need
		// to expose multiple metrics endpoints or servers.
		//
		// Ideally, we should use our own Registry instance, but the metrics
		// registration is done by init() functions, which are executed before
		// this function is called.
		Registry = controllerRuntimeMetrics.Registry
	} else {
		Registry = prometheus.NewPedanticRegistry()
	}

	Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: metrics.CiliumOperatorNamespace}))

	for _, metric := range mm.metrics {
		Registry.MustRegister(metric.(prometheus.Collector))
	}

	p.Lifecycle.Append(mm)
}
