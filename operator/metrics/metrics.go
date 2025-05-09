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

	"github.com/cilium/cilium/operator/metrics/node"
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

	WorkQueueMetrics *node.WorkqueuePrometheusMetricsProvider

	Registry *metrics.Registry
}

type metricsManager struct {
	logger     *slog.Logger
	shutdowner hive.Shutdowner

	server http.Server

	metrics []metric.WithMetadata
}

func (mm *metricsManager) Start(ctx cell.HookContext) error {
	mux := http.NewServeMux()
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

// Note: metrics are always initialized so we have access to sampler ring buffer data
// for debugging. However, actual prometheus server will be started depending on if
// metrics are enabled.
//
// Note: Some metrics are not fully integrated with the operator, specifically k8s
// controller runtime metrics register against their own global registry.
// This registry is included as part of the (*metrics).Registry.Gather() call
// but this data is not accessed from the sampler.
// Therefore the metrics stored in the sampler ring buffer are not complete and will
// miss any of the controll runtime metrics.
func initializeMetrics(p params) {
	p.Registry.MustRegister(collectors.NewGoCollector(
		collectors.WithGoCollectorRuntimeMetrics(
			collectors.GoRuntimeMetricsRule{Matcher: goCustomCollectorsRX},
		),
	))

	p.Registry.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{Namespace: metrics.CiliumOperatorNamespace}))

	for _, metric := range p.Metrics {
		p.Registry.MustRegister(metric.(prometheus.Collector))
	}

	metrics.NewLegacyMetrics()
	p.Registry.MustRegister(
		metrics.VersionMetric,
		metrics.KVStoreOperationsDuration,
		metrics.KVStoreEventsQueueDuration,
		metrics.KVStoreQuorumErrors,
		metrics.APILimiterProcessingDuration,
		metrics.APILimiterWaitDuration,
		metrics.APILimiterRequestsInFlight,
		metrics.APILimiterRateLimit,
		metrics.APILimiterProcessedRequests,

		metrics.WorkQueueDepth,
		metrics.WorkQueueAddsTotal,
		metrics.WorkQueueLatency,
		metrics.WorkQueueDuration,
		metrics.WorkQueueUnfinishedWork,
		metrics.WorkQueueLongestRunningProcessor,
		metrics.WorkQueueRetries,
	)

	metrics.InitOperatorMetrics()
	p.Registry.MustRegister(metrics.ErrorsWarnings)
	metrics.FlushLoggingMetrics()

	p.Registry.AddServerRuntimeHooks()
}
