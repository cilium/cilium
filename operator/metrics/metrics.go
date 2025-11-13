// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"log/slog"
	"regexp"

	"github.com/cilium/hive/cell"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	k8sCtrlMetrics "sigs.k8s.io/controller-runtime/pkg/certwatcher/metrics"

	"github.com/cilium/cilium/pkg/hive"
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

	Registry         *metrics.Registry
	TLSConfigPromise metrics.TLSConfigPromise
}

// Note: metrics are always initialized so we have access to sampler ring buffer data
// for debugging. However, actual prometheus server will be started depending on if
// metrics are enabled.
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

	p.Registry.Register(k8sCtrlMetrics.ReadCertificateTotal)
	p.Registry.Register(k8sCtrlMetrics.ReadCertificateErrors)

	metrics.InitOperatorMetrics()
	p.Registry.MustRegister(metrics.ErrorsWarnings)
	metrics.FlushLoggingMetrics()

	p.Registry.AddServerRuntimeHooks("operator-prometheus-server", p.TLSConfigPromise)
}
