// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/spf13/pflag"
	controllerRuntimeMetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

var defaultOperatorRegistryConfig = OperatorRegistryConfig{
	OperatorPrometheusServeAddr: ":9963",
}

type OperatorRegistryConfig struct {
	// OperatorPrometheusServeAddr IP:Port on which to serve prometheus metrics (pass ":Port" to bind on all interfaces, "" is off)
	OperatorPrometheusServeAddr string
	EnableMetrics               bool
	// This is a list of metrics to be enabled or disabled, format is `+`/`-` + `{metric name}`
	Metrics []string
}

func (rc OperatorRegistryConfig) Flags(flags *pflag.FlagSet) {
	flags.String("operator-prometheus-serve-addr", rc.OperatorPrometheusServeAddr, "IP:Port on which to serve prometheus metrics (pass \":Port\" to bind on all interfaces, \"\" is off)")
	flags.Bool("enable-metrics", rc.EnableMetrics, "Enable Prometheus metrics")
	flags.StringSlice("metrics", rc.Metrics, "Metrics that should be enabled or disabled from the default metric list. (+metric_foo to enable metric_foo, -metric_bar to disable metric_bar)")
}

func (rc OperatorRegistryConfig) GetMetrics() []string {
	return rc.Metrics
}

func (rc OperatorRegistryConfig) GetServeAddr() string {
	if !rc.EnableMetrics {
		return ""
	}

	return rc.OperatorPrometheusServeAddr
}

// Namespace is the namespace key to use for cilium operator metrics.
const Namespace = "cilium_operator"

var (
	// IdentityGCSize records the identity GC results
	IdentityGCSize *prometheus.GaugeVec

	// IdentityGCRuns records how many times identity GC has run
	IdentityGCRuns *prometheus.GaugeVec

	// EndpointGCObjects records the number of times endpoint objects have been
	// garbage-collected.
	EndpointGCObjects *prometheus.CounterVec

	// CiliumEndpointSliceDensity indicates the number of CEPs batched in a CES and it used to
	// collect the number of CEPs in CES at various buckets.
	CiliumEndpointSliceDensity prometheus.Histogram

	// CiliumEndpointsChangeCount indicates the total number of CEPs changed for every CES request sent to k8s-apiserver.
	// This metric is used to collect number of CEP changes happening at various buckets.
	CiliumEndpointsChangeCount *prometheus.HistogramVec

	// CiliumEndpointSliceSyncTotal indicates the total number of completed CES syncs with k8s-apiserver by success/fail outcome.
	CiliumEndpointSliceSyncTotal *prometheus.CounterVec

	// CiliumEndpointSliceSyncErrors used to track the total number of errors occurred during syncing CES with k8s-apiserver.
	// This metric is going to be deprecated in Cilium 1.14 and removed in 1.15.
	// It is replaced by CiliumEndpointSliceSyncTotal metric.
	CiliumEndpointSliceSyncErrors prometheus.Counter

	// CiliumEndpointSliceQueueDelay measures the time spent by CES's in the workqueue. This measures time difference between
	// CES insert in the workqueue and removal from workqueue.
	CiliumEndpointSliceQueueDelay prometheus.Histogram
)

const (
	// LabelStatus marks the status of a resource or completed task
	LabelStatus = "status"

	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelOpcode indicates the kind of CES metric, could be CEP insert or remove
	LabelOpcode = "opcode"

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelValueOutcomeAlive is used as outcome of alive identity entries
	LabelValueOutcomeAlive = "alive"

	// LabelValueOutcomeDeleted is used as outcome of deleted identity entries
	LabelValueOutcomeDeleted = "deleted"

	// LabelValueCEPInsert is used to indicate the number of CEPs inserted in a CES
	LabelValueCEPInsert = "cepinserted"

	// LabelValueCEPRemove is used to indicate the number of CEPs removed from a CES
	LabelValueCEPRemove = "cepremoved"
)

func registerDefaultMetrics(r *metrics.Registry, config *operatorOption.OperatorConfig) {
	r.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{Namespace: Namespace}))

	if config.EnableGatewayAPI {
		// If API gateway is enabled, add the registry used by the controller runtime to our main
		// registry. This works because *prometheus.Registry implements prometheus.Collector
		// which will collect all metrics registered so the output is merged.
		r.MustRegister(controllerRuntimeMetrics.Registry.(prometheus.Collector))
	}
}

type LegacyMetrics struct {
	IdentityGCSize                metric.Vec[metric.Gauge]
	IdentityGCRuns                metric.Vec[metric.Gauge]
	EndpointGCObjects             metric.Vec[metric.Counter]
	CiliumEndpointSliceDensity    metric.Histogram
	CiliumEndpointsChangeCount    metric.Vec[metric.Observer]
	CiliumEndpointSliceSyncTotal  metric.Vec[metric.Counter]
	CiliumEndpointSliceSyncErrors metric.Counter
	CiliumEndpointSliceQueueDelay metric.Histogram
}

func NewLegacyMetrics() *LegacyMetrics {
	return &LegacyMetrics{
		IdentityGCSize: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_identity_gc_entries",
			Namespace:  Namespace,
			Name:       "identity_gc_entries",
			Help:       "The number of alive and deleted identities at the end of a garbage collector run",
		}, []string{LabelStatus}),

		IdentityGCRuns: metric.NewGaugeVec(metric.GaugeOpts{
			ConfigName: Namespace + "_identity_gc_runs",
			Namespace:  Namespace,
			Name:       "identity_gc_runs",
			Help:       "The number of times identity garbage collector has run",
		}, []string{LabelOutcome}),

		EndpointGCObjects: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_endpoint_gc_objects",
			Namespace:  Namespace,
			Name:       "endpoint_gc_objects",
			Help:       "The number of times endpoint objects have been garbage-collected",
		}, []string{LabelOutcome}),

		CiliumEndpointSliceDensity: metric.NewHistogram(metric.HistogramOpts{
			ConfigName: Namespace + "_number_of_ceps_per_ces",
			Namespace:  Namespace,
			Name:       "number_of_ceps_per_ces",
			Help:       "The number of CEPs batched in a CES",
			Buckets:    []float64{1, 10, 25, 50, 100, 200, 500, 1000},
		}),

		CiliumEndpointsChangeCount: metric.NewHistogramVec(metric.HistogramOpts{
			ConfigName: Namespace + "_number_of_cep_changes_per_ces",
			Namespace:  Namespace,
			Name:       "number_of_cep_changes_per_ces",
			Help:       "The number of changed CEPs in each CES update",
		}, []string{LabelOpcode}),

		CiliumEndpointSliceSyncErrors: metric.NewCounter(metric.CounterOpts{
			ConfigName: Namespace + "_ces_sync_errors_total",
			Namespace:  Namespace,
			Name:       "ces_sync_errors_total",
			Help:       "Number of CES sync errors",
		}),

		CiliumEndpointSliceSyncTotal: metric.NewCounterVec(metric.CounterOpts{
			ConfigName: Namespace + "_ces_sync_total",
			Namespace:  Namespace,
			Name:       "ces_sync_total",
			Help:       "The number of completed CES syncs by outcome",
		}, []string{"outcome"}),

		CiliumEndpointSliceQueueDelay: metric.NewHistogram(metric.HistogramOpts{
			ConfigName: Namespace + "_ces_queueing_delay_seconds",
			Namespace:  Namespace,
			Name:       "ces_queueing_delay_seconds",
			Help:       "CiliumEndpointSlice queueing delay in seconds",
			Buckets:    append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}),
	}
}
