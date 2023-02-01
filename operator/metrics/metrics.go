// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"context"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	dto "github.com/prometheus/client_model/go"
	controllerRuntimeMetrics "sigs.k8s.io/controller-runtime/pkg/metrics"

	"github.com/cilium/cilium/api/v1/operator/models"
	operatorOption "github.com/cilium/cilium/operator/option"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var (
	log = logging.DefaultLogger.WithField(logfields.LogSubsys, "metrics")
)

// Namespace is the namespace key to use for cilium operator metrics.
const Namespace = "cilium_operator"

type RegisterGatherer interface {
	prometheus.Registerer
	prometheus.Gatherer
}

var (
	// Registry is the global prometheus registry for cilium-operator metrics.
	Registry   RegisterGatherer
	shutdownCh chan struct{}
)

// Register registers metrics for cilium-operator.
func Register() {
	log.Info("Registering Operator metrics")

	if operatorOption.Config.EnableGatewayAPI {
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

	registerMetrics()

	m := http.NewServeMux()
	m.Handle("/metrics", promhttp.HandlerFor(Registry, promhttp.HandlerOpts{}))
	srv := &http.Server{
		Addr:    operatorOption.Config.OperatorPrometheusServeAddr,
		Handler: m,
	}

	shutdownCh = make(chan struct{})
	go func() {
		go func() {
			err := srv.ListenAndServe()
			switch err {
			case http.ErrServerClosed:
				log.Info("Metrics server shutdown successfully")
				return
			default:
				log.WithError(err).Fatal("Metrics server ListenAndServe failed")
			}
		}()

		<-shutdownCh
		log.Info("Received shutdown signal")
		if err := srv.Shutdown(context.TODO()); err != nil {
			log.WithError(err).Error("Shutdown operator metrics server failed")
		}
	}()
}

// Unregister shuts down the metrics server.
func Unregister() {
	log.Info("Shutting down metrics server")

	if shutdownCh == nil {
		return
	}

	shutdownCh <- struct{}{}
}

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

func registerMetrics() []prometheus.Collector {
	// Builtin process metrics
	Registry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{Namespace: Namespace}))

	// Custom metrics
	var collectors []prometheus.Collector

	IdentityGCSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "identity_gc_entries",
		Help:      "The number of alive and deleted identities at the end of a garbage collector run",
	}, []string{LabelStatus})
	collectors = append(collectors, IdentityGCSize)

	IdentityGCRuns = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "identity_gc_runs",
		Help:      "The number of times identity garbage collector has run",
	}, []string{LabelOutcome})
	collectors = append(collectors, IdentityGCRuns)

	EndpointGCObjects = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "endpoint_gc_objects",
		Help:      "The number of times endpoint objects have been garbage-collected",
	}, []string{LabelOutcome})
	collectors = append(collectors, EndpointGCObjects)

	CiliumEndpointSliceDensity = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "number_of_ceps_per_ces",
		Help:      "The number of CEPs batched in a CES",
		Buckets:   []float64{1, 10, 25, 50, 100, 200, 500, 1000},
	})
	collectors = append(collectors, CiliumEndpointSliceDensity)

	CiliumEndpointsChangeCount = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "number_of_cep_changes_per_ces",
		Help:      "The number of changed CEPs in each CES update",
	}, []string{LabelOpcode})
	collectors = append(collectors, CiliumEndpointsChangeCount)

	CiliumEndpointSliceSyncErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "ces_sync_errors_total",
		Help:      "Number of CES sync errors",
	})
	collectors = append(collectors, CiliumEndpointSliceSyncErrors)

	CiliumEndpointSliceSyncTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "ces_sync_total",
		Help:      "The number of completed CES syncs by outcome",
	}, []string{"outcome"})
	collectors = append(collectors, CiliumEndpointSliceSyncTotal)

	CiliumEndpointSliceQueueDelay = prometheus.NewHistogram(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "ces_queueing_delay_seconds",
		Help:      "CiliumEndpointSlice queueing delay in seconds",
		Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
	})
	collectors = append(collectors, CiliumEndpointSliceQueueDelay)

	Registry.MustRegister(collectors...)

	return collectors
}

// DumpMetrics gets the current Cilium operator metrics and dumps all into a
// Metrics structure. If metrics cannot be retrieved, returns an error.
func DumpMetrics() ([]*models.Metric, error) {
	result := []*models.Metric{}
	if Registry == nil {
		return result, nil
	}

	currentMetrics, err := Registry.Gather()
	if err != nil {
		return result, err
	}

	for _, val := range currentMetrics {

		metricName := val.GetName()
		metricType := val.GetType()

		for _, metricLabel := range val.Metric {
			labels := map[string]string{}
			for _, label := range metricLabel.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}

			var value float64
			switch metricType {
			case dto.MetricType_COUNTER:
				value = metricLabel.Counter.GetValue()
			case dto.MetricType_GAUGE:
				value = metricLabel.GetGauge().GetValue()
			case dto.MetricType_UNTYPED:
				value = metricLabel.GetUntyped().GetValue()
			case dto.MetricType_SUMMARY:
				value = metricLabel.GetSummary().GetSampleSum()
			case dto.MetricType_HISTOGRAM:
				value = metricLabel.GetHistogram().GetSampleSum()
			default:
				continue
			}

			metric := &models.Metric{
				Name:   metricName,
				Labels: labels,
				Value:  value,
			}
			result = append(result, metric)
		}
	}

	return result, nil
}
