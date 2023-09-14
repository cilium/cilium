// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/api/v1/operator/models"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

// Registry is the global prometheus registry for cilium-operator metrics.
var Registry RegisterGatherer

type RegisterGatherer interface {
	prometheus.Registerer
	prometheus.Gatherer
}

const (
	// LabelOutcome indicates whether the outcome of the operation was successful or not
	LabelOutcome = "outcome"

	// LabelOpcode indicates the kind of CES metric, could be CEP insert or remove
	LabelOpcode = "opcode"

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"

	// LabelValueCEPInsert is used to indicate the number of CEPs inserted in a CES
	LabelValueCEPInsert = "cepinserted"

	// LabelValueCEPRemove is used to indicate the number of CEPs removed from a CES
	LabelValueCEPRemove = "cepremoved"
)

var (
	// EndpointGCObjects records the number of times endpoint objects have been
	// garbage-collected.
	EndpointGCObjects = metrics.NoOpCounterVec

	// CiliumEndpointSliceDensity indicates the number of CEPs batched in a CES and it used to
	// collect the number of CEPs in CES at various buckets.
	CiliumEndpointSliceDensity = metrics.NoOpHistogram

	// CiliumEndpointsChangeCount indicates the total number of CEPs changed for every CES request sent to k8s-apiserver.
	// This metric is used to collect number of CEP changes happening at various buckets.
	CiliumEndpointsChangeCount = metrics.NoOpObserverVec

	// CiliumEndpointSliceSyncTotal indicates the total number of completed CES syncs with k8s-apiserver by success/fail outcome.
	CiliumEndpointSliceSyncTotal = metrics.NoOpCounterVec

	// CiliumEndpointSliceSyncErrors used to track the total number of errors occurred during syncing CES with k8s-apiserver.
	// This metric is going to be deprecated in Cilium 1.14 and removed in 1.15.
	// It is replaced by CiliumEndpointSliceSyncTotal metric.
	CiliumEndpointSliceSyncErrors = metrics.NoOpCounter

	// CiliumEndpointSliceQueueDelay measures the time spent by CES's in the workqueue. This measures time difference between
	// CES insert in the workqueue and removal from workqueue.
	CiliumEndpointSliceQueueDelay = metrics.NoOpHistogram
)

type legacyMetrics struct {
	EndpointGCObjects             metric.Vec[metric.Counter]
	CiliumEndpointSliceDensity    metric.Histogram
	CiliumEndpointsChangeCount    metric.Vec[metric.Observer]
	CiliumEndpointSliceSyncTotal  metric.Vec[metric.Counter]
	CiliumEndpointSliceSyncErrors metric.Counter
	CiliumEndpointSliceQueueDelay metric.Histogram
}

func newLegacyMetrics() *legacyMetrics {
	lm := &legacyMetrics{
		EndpointGCObjects: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "endpoint_gc_objects",
			Help:      "The number of times endpoint objects have been garbage-collected",
		}, []string{LabelOutcome}),

		CiliumEndpointSliceDensity: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "number_of_ceps_per_ces",
			Help:      "The number of CEPs batched in a CES",
			Buckets:   []float64{1, 10, 25, 50, 100, 200, 500, 1000},
		}),

		CiliumEndpointsChangeCount: metric.NewHistogramVec(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "number_of_cep_changes_per_ces",
			Help:      "The number of changed CEPs in each CES update",
		}, []string{LabelOpcode}),

		CiliumEndpointSliceSyncErrors: metric.NewCounter(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_sync_errors_total",
			Help:      "Number of CES sync errors",
		}),

		CiliumEndpointSliceSyncTotal: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_sync_total",
			Help:      "The number of completed CES syncs by outcome",
		}, []string{LabelOutcome}),

		CiliumEndpointSliceQueueDelay: metric.NewHistogram(metric.HistogramOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "ces_queueing_delay_seconds",
			Help:      "CiliumEndpointSlice queueing delay in seconds",
			Buckets:   append(prometheus.DefBuckets, 60, 300, 900, 1800, 3600),
		}),
	}

	EndpointGCObjects = lm.EndpointGCObjects
	CiliumEndpointSliceDensity = lm.CiliumEndpointSliceDensity
	CiliumEndpointsChangeCount = lm.CiliumEndpointsChangeCount
	CiliumEndpointSliceSyncTotal = lm.CiliumEndpointSliceSyncTotal
	CiliumEndpointSliceSyncErrors = lm.CiliumEndpointSliceSyncErrors
	CiliumEndpointSliceQueueDelay = lm.CiliumEndpointSliceQueueDelay

	return lm
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
			labelPairs := metricLabel.GetLabel()
			labels := make(map[string]string, len(labelPairs))
			for _, label := range labelPairs {
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
