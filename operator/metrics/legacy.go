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

	// Label values

	// LabelValueOutcomeSuccess is used as a successful outcome of an operation
	LabelValueOutcomeSuccess = "success"

	// LabelValueOutcomeFail is used as an unsuccessful outcome of an operation
	LabelValueOutcomeFail = "fail"
)

var (
	// EndpointGCObjects records the number of times endpoint objects have been
	// garbage-collected.
	EndpointGCObjects = metrics.NoOpCounterVec
)

type legacyMetrics struct {
	EndpointGCObjects metric.Vec[metric.Counter]
}

func newLegacyMetrics() *legacyMetrics {
	lm := &legacyMetrics{
		EndpointGCObjects: metric.NewCounterVec(metric.CounterOpts{
			Namespace: metrics.CiliumOperatorNamespace,
			Name:      "endpoint_gc_objects",
			Help:      "The number of times endpoint objects have been garbage-collected",
		}, []string{LabelOutcome}),
	}

	EndpointGCObjects = lm.EndpointGCObjects

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
