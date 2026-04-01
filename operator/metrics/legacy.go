// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"maps"

	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/api/v1/operator/models"
	"github.com/cilium/cilium/pkg/metrics"
)

// DumpMetrics gets the current Cilium operator metrics and dumps all into a
// Metrics structure. If metrics cannot be retrieved, returns an error.
//
// For histogram metrics, three entries are emitted with a "quantile" label set
// to "0.5", "0.9", and "0.99" respectively, each holding the computed quantile
// value. For summary metrics, one entry per predefined quantile is emitted with
// the corresponding "quantile" label.
func DumpMetrics(reg *metrics.Registry) ([]*models.Metric, error) {
	result := []*models.Metric{}
	if reg == nil {
		return result, nil
	}

	currentMetrics, err := reg.Gather()
	if err != nil {
		return result, err
	}

	for _, val := range currentMetrics {

		metricName := val.GetName()
		metricType := val.GetType()

		for _, metricLabel := range val.Metric {
			labelPairs := metricLabel.GetLabel()
			baseLabels := make(map[string]string, len(labelPairs))
			for _, label := range labelPairs {
				baseLabels[label.GetName()] = label.GetValue()
			}

			switch metricType {
			case dto.MetricType_COUNTER:
				result = append(result, &models.Metric{
					Name:   metricName,
					Labels: baseLabels,
					Value:  metricLabel.Counter.GetValue(),
				})
			case dto.MetricType_GAUGE:
				result = append(result, &models.Metric{
					Name:   metricName,
					Labels: baseLabels,
					Value:  metricLabel.GetGauge().GetValue(),
				})
			case dto.MetricType_UNTYPED:
				result = append(result, &models.Metric{
					Name:   metricName,
					Labels: baseLabels,
					Value:  metricLabel.GetUntyped().GetValue(),
				})
			case dto.MetricType_HISTOGRAM:
				p50, p90, p99 := metrics.HistogramQuantiles(metricLabel.GetHistogram())
				for _, qv := range []struct {
					q string
					v float64
				}{
					{"0.5", p50},
					{"0.9", p90},
					{"0.99", p99},
				} {
					labels := make(map[string]string, len(baseLabels)+1)
					maps.Copy(labels, baseLabels)
					labels["quantile"] = qv.q
					result = append(result, &models.Metric{
						Name:   metricName,
						Labels: labels,
						Value:  qv.v,
					})
				}
			case dto.MetricType_SUMMARY:
				for _, q := range metricLabel.GetSummary().GetQuantile() {
					labels := make(map[string]string, len(baseLabels)+1)
					maps.Copy(labels, baseLabels)
					labels["quantile"] = fmt.Sprintf("%g", q.GetQuantile())
					result = append(result, &models.Metric{
						Name:   metricName,
						Labels: labels,
						Value:  q.GetValue(),
					})
				}
			default:
				continue
			}
		}
	}

	return result, nil
}
