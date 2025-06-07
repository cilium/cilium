// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/cilium/cilium/api/v1/operator/models"
)

// Registry is the global prometheus registry for cilium-operator metrics.
var Registry RegisterGatherer

type RegisterGatherer interface {
	prometheus.Registerer
	prometheus.Gatherer
}

func formatDuration(seconds float64) string {
	if seconds < 0.001 {
		return fmt.Sprintf("%.3fµs", seconds*1000000)
	} else if seconds < 1 {
		return fmt.Sprintf("%.3fms", seconds*1000)
	}
	return fmt.Sprintf("%.3fs", seconds)
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
			var additionalInfo map[string]float64
			var formattedValue string

			switch metricType {
			case dto.MetricType_COUNTER:
				value = metricLabel.Counter.GetValue()
				formattedValue = fmt.Sprintf("%.3f", value)
			case dto.MetricType_GAUGE:
				value = metricLabel.GetGauge().GetValue()
				formattedValue = fmt.Sprintf("%.3f", value)
			case dto.MetricType_UNTYPED:
				value = metricLabel.GetUntyped().GetValue()
				formattedValue = fmt.Sprintf("%.3f", value)
			case dto.MetricType_SUMMARY:
				summary := metricLabel.GetSummary()
				value = summary.GetSampleSum()
				additionalInfo = make(map[string]float64)
				additionalInfo["count"] = float64(summary.GetSampleCount())

				// Get quantiles and format them
				var quantiles []string
				for _, q := range summary.GetQuantile() {
					additionalInfo[fmt.Sprintf("quantile_%g", q.GetQuantile())] = q.GetValue()
					quantiles = append(quantiles, formatDuration(q.GetValue()))
				}
				formattedValue = strings.Join(quantiles, " / ")
			case dto.MetricType_HISTOGRAM:
				hist := metricLabel.GetHistogram()
				value = hist.GetSampleSum()
				additionalInfo = make(map[string]float64)
				additionalInfo["count"] = float64(hist.GetSampleCount())

				// Get buckets and format them
				var buckets []string
				for _, b := range hist.GetBucket() {
					additionalInfo[fmt.Sprintf("bucket_%g", b.GetUpperBound())] = float64(b.GetCumulativeCount())
					buckets = append(buckets, formatDuration(b.GetUpperBound()))
				}
				formattedValue = strings.Join(buckets, " / ")
			default:
				continue
			}

			var labelStrs []string
			for k, v := range labels {
				labelStrs = append(labelStrs, fmt.Sprintf("%s=%s", k, v))
			}
			labelStr := strings.Join(labelStrs, " ")

			metric := &models.Metric{
				Name:   fmt.Sprintf("%s %s", metricName, labelStr),
				Value:  value,
				Labels: map[string]string{"formatted_value": formattedValue},
			}
			if additionalInfo != nil {
				metric.AdditionalInfo = additionalInfo
			}
			result = append(result, metric)
		}
	}

	return result, nil
}
