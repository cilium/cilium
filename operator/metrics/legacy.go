// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"fmt"
	"strings"
	"time"

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

type metricData struct {
	value          float64
	formattedValue string
	buckets        map[string]float64
	quantiles      map[string]float64
	count          float64
	sum            float64
	additionalInfo map[string]float64
}

func formatDuration(seconds float64) string {
	duration := time.Duration(seconds * float64(time.Second))
	if duration < time.Millisecond {
		return fmt.Sprintf("%.3fµs", float64(duration.Microseconds()))
	}
	if duration < time.Second {
		return fmt.Sprintf("%.3fms", float64(duration.Milliseconds()))
	}
	return fmt.Sprintf("%.3fs", seconds)
}

func processSummary(metricLabel *dto.Metric) metricData {
	summary := metricLabel.GetSummary()
	data := metricData{
		value:     summary.GetSampleSum(),
		sum:       summary.GetSampleSum(),
		count:     float64(summary.GetSampleCount()),
		quantiles: make(map[string]float64),
		additionalInfo: map[string]float64{
			"count": float64(summary.GetSampleCount()),
		},
	}

	var quantilesStr []string
	for _, q := range summary.GetQuantile() {
		data.additionalInfo[fmt.Sprintf("quantile_%g", q.GetQuantile())] = q.GetValue()
		data.quantiles[fmt.Sprintf("%g", q.GetQuantile())] = q.GetValue()
		quantilesStr = append(quantilesStr, formatDuration(q.GetValue()))
	}
	data.formattedValue = strings.Join(quantilesStr, " / ")

	return data
}

func processHistogram(metricLabel *dto.Metric) metricData {
	hist := metricLabel.GetHistogram()
	data := metricData{
		value:   hist.GetSampleSum(),
		sum:     hist.GetSampleSum(),
		count:   float64(hist.GetSampleCount()),
		buckets: make(map[string]float64),
		additionalInfo: map[string]float64{
			"count": float64(hist.GetSampleCount()),
		},
	}

	var bucketsStr []string
	for _, b := range hist.GetBucket() {
		data.additionalInfo[fmt.Sprintf("bucket_%g", b.GetUpperBound())] = float64(b.GetCumulativeCount())
		data.buckets[fmt.Sprintf("%g", b.GetUpperBound())] = float64(b.GetCumulativeCount())
		bucketsStr = append(bucketsStr, formatDuration(b.GetUpperBound()))
	}
	data.formattedValue = strings.Join(bucketsStr, " / ")

	return data
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

			var data metricData

			switch metricType {
			case dto.MetricType_COUNTER:
				data = metricData{
					value:          metricLabel.Counter.GetValue(),
					formattedValue: fmt.Sprintf("%.3f", metricLabel.Counter.GetValue()),
				}
			case dto.MetricType_GAUGE:
				data = metricData{
					value:          metricLabel.GetGauge().GetValue(),
					formattedValue: fmt.Sprintf("%.3f", metricLabel.GetGauge().GetValue()),
				}
			case dto.MetricType_UNTYPED:
				data = metricData{
					value:          metricLabel.GetUntyped().GetValue(),
					formattedValue: fmt.Sprintf("%.3f", metricLabel.GetUntyped().GetValue()),
				}
			case dto.MetricType_SUMMARY:
				data = processSummary(metricLabel)
			case dto.MetricType_HISTOGRAM:
				data = processHistogram(metricLabel)
			default:
				continue
			}

			var labelStrs []string
			for k, v := range labels {
				labelStrs = append(labelStrs, fmt.Sprintf("%s=%s", k, v))
			}
			labelStr := strings.Join(labelStrs, " ")

			metric := &models.Metric{
				Name:      fmt.Sprintf("%s %s", metricName, labelStr),
				Value:     data.value,
				Labels:    map[string]string{"formatted_value": data.formattedValue},
				Buckets:   data.buckets,
				Quantiles: data.quantiles,
				Count:     data.count,
				Sum:       data.sum,
			}
			if data.additionalInfo != nil {
				metric.AdditionalInfo = data.additionalInfo
			}
			result = append(result, metric)
		}
	}

	return result, nil
}
