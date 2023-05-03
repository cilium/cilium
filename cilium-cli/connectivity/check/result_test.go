// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"testing"

	"github.com/cilium/cilium/pkg/components"

	prommodel "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
)

func TestExpectMetricsToIncrease(t *testing.T) {
	ciliumPod := Pod{
		Pod: &corev1.Pod{
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: components.CiliumAgentName,
						Ports: []corev1.ContainerPort{
							{
								Name:          "prometheus",
								HostPort:      9962,
								ContainerPort: 9962,
								Protocol:      corev1.ProtocolTCP,
							}},
					},
				},
			},
		},
	}

	metricName := "cilium_forward_count_total"
	metricHelp := "Total forwarded packets, tagged by ingress/egress direction"
	metricTypeCounter := prommodel.MetricType_COUNTER
	labelName := "direction"
	labelEgress := "EGRESS"
	labelIngress := "INGRESS"
	valueBefore := 1432571.
	valueAfter := 1432625.

	metricsBefore := promMetricsFamily{
		metricName: {
			Name: &metricName,
			Help: &metricHelp,
			Type: &metricTypeCounter,
			Metric: []*prommodel.Metric{
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelEgress}},
					Counter: &prommodel.Counter{Value: &valueBefore},
				},
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelIngress}},
					Counter: &prommodel.Counter{Value: &valueBefore},
				},
			},
		},
	}

	metricsAfter := promMetricsFamily{
		metricName: {
			Name: &metricName,
			Help: &metricHelp,
			Type: &metricTypeCounter,
			Metric: []*prommodel.Metric{
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelEgress}},
					Counter: &prommodel.Counter{Value: &valueAfter},
				},
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelIngress}},
					Counter: &prommodel.Counter{Value: &valueAfter},
				},
			},
		},
	}

	otherMetric := promMetricsFamily{
		"other_metrics": {
			Name: &metricName,
			Help: &metricHelp,
			Type: &metricTypeCounter,
			Metric: []*prommodel.Metric{
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelEgress}},
					Counter: &prommodel.Counter{Value: &valueAfter},
				},
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelIngress}},
					Counter: &prommodel.Counter{Value: &valueAfter},
				},
			},
		},
	}

	tests := map[string]struct {
		source        MetricsSource
		metrics       string
		metricsBefore promMetricsFamily
		metricsAfter  promMetricsFamily
		wantErr       bool
	}{
		"nominal case: metrics increase": {
			metrics:       "cilium_forward_count_total",
			metricsBefore: metricsBefore,
			metricsAfter:  metricsAfter,
			wantErr:       false,
		},
		"metrics decrease": {
			metrics:       "cilium_forward_count_total",
			metricsBefore: metricsAfter,
			metricsAfter:  metricsBefore,
			wantErr:       true,
		},
		"metric name not present in the metrics before": {
			metrics: "cilium_forward_count_total",
			source: MetricsSource{
				Name: components.CiliumAgentName,
				Pods: []Pod{ciliumPod},
				Port: "9962",
			},
			metricsBefore: otherMetric,
			metricsAfter:  metricsAfter,
			wantErr:       true,
		},
		"metric name not present in the metrics after": {
			metrics:       "cilium_forward_count_total",
			metricsBefore: metricsBefore,
			metricsAfter:  otherMetric,
			wantErr:       true,
		},
		"metric name not present in the metrics before and after": {
			metrics:       "unknown_metric",
			metricsBefore: metricsBefore,
			metricsAfter:  metricsAfter,
			wantErr:       true,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			r := Result{}
			got := r.ExpectMetricsIncrease(tc.source, tc.metrics)

			for _, m := range got.Metrics {
				// check the source
				assert.Equal(t, tc.source, m.Source)

				// check the assert method
				err := m.Assert(tc.metricsBefore, tc.metricsAfter)
				if tc.wantErr {
					assert.Error(t, err)
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}
