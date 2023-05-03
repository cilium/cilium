// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	prommodel "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
)

func TestParsePromMetrics(t *testing.T) {
	input := `
# HELP cilium_forward_count_total Total forwarded packets, tagged by ingress/egress direction
# TYPE cilium_forward_count_total counter
cilium_forward_count_total{direction="EGRESS"} 444088
cilium_forward_count_total{direction="INGRESS"} 812973
`

	metricName := "cilium_forward_count_total"
	metricHelp := "Total forwarded packets, tagged by ingress/egress direction"
	metricTypeCounter := prommodel.MetricType_COUNTER
	labelName := "direction"
	labelEgress := "EGRESS"
	labelIngress := "INGRESS"
	valueEgress := float64(444088)
	valueIngress := float64(812973)

	want := promMetricsFamily{
		metricName: {
			Name: &metricName,
			Help: &metricHelp,
			Type: &metricTypeCounter,
			Metric: []*prommodel.Metric{
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelEgress}},
					Counter: &prommodel.Counter{Value: &valueEgress},
				},
				{
					Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelIngress}},
					Counter: &prommodel.Counter{Value: &valueIngress},
				},
			},
		},
	}

	reader := strings.NewReader(input)
	got, err := parseMetrics(reader)
	assert.NoError(t, err)
	assert.Exactly(t, want, got)
}

func TestMetricsIncrease(t *testing.T) {
	metricName := "cilium_forward_count_total"
	metricHelp := "Total forwarded packets, tagged by ingress/egress direction"
	metricTypeCounter := prommodel.MetricType_COUNTER
	labelName := "direction"
	labelEgress := "EGRESS"
	labelIngress := "INGRESS"
	valueEgress := 444088.
	valueIngress := 812973.

	valueEgressAfter := 1599128.
	valueIngressAfter := 3789798.

	ciliumForwardCountTotalBefore := dto.MetricFamily{
		Name: &metricName,
		Help: &metricHelp,
		Type: &metricTypeCounter,
		Metric: []*prommodel.Metric{
			{
				Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelEgress}},
				Counter: &prommodel.Counter{Value: &valueEgress},
			},
			{
				Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelIngress}},
				Counter: &prommodel.Counter{Value: &valueIngress},
			},
		},
	}

	ciliumForwardCountTotalAfter := dto.MetricFamily{
		Name: &metricName,
		Help: &metricHelp,
		Type: &metricTypeCounter,
		Metric: []*prommodel.Metric{
			{
				Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelEgress}},
				Counter: &prommodel.Counter{Value: &valueEgressAfter},
			},
			{
				Label:   []*prommodel.LabelPair{{Name: &labelName, Value: &labelIngress}},
				Counter: &prommodel.Counter{Value: &valueIngressAfter},
			},
		},
	}

	tt := map[string]struct {
		before dto.MetricFamily
		after  dto.MetricFamily
		err    bool
	}{
		"metric increases": {
			before: ciliumForwardCountTotalBefore,
			after:  ciliumForwardCountTotalAfter,
			err:    false,
		},
		"metrics are equals": {
			before: ciliumForwardCountTotalBefore,
			after:  ciliumForwardCountTotalBefore,
			err:    true,
		},
		"metric decreases": {
			before: ciliumForwardCountTotalAfter,
			after:  ciliumForwardCountTotalBefore,
			err:    true,
		},
	}

	for name, tc := range tt {
		t.Run(name, func(t *testing.T) {
			err := metricsIncrease(tc.before, tc.after)
			if tc.err {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
