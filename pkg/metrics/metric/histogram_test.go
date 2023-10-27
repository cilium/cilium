// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestHistogramWithLabels(t *testing.T) {
	o := NewHistogramVecWithLabels(HistogramOpts{
		Namespace: "cilium",
		Subsystem: "subsystem",
		Name:      "test",
	}, Labels{
		{Name: "foo", Values: NewValues("0", "1")},
	})
	r := prometheus.NewRegistry()
	r.MustRegister(o)
	o.WithLabelValues("1").Observe(1234)
	ms, err := dumpMetrics(o)
	assert.NoError(t, err)
	assert.Len(t, ms, 2)
	for _, m := range ms {
		switch m.Label[0].GetValue() {
		case "0":
			assert.Zero(t, m.Histogram.GetSampleCount())
		case "1":
			assert.Equal(t, uint64(1), m.Histogram.GetSampleCount())
		default:
			assert.Fail(t, "unexpected label value")
		}
	}
}
