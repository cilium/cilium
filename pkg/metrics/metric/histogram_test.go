// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
)

func TestHistogramNativeDefaults(t *testing.T) {
	customBuckets := []float64{0.1, 0.5, 1}

	tests := []struct {
		name                string
		opts                HistogramOpts
		wantBucketFactor    float64
		wantMaxBucketNumber uint32
		wantBuckets         []float64
	}{
		{
			name:                "native defaults applied and DefBuckets preserved when unset",
			opts:                HistogramOpts{Name: "test"},
			wantBucketFactor:    defaultNativeHistogramBucketFactor,
			wantMaxBucketNumber: defaultNativeHistogramMaxBucketNumber,
			wantBuckets:         prometheus.DefBuckets,
		},
		{
			name:                "explicit classic buckets kept while native defaults applied",
			opts:                HistogramOpts{Name: "test", Buckets: customBuckets},
			wantBucketFactor:    defaultNativeHistogramBucketFactor,
			wantMaxBucketNumber: defaultNativeHistogramMaxBucketNumber,
			wantBuckets:         customBuckets,
		},
		{
			name: "explicit native config left untouched",
			opts: HistogramOpts{
				Name:                           "test",
				NativeHistogramBucketFactor:    2,
				NativeHistogramMaxBucketNumber: 15,
			},
			wantBucketFactor:    2,
			wantMaxBucketNumber: 15,
			wantBuckets:         nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			promOpts := tt.opts.toPrometheus()
			assert.Equal(t, tt.wantBucketFactor, promOpts.NativeHistogramBucketFactor)
			assert.Equal(t, tt.wantMaxBucketNumber, promOpts.NativeHistogramMaxBucketNumber)
			assert.Equal(t, tt.wantBuckets, promOpts.Buckets)
		})
	}
}

// TestHistogramDualExposition verifies that a histogram created with the default
// options exposes both classic buckets and native histogram data (dual exposition).
func TestHistogramDualExposition(t *testing.T) {
	o := NewHistogram(HistogramOpts{Name: "test"})
	o.Observe(0.42)

	ms, err := dumpMetrics(o)
	assert.NoError(t, err)
	assert.Len(t, ms, 1)

	h := ms[0].Histogram
	// Classic buckets are still emitted (text/OpenMetrics scrapes).
	assert.NotEmpty(t, h.GetBucket())
	// Native histogram data is emitted (protobuf scrapes): a non-zero schema and at
	// least one positive span indicate sparse buckets are present.
	assert.Positive(t, h.GetSchema())
	assert.NotEmpty(t, h.GetPositiveSpan())
}

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
