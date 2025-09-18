// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"testing"
	"unsafe"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// maxSamplerMemoryUsage sets the worst-case memory usage limit for the samples.
const maxSamplerMemoryUsage = 1 * 1024 * 1024

func TestSamplerMaxMemoryUsage(t *testing.T) {
	maxSize := max(
		unsafe.Sizeof(gaugeOrCounterSamples{}),
		unsafe.Sizeof(histogramSamples{}),
	)
	maxUsage := maxSize * maxSampledMetrics
	if maxUsage > maxSamplerMemoryUsage {
		t.Fatalf("%d sampled metrics uses %d bytes, which is more maximum allowed %d",
			maxSampledMetrics, maxUsage, maxSamplerMemoryUsage,
		)
	}
}

func TestSampler(t *testing.T) {
	log := hivetest.Logger(t)
	reg := &Registry{params: RegistryParams{Logger: log}, inner: prometheus.NewPedanticRegistry()}

	counter := prometheus.NewCounter(prometheus.CounterOpts{Name: "counter"})
	reg.Register(counter)
	gauge := prometheus.NewGauge(prometheus.GaugeOpts{Name: "gauge"})
	reg.Register(gauge)

	histogramVec := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: "histogram"},
		[]string{"foo"})
	histogram := histogramVec.WithLabelValues("bar")
	reg.Register(histogramVec)

	sampler := &sampler{log: log, reg: reg, metrics: make(map[metricKey]debugSamples)}
	health, _ := cell.NewSimpleHealth()

	for i := range 211 {
		sampler.collect(health)
		counter.Add(1)
		gauge.Set(float64(i + 1))
		histogram.Observe(1.0 / float64(i))
	}
	expected := make([]float32, numSamples)
	for i := range numSamples {
		expected[i] = float32(211 - i - 1)
	}

	require.Len(t, sampler.metrics, 3)
	samples := map[string]debugSamples{}
	for k, s := range sampler.metrics {
		samples[k.fqName()] = s
	}
	counterSamples := samples["counter"].(*gaugeOrCounterSamples)
	assert.Equal(t, expected, counterSamples.samples.grab())

	gaugeSamples := samples["gauge"].(*gaugeOrCounterSamples)
	assert.Equal(t, expected, gaugeSamples.samples.grab())

	histogramSamples := samples["histogram"].(*histogramSamples)
	m1, m30, m60, m120 := histogramSamples.get()
	assert.Equal(t, "2.5m / 4.5m / 4.95m", m1) // 1.0/211 =~ 4.7m
	assert.Equal(t, "2.5m / 4.5m / 4.95m", m30)
	assert.Equal(t, "7.5m / 9.5m / 9.95m", m60)
	assert.Equal(t, "7.5m / 9.5m / 9.95m", m120)
}
