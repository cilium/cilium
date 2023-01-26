// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/pkg/metrics/metric"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

var _ metric.WithMetadata = (*noopMetric)(nil)

type noopMetric struct{}

func (no *noopMetric) IsEnabled() bool                  { return false }
func (no *noopMetric) SetEnabled(bool)                  {}
func (no *noopMetric) Opts() metric.Opts                { return metric.Opts{} }
func (no *noopMetric) Labels() metric.LabelDescriptions { return nil }
func (no *noopMetric) Desc() *prometheus.Desc           { return nil }
func (no *noopMetric) Write(*dto.Metric) error          { return nil }
func (no *noopMetric) Describe(chan<- *prometheus.Desc) {}
func (no *noopMetric) Collect(chan<- prometheus.Metric) {}

var _ metric.Counter = (*noopCounter)(nil)

type noopCounter struct {
	noopMetric
}

func (nc *noopCounter) Inc()         {}
func (nc *noopCounter) Add(float64)  {}
func (nc *noopCounter) Get() float64 { return 0 }

var _ metric.Vec[metric.Counter] = (*noopVecCounter)(nil)

type noopVecCounter struct {
	noopMetric
}

func (nvc *noopVecCounter) CurryWith(labels prometheus.Labels) (metric.Vec[metric.Counter], error) {
	return nvc, nil
}
func (nvc *noopVecCounter) GetMetricWith(labels prometheus.Labels) (metric.Counter, error) {
	return &noopCounter{}, nil
}
func (nvc *noopVecCounter) GetMetricWithLabelValues(lvs ...string) (metric.Counter, error) {
	return &noopCounter{}, nil
}
func (nvc *noopVecCounter) With(labels prometheus.Labels) metric.Counter { return &noopCounter{} }
func (nvc *noopVecCounter) WithLabelValues(lvs ...string) metric.Counter { return &noopCounter{} }
func (nvc *noopVecCounter) LabelDescriptions() metric.LabelDescriptions  { return nil }

var _ metric.Gauge = (*noopGauge)(nil)

type noopGauge struct {
	noopMetric
}

// Set sets the Gauge to an arbitrary value.
func (ng *noopGauge) Set(float64)       {}
func (ng *noopGauge) Inc()              {}
func (ng *noopGauge) Dec()              {}
func (ng *noopGauge) Add(float64)       {}
func (ng *noopGauge) Sub(float64)       {}
func (ng *noopGauge) SetToCurrentTime() {}
func (ng *noopGauge) Get() float64      { return 0 }

var _ metric.Vec[metric.Gauge] = (*noopVecGauge)(nil)

type noopVecGauge struct {
	noopMetric
}

func (nvg *noopVecGauge) CurryWith(labels prometheus.Labels) (metric.Vec[metric.Gauge], error) {
	return nvg, nil
}
func (nvg *noopVecGauge) GetMetricWith(labels prometheus.Labels) (metric.Gauge, error) {
	return &noopGauge{}, nil
}
func (nvg *noopVecGauge) GetMetricWithLabelValues(lvs ...string) (metric.Gauge, error) {
	return &noopGauge{}, nil
}
func (nvg *noopVecGauge) With(labels prometheus.Labels) metric.Gauge  { return &noopGauge{} }
func (nvg *noopVecGauge) WithLabelValues(lvs ...string) metric.Gauge  { return &noopGauge{} }
func (nvg *noopVecGauge) LabelDescriptions() metric.LabelDescriptions { return nil }

var _ metric.Histogram = (*noopHistogram)(nil)

type noopHistogram struct {
	noopMetric
}

func (nh *noopHistogram) Observe(float64) {}

var _ metric.Vec[metric.Observer] = (*noopVecHistogram)(nil)

type noopVecHistogram struct {
	noopMetric
}

func (nvh *noopVecHistogram) CurryWith(labels prometheus.Labels) (metric.Vec[metric.Observer], error) {
	return nvh, nil
}
func (nvh *noopVecHistogram) GetMetricWith(labels prometheus.Labels) (metric.Observer, error) {
	return &noopHistogram{}, nil
}
func (nvh *noopVecHistogram) GetMetricWithLabelValues(lvs ...string) (metric.Observer, error) {
	return &noopHistogram{}, nil
}
func (nvh *noopVecHistogram) With(labels prometheus.Labels) metric.Observer { return &noopHistogram{} }
func (nvh *noopVecHistogram) WithLabelValues(lvs ...string) metric.Observer { return &noopHistogram{} }
func (nvh *noopVecHistogram) LabelDescriptions() metric.LabelDescriptions   { return nil }
