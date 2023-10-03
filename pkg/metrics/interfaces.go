// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"github.com/cilium/cilium/api/v1/client/daemon"
	"github.com/cilium/cilium/api/v1/health/client/connectivity"
	metricpkg "github.com/cilium/cilium/pkg/metrics/metric"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type daemonHealthGetter interface {
	GetHealthz(params *daemon.GetHealthzParams, opts ...daemon.ClientOption) (*daemon.GetHealthzOK, error)
}

type connectivityStatusGetter interface {
	GetStatus(params *connectivity.GetStatusParams, opts ...connectivity.ClientOption) (*connectivity.GetStatusOK, error)
}

var (
	NoOpMetric    prometheus.Metric    = &mockMetric{}
	NoOpCollector prometheus.Collector = &collector{}

	NoOpCounter           metricpkg.Counter                       = &counter{NoOpMetric, NoOpCollector}
	NoOpCounterVec        metricpkg.Vec[metricpkg.Counter]        = &counterVec{NoOpCollector}
	NoOpObserver          metricpkg.Observer                      = &observer{}
	NoOpHistogram         metricpkg.Histogram                     = &histogram{NoOpCollector}
	NoOpObserverVec       metricpkg.Vec[metricpkg.Observer]       = &observerVec{NoOpCollector}
	NoOpGauge             metricpkg.Gauge                         = &gauge{NoOpMetric, NoOpCollector}
	NoOpGaugeVec          metricpkg.Vec[metricpkg.Gauge]          = &gaugeVec{NoOpCollector}
	NoOpGaugeDeletableVec metricpkg.DeletableVec[metricpkg.Gauge] = &gaugeDeletableVec{gaugeVec{NoOpCollector}}
)

// Metric

type mockMetric struct{}

// *WARNING*: Desc returns nil so do not register this metric into prometheus
// default register.
func (m *mockMetric) Desc() *prometheus.Desc  { return nil }
func (m *mockMetric) Write(*dto.Metric) error { return nil }

// Collector

type collector struct{}

func (c *collector) Describe(chan<- *prometheus.Desc) {}
func (c *collector) Collect(chan<- prometheus.Metric) {}

// Counter

type counter struct {
	prometheus.Metric
	prometheus.Collector
}

func (cv *counter) Add(float64)          {}
func (cv *counter) Get() float64         { return 0 }
func (cv *counter) Inc()                 {}
func (cv *counter) IsEnabled() bool      { return false }
func (cv *counter) SetEnabled(bool)      {}
func (cv *counter) Opts() metricpkg.Opts { return metricpkg.Opts{} }

// CounterVec

type counterVec struct{ prometheus.Collector }

func (cv *counterVec) With(prometheus.Labels) metricpkg.Counter    { return NoOpGauge }
func (cv *counterVec) WithLabelValues(...string) metricpkg.Counter { return NoOpGauge }

func (cv *counterVec) CurryWith(prometheus.Labels) (metricpkg.Vec[metricpkg.Counter], error) {
	return NoOpCounterVec, nil
}
func (cv *counterVec) MustCurryWith(prometheus.Labels) metricpkg.Vec[metricpkg.Counter] {
	return NoOpCounterVec
}
func (cv *counterVec) GetMetricWith(prometheus.Labels) (metricpkg.Counter, error) {
	return NoOpCounter, nil
}
func (cv *counterVec) GetMetricWithLabelValues(...string) (metricpkg.Counter, error) {
	return NoOpCounter, nil
}
func (cv *counterVec) IsEnabled() bool      { return false }
func (cv *counterVec) SetEnabled(bool)      {}
func (cv *counterVec) Opts() metricpkg.Opts { return metricpkg.Opts{} }

// Observer

type observer struct{}

func (o *observer) Observe(float64)      {}
func (o *observer) IsEnabled() bool      { return false }
func (o *observer) SetEnabled(bool)      {}
func (o *observer) Opts() metricpkg.Opts { return metricpkg.Opts{} }

// Histogram

type histogram struct {
	prometheus.Collector
}

func (h *histogram) Observe(float64) {}

func (h *histogram) Desc() *prometheus.Desc  { return nil }
func (h *histogram) Write(*dto.Metric) error { return nil }
func (h *histogram) IsEnabled() bool         { return false }
func (h *histogram) SetEnabled(bool)         {}
func (h *histogram) Opts() metricpkg.Opts    { return metricpkg.Opts{} }

// ObserverVec

type observerVec struct {
	prometheus.Collector
}

func (ov *observerVec) GetMetricWith(prometheus.Labels) (metricpkg.Observer, error) {
	return NoOpObserver, nil
}
func (ov *observerVec) GetMetricWithLabelValues(lvs ...string) (metricpkg.Observer, error) {
	return NoOpObserver, nil
}

func (ov *observerVec) With(prometheus.Labels) metricpkg.Observer    { return NoOpObserver }
func (ov *observerVec) WithLabelValues(...string) metricpkg.Observer { return NoOpObserver }

func (ov *observerVec) CurryWith(prometheus.Labels) (metricpkg.Vec[metricpkg.Observer], error) {
	return NoOpObserverVec, nil
}
func (ov *observerVec) MustCurryWith(prometheus.Labels) metricpkg.Vec[metricpkg.Observer] {
	return NoOpObserverVec
}

func (ov *observerVec) IsEnabled() bool      { return false }
func (ov *observerVec) SetEnabled(bool)      {}
func (ov *observerVec) Opts() metricpkg.Opts { return metricpkg.Opts{} }

// Gauge

type gauge struct {
	prometheus.Metric
	prometheus.Collector
}

func (g *gauge) Set(float64)          {}
func (g *gauge) Get() float64         { return 0 }
func (g *gauge) Inc()                 {}
func (g *gauge) Dec()                 {}
func (g *gauge) Add(float64)          {}
func (g *gauge) Sub(float64)          {}
func (g *gauge) SetToCurrentTime()    {}
func (g *gauge) IsEnabled() bool      { return false }
func (g *gauge) SetEnabled(bool)      {}
func (g *gauge) Opts() metricpkg.Opts { return metricpkg.Opts{} }

// GaugeVec

type gaugeDeletableVec struct {
	gaugeVec
}

func (*gaugeDeletableVec) Delete(ll prometheus.Labels) bool {
	return false
}

func (*gaugeDeletableVec) DeleteLabelValues(lvs ...string) bool {
	return false
}

func (*gaugeDeletableVec) DeletePartialMatch(labels prometheus.Labels) int {
	return 0
}

func (*gaugeDeletableVec) Reset() {}

type gaugeVec struct {
	prometheus.Collector
}

func (gv *gaugeVec) With(prometheus.Labels) metricpkg.Gauge    { return NoOpGauge }
func (gv *gaugeVec) WithLabelValues(...string) metricpkg.Gauge { return NoOpGauge }

func (gv *gaugeVec) CurryWith(prometheus.Labels) (metricpkg.Vec[metricpkg.Gauge], error) {
	return NoOpGaugeVec, nil
}
func (gv *gaugeVec) MustCurryWith(prometheus.Labels) metricpkg.Vec[metricpkg.Gauge] {
	return NoOpGaugeVec
}
func (gv *gaugeVec) GetMetricWith(prometheus.Labels) (metricpkg.Gauge, error) {
	return NoOpGauge, nil
}
func (gv *gaugeVec) GetMetricWithLabelValues(...string) (metricpkg.Gauge, error) {
	return NoOpGauge, nil
}
func (gv *gaugeVec) IsEnabled() bool      { return false }
func (gv *gaugeVec) SetEnabled(bool)      {}
func (gv *gaugeVec) Opts() metricpkg.Opts { return metricpkg.Opts{} }
