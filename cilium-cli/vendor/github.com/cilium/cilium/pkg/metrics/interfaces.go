// Copyright 2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

type CounterVec interface {
	WithLabelValues(lvls ...string) prometheus.Counter
	GetMetricWithLabelValues(lvs ...string) (prometheus.Counter, error)
	With(labels prometheus.Labels) prometheus.Counter
	prometheus.Collector
}

type GaugeVec interface {
	WithLabelValues(lvls ...string) prometheus.Gauge
	prometheus.Collector
}

var (
	NoOpMetric    prometheus.Metric    = &metric{}
	NoOpCollector prometheus.Collector = &collector{}

	NoOpCounter     prometheus.Counter     = &counter{NoOpMetric, NoOpCollector}
	NoOpCounterVec  CounterVec             = &counterVec{NoOpCollector}
	NoOpObserver    prometheus.Observer    = &observer{}
	NoOpObserverVec prometheus.ObserverVec = &observerVec{NoOpCollector}
	NoOpGauge       prometheus.Gauge       = &gauge{NoOpMetric, NoOpCollector}
	NoOpGaugeVec    GaugeVec               = &gaugeVec{NoOpCollector}
)

// Metric

type metric struct{}

// *WARNING*: Desc returns nil so do not register this metric into prometheus
// default register.
func (m *metric) Desc() *prometheus.Desc  { return nil }
func (m *metric) Write(*dto.Metric) error { return nil }

// Collector

type collector struct{}

func (c *collector) Describe(chan<- *prometheus.Desc) {}
func (c *collector) Collect(chan<- prometheus.Metric) {}

// Counter

type counter struct {
	prometheus.Metric
	prometheus.Collector
}

func (cv *counter) Add(float64) {}
func (cv *counter) Inc()        {}

// CounterVec

type counterVec struct{ prometheus.Collector }

func (cv *counterVec) WithLabelValues(lvls ...string) prometheus.Counter { return NoOpCounter }

func (cv *counterVec) GetMetricWithLabelValues(lvs ...string) (prometheus.Counter, error) {
	return NoOpCounter, nil
}

func (cv *counterVec) With(labels prometheus.Labels) prometheus.Counter { return NoOpCounter }

// Observer

type observer struct{}

func (o *observer) Observe(float64) {}

// ObserverVec

type observerVec struct {
	prometheus.Collector
}

func (ov *observerVec) GetMetricWith(prometheus.Labels) (prometheus.Observer, error) {
	return NoOpObserver, nil
}
func (ov *observerVec) GetMetricWithLabelValues(lvs ...string) (prometheus.Observer, error) {
	return NoOpObserver, nil
}

func (ov *observerVec) With(prometheus.Labels) prometheus.Observer    { return NoOpObserver }
func (ov *observerVec) WithLabelValues(...string) prometheus.Observer { return NoOpObserver }

func (ov *observerVec) CurryWith(prometheus.Labels) (prometheus.ObserverVec, error) {
	return NoOpObserverVec, nil
}
func (ov *observerVec) MustCurryWith(prometheus.Labels) prometheus.ObserverVec {
	return NoOpObserverVec
}

// Gauge

type gauge struct {
	prometheus.Metric
	prometheus.Collector
}

func (g *gauge) Set(float64)       {}
func (g *gauge) Inc()              {}
func (g *gauge) Dec()              {}
func (g *gauge) Add(float64)       {}
func (g *gauge) Sub(float64)       {}
func (g *gauge) SetToCurrentTime() {}

// GaugeVec

type gaugeVec struct {
	prometheus.Collector
}

func (gv *gaugeVec) WithLabelValues(lvls ...string) prometheus.Gauge {
	return NoOpGauge
}
