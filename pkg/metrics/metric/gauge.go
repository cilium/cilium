// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func NewGauge(opts GaugeOpts) Gauge {
	return &gauge{
		Gauge: prometheus.NewGauge(opts.toPrometheus()),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type Gauge interface {
	prometheus.Gauge
	WithMetadata

	Get() float64
}

type gauge struct {
	prometheus.Gauge
	metric
}

func (g *gauge) Collect(metricChan chan<- prometheus.Metric) {
	if g.enabled {
		g.Gauge.Collect(metricChan)
	}
}

func (g *gauge) Get() float64 {
	if !g.enabled {
		return 0
	}

	var pm dto.Metric
	err := g.Gauge.Write(&pm)
	if err == nil {
		return *pm.Gauge.Value
	}
	return 0
}

// Set sets the Gauge to an arbitrary value.
func (g *gauge) Set(val float64) {
	if g.enabled {
		g.Gauge.Set(val)
	}
}

// Inc increments the Gauge by 1. Use Add to increment it by arbitrary
// values.
func (g *gauge) Inc() {
	if g.enabled {
		g.Gauge.Inc()
	}
}

// Dec decrements the Gauge by 1. Use Sub to decrement it by arbitrary
// values.
func (g *gauge) Dec() {
	if g.enabled {
		g.Gauge.Dec()
	}
}

// Add adds the given value to the Gauge. (The value can be negative,
// resulting in a decrease of the Gauge.)
func (g *gauge) Add(val float64) {
	if g.enabled {
		g.Gauge.Add(val)
	}
}

// Sub subtracts the given value from the Gauge. (The value can be
// negative, resulting in an increase of the Gauge.)
func (g *gauge) Sub(i float64) {
	if g.enabled {
		g.Gauge.Sub(i)
	}
}

// SetToCurrentTime sets the Gauge to the current Unix time in seconds.
func (g *gauge) SetToCurrentTime() {
	if g.enabled {
		g.Gauge.SetToCurrentTime()
	}
}

func NewGaugeVec(opts GaugeOpts, labelNames []string) DeletableVec[Gauge] {
	return &gaugeVec{
		GaugeVec: prometheus.NewGaugeVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type gaugeVec struct {
	*prometheus.GaugeVec
	metric
}

func (gv *gaugeVec) CurryWith(labels prometheus.Labels) (Vec[Gauge], error) {
	vec, err := gv.GaugeVec.CurryWith(labels)
	if err == nil {
		return &gaugeVec{GaugeVec: vec, metric: gv.metric}, nil
	}
	return nil, err
}

func (gv *gaugeVec) GetMetricWith(labels prometheus.Labels) (Gauge, error) {
	if !gv.enabled {
		return &gauge{
			metric: metric{enabled: false},
		}, nil
	}

	promGauge, err := gv.GaugeVec.GetMetricWith(labels)
	if err == nil {
		return &gauge{
			Gauge:  promGauge,
			metric: gv.metric,
		}, nil
	}
	return nil, err
}

func (gv *gaugeVec) GetMetricWithLabelValues(lvs ...string) (Gauge, error) {
	if !gv.enabled {
		return &gauge{
			metric: metric{enabled: false},
		}, nil
	}

	promGauge, err := gv.GaugeVec.GetMetricWithLabelValues(lvs...)
	if err == nil {
		return &gauge{
			Gauge:  promGauge,
			metric: gv.metric,
		}, nil
	}
	return nil, err
}

func (gv *gaugeVec) With(labels prometheus.Labels) Gauge {
	if !gv.enabled {
		return &gauge{
			metric: metric{enabled: false},
		}
	}

	promGauge := gv.GaugeVec.With(labels)
	return &gauge{
		Gauge:  promGauge,
		metric: gv.metric,
	}
}

func (gv *gaugeVec) WithLabelValues(lvs ...string) Gauge {
	if !gv.enabled {
		return &gauge{
			metric: metric{enabled: false},
		}
	}

	promGauge := gv.GaugeVec.WithLabelValues(lvs...)
	return &gauge{
		Gauge:  promGauge,
		metric: gv.metric,
	}
}

func (gv *gaugeVec) SetEnabled(e bool) {
	if !e {
		gv.Reset()
	}

	gv.metric.SetEnabled(e)
}

type GaugeFunc interface {
	prometheus.GaugeFunc
	WithMetadata
}

func NewGaugeFunc(opts GaugeOpts, function func() float64) GaugeFunc {
	return &gaugeFunc{
		GaugeFunc: prometheus.NewGaugeFunc(opts.toPrometheus(), function),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type gaugeFunc struct {
	prometheus.GaugeFunc
	metric
}

func (gf *gaugeFunc) Collect(metricChan chan<- prometheus.Metric) {
	if gf.enabled {
		gf.GaugeFunc.Collect(metricChan)
	}
}

type GaugeOpts Opts

func (o GaugeOpts) toPrometheus() prometheus.GaugeOpts {
	return prometheus.GaugeOpts{
		Namespace:   o.Namespace,
		Subsystem:   o.Subsystem,
		Name:        o.Name,
		Help:        o.Help,
		ConstLabels: o.ConstLabels,
	}
}
