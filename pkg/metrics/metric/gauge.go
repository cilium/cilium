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

func (g *gauge) Get() float64 {
	var pm dto.Metric
	err := g.Gauge.Write(&pm)
	if err == nil {
		return *pm.Gauge.Value
	}
	return 0
}

// NewGaugeVec creates a new DeletableVec[Gauge] based on the provided GaugeOpts and
// partitioned by the given label names.
func NewGaugeVec(opts GaugeOpts, labelNames []string) *gaugeVec {
	gv := &gaugeVec{
		GaugeVec: prometheus.NewGaugeVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
	return gv
}

// NewGaugeVecWithLabels creates a new DeletableVec[Gauge] based on the provided CounterOpts and
// partitioned by the given labels.
// This will also initialize the labels with the provided values so that metrics with known label value
// ranges can be pre-initialized to zero upon init.
//
// This should only be used when all label values are known at init, otherwise use of the
// metric vector with uninitialized labels will result in warnings.
//
// Note: Disabled metrics will not have their label values initialized.
//
// For example:
//
//	NewGaugeVecWithLabels(GaugeOpts{
//		Namespace: "cilium",
//		Subsystem: "subsystem",
//		Name:      "cilium_test",
//		Disabled:  false,
//	}, Labels{
//		{Name: "foo", Values: NewValues("0", "1")},
//		{Name: "bar", Values: NewValues("a", "b")},
//	})
//
// Will initialize the following metrics to:
//
//	cilium_subsystem_cilium_test{foo="0", bar="a"} 0
//	cilium_subsystem_cilium_test{foo="0", bar="b"} 0
//	cilium_subsystem_cilium_test{foo="1", bar="a"} 0
//	cilium_subsystem_cilium_test{foo="1", bar="b"} 0
func NewGaugeVecWithLabels(opts GaugeOpts, labels Labels) *gaugeVec {
	gv := NewGaugeVec(opts, labels.labelNames())
	initLabels[Gauge](&gv.metric, labels, gv, opts.Disabled)
	return gv
}

type gaugeVec struct {
	*prometheus.GaugeVec
	metric
}

func (gv *gaugeVec) CurryWith(labels prometheus.Labels) (Vec[Gauge], error) {
	gv.checkLabels(labels)
	vec, err := gv.GaugeVec.CurryWith(labels)
	if err == nil {
		return &gaugeVec{GaugeVec: vec, metric: gv.metric}, nil
	}
	return nil, err
}

func (gv *gaugeVec) GetMetricWith(labels prometheus.Labels) (Gauge, error) {
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
	gv.checkLabels(labels)

	promGauge := gv.GaugeVec.With(labels)
	return &gauge{
		Gauge:  promGauge,
		metric: gv.metric,
	}
}

func (gv *gaugeVec) WithLabelValues(lvs ...string) Gauge {
	gv.checkLabelValues(lvs...)

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
