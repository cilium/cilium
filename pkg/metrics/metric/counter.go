// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metric

import (
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func NewCounter(opts CounterOpts) Counter {
	return &counter{
		Counter: prometheus.NewCounter(opts.toPrometheus()),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type Counter interface {
	prometheus.Counter
	WithMetadata

	Get() float64
}

type counter struct {
	prometheus.Counter
	metric
}

func (c *counter) Collect(metricChan chan<- prometheus.Metric) {
	if c.enabled {
		c.Counter.Collect(metricChan)
	}
}

func (c *counter) Get() float64 {
	var pm dto.Metric
	err := c.Counter.Write(&pm)
	if err == nil {
		return *pm.Counter.Value
	}
	return 0
}

// Inc increments the counter by 1. Use Add to increment it by arbitrary
// non-negative values.
func (c *counter) Inc() {
	if c.enabled {
		c.Counter.Inc()
	}
}

// Add adds the given value to the counter. It panics if the value is < 0.
func (c *counter) Add(val float64) {
	if c.enabled {
		c.Counter.Add(val)
	}
}

// NewCounterVec creates a new DeletableVec[Counter] based on the provided CounterOpts and
// partitioned by the given label names.
func NewCounterVec(opts CounterOpts, labelNames []string) *counterVec {
	return &counterVec{
		CounterVec: prometheus.NewCounterVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

// NewCounterVecWithLabels creates a new DeletableVec[Counter] based on the provided CounterOpts and
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
//	NewCounterVecWithLabels(CounterOpts{
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
func NewCounterVecWithLabels(opts CounterOpts, labels Labels) *counterVec {
	cv := NewCounterVec(opts, labels.labelNames())
	initLabels[Counter](&cv.metric, labels, cv, opts.Disabled)
	return cv
}

type counterVec struct {
	*prometheus.CounterVec
	metric
}

func (cv *counterVec) CurryWith(labels prometheus.Labels) (Vec[Counter], error) {
	cv.checkLabels(labels)
	vec, err := cv.CounterVec.CurryWith(labels)
	if err == nil {
		return &counterVec{CounterVec: vec, metric: cv.metric}, nil
	}
	return nil, err
}

func (cv *counterVec) GetMetricWith(labels prometheus.Labels) (Counter, error) {
	if !cv.enabled {
		return &counter{
			metric: metric{enabled: false},
		}, nil
	}

	promCounter, err := cv.CounterVec.GetMetricWith(labels)
	if err == nil {
		return &counter{
			Counter: promCounter,
			metric:  cv.metric,
		}, nil
	}
	return nil, err
}

func (cv *counterVec) GetMetricWithLabelValues(lvs ...string) (Counter, error) {
	if !cv.enabled {
		return &counter{
			metric: metric{enabled: false},
		}, nil
	}

	promCounter, err := cv.CounterVec.GetMetricWithLabelValues(lvs...)
	if err == nil {
		return &counter{
			Counter: promCounter,
			metric:  cv.metric,
		}, nil
	}
	return nil, err
}

func (cv *counterVec) With(labels prometheus.Labels) Counter {
	cv.checkLabels(labels)
	if !cv.enabled {
		return &counter{
			metric: metric{enabled: false},
		}
	}

	promCounter := cv.CounterVec.With(labels)
	return &counter{
		Counter: promCounter,
		metric:  cv.metric,
	}
}

func (cv *counterVec) WithLabelValues(lvs ...string) Counter {
	cv.checkLabelValues(lvs...)
	if !cv.enabled {
		return &counter{
			metric: metric{enabled: false},
		}
	}

	promCounter := cv.CounterVec.WithLabelValues(lvs...)
	return &counter{
		Counter: promCounter,
		metric:  cv.metric,
	}
}

func (cv *counterVec) SetEnabled(e bool) {
	if !e {
		cv.Reset()
	}

	cv.metric.SetEnabled(e)
}

type CounterOpts Opts

func (co CounterOpts) toPrometheus() prometheus.CounterOpts {
	return prometheus.CounterOpts{
		Name:        co.Name,
		Namespace:   co.Namespace,
		Subsystem:   co.Subsystem,
		Help:        co.Help,
		ConstLabels: co.ConstLabels,
	}
}
