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

func NewCounterVec(opts CounterOpts, labelNames []string) DeletableVec[Counter] {
	return &counterVec{
		CounterVec: prometheus.NewCounterVec(opts.toPrometheus(), labelNames),
		metric: metric{
			enabled: !opts.Disabled,
			opts:    Opts(opts),
		},
	}
}

type counterVec struct {
	*prometheus.CounterVec
	metric
}

func (cv *counterVec) CurryWith(labels prometheus.Labels) (Vec[Counter], error) {
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
