// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/metrics/metric"
)

func (s *MetricsSuite) TestGaugeWithThreshold(c *C) {
	threshold := 1.0
	underThreshold := threshold - 0.5
	overThreshold := threshold + 0.5
	mapname := "test_map"
	mapMetrics := NewBPFMapMetrics()
	gauge := mapMetrics.MapPressure.NewBPFMapPressureGauge(mapname, threshold)

	reg := NewRegistry(RegistryParams{
		AutoMetrics: []metric.WithMetadata{
			mapMetrics.MapPressure,
		},
	})

	metrics, err := reg.inner.Gather()
	c.Assert(err, IsNil)
	initMetricLen := len(metrics)

	gauge.Set(underThreshold)
	metrics, err = reg.inner.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(GetGaugeValue(gauge.vec.WithLabelValues(mapname)), Equals, float64(0))

	gauge.Set(overThreshold)
	metrics, err = reg.inner.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen+1)
	c.Assert(GetGaugeValue(gauge.vec.WithLabelValues(mapname)), Equals, overThreshold)

	gauge.Set(threshold)
	metrics, err = reg.inner.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(GetGaugeValue(gauge.vec.WithLabelValues(mapname)), Equals, float64(0))

	gauge.Set(overThreshold)
	metrics, err = reg.inner.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen+1)
	c.Assert(GetGaugeValue(gauge.vec.WithLabelValues(mapname)), Equals, overThreshold)

	gauge.Set(underThreshold)
	metrics, err = reg.inner.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(GetGaugeValue(gauge.vec.WithLabelValues(mapname)), Equals, float64(0))
}
