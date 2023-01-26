// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/metrics/metric"
)

func (s *MetricsSuite) TestMapPressureMetric(c *C) {
	threshold := 1.0
	underThreshold := threshold - 0.5
	overThreshold := threshold + 0.5

	mapPressure := NewMapPressureMetric()
	mapPressure.MapPressure.SetEnabled(true)
	gauge := mapPressure.BPFMapPressureGauge("test_map", threshold)

	registry, err := NewRegistry(RegistryParams{
		Metrics: []metric.WithMetadata{
			mapPressure.MapPressure,
		},
		Lifecycle: &hive.DefaultLifecycle{},
	})
	c.Assert(err, IsNil)

	metrics, err := registry.registry.Gather()
	c.Assert(err, IsNil)
	initMetricLen := len(metrics)

	gauge.Set(underThreshold)
	metrics, err = registry.registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(gauge.Get(), Equals, float64(0))

	gauge.Set(overThreshold)
	metrics, err = registry.registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen+1)
	c.Assert(gauge.Get(), Equals, overThreshold)

	gauge.Set(threshold)
	metrics, err = registry.registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(gauge.Get(), Equals, float64(0))

	gauge.Set(overThreshold)
	metrics, err = registry.registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen+1)
	c.Assert(gauge.Get(), Equals, overThreshold)

	gauge.Set(underThreshold)
	metrics, err = registry.registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(gauge.Get(), Equals, float64(0))
}
