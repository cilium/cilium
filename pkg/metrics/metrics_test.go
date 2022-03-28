// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package metrics

import (
	. "gopkg.in/check.v1"
)

func (s *MetricsSuite) TestGaugeWithThreshold(c *C) {
	threshold := 1.0
	underThreshold := threshold - 0.5
	overThreshold := threshold + 0.5
	gauge := NewGaugeWithThreshold(
		"test_metric",
		"test_subsystem",
		"test_metric",
		map[string]string{
			"test_label": "test_value",
		},
		threshold,
	)

	metrics, err := registry.Gather()
	c.Assert(err, IsNil)
	initMetricLen := len(metrics)

	gauge.Set(underThreshold)
	metrics, err = registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(GetGaugeValue(gauge.gauge), Equals, underThreshold)

	gauge.Set(overThreshold)
	metrics, err = registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen+1)
	c.Assert(GetGaugeValue(gauge.gauge), Equals, overThreshold)

	gauge.Set(threshold)
	metrics, err = registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(GetGaugeValue(gauge.gauge), Equals, threshold)

	gauge.Set(overThreshold)
	metrics, err = registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen+1)
	c.Assert(GetGaugeValue(gauge.gauge), Equals, overThreshold)

	gauge.Set(underThreshold)
	metrics, err = registry.Gather()
	c.Assert(err, IsNil)
	c.Assert(metrics, HasLen, initMetricLen)
	c.Assert(GetGaugeValue(gauge.gauge), Equals, underThreshold)
}
