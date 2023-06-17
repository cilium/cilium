// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"strconv"

	. "github.com/cilium/checkmate"
)

func (s *OptionSuite) TestVerifyMonitorAggregationLevel(c *C) {
	c.Assert(VerifyMonitorAggregationLevel("", ""), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "none"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "disabled"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "lowest"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "low"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "medium"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "max"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "maximum"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "LoW"), IsNil)
	c.Assert(VerifyMonitorAggregationLevel("", "disable"), NotNil)
}

func (s *OptionSuite) TestParseMonitorAggregationLevel(c *C) {
	level, err := ParseMonitorAggregationLevel("2")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelLow)

	_, err = ParseMonitorAggregationLevel(strconv.Itoa(int(MonitorAggregationLevelMax) + 1))
	c.Assert(err, NotNil)

	_, err = ParseMonitorAggregationLevel("-1")
	c.Assert(err, NotNil)

	_, err = ParseMonitorAggregationLevel("foo")
	c.Assert(err, NotNil)

	level, err = ParseMonitorAggregationLevel("")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelNone)

	level, err = ParseMonitorAggregationLevel("none")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelNone)

	level, err = ParseMonitorAggregationLevel("disabled")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelNone)

	level, err = ParseMonitorAggregationLevel("lowest")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelLowest)

	level, err = ParseMonitorAggregationLevel("low")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelLow)

	level, err = ParseMonitorAggregationLevel("medium")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelMedium)

	level, err = ParseMonitorAggregationLevel("max")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelMax)

	level, err = ParseMonitorAggregationLevel("maximum")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelMax)

	level, err = ParseMonitorAggregationLevel("LOW")
	c.Assert(err, IsNil)
	c.Assert(level, Equals, MonitorAggregationLevelLow)
}
