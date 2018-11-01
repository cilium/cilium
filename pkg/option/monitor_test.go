// Copyright 2018 Authors of Cilium
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

// +build !privileged_tests

package option

import (
	"strconv"

	. "gopkg.in/check.v1"
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
