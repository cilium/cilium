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

// +build !privileged_tests

package eni

import (
	"github.com/cilium/cilium/pkg/option"

	"gopkg.in/check.v1"
)

func (e *ENISuite) TestGetLimits(c *check.C) {
	option.Config.AwsInstanceLimitMapping = map[string]string{"a2.custom2": "4,5,6"}

	_, ok := getLimits("unknown")
	c.Assert(ok, check.Equals, false)

	l, ok := getLimits("m3.large")
	c.Assert(ok, check.Equals, true)
	c.Assert(l.Adapters, check.Not(check.Equals), 0)
	c.Assert(l.IPv4, check.Not(check.Equals), 0)

	UpdateLimitsFromUserDefinedMappings(option.Config.AwsInstanceLimitMapping)
	l, ok = getLimits("a2.custom2")
	c.Assert(ok, check.Equals, true)
	c.Assert(l.Adapters, check.Equals, 4)
	c.Assert(l.IPv4, check.Equals, 5)
	c.Assert(l.IPv6, check.Equals, 6)
}

func (e *ENISuite) TestUpdateLimitsFromUserDefinedMappings(c *check.C) {
	m1 := map[string]string{"a1.medium": "2,4,100"}

	err := UpdateLimitsFromUserDefinedMappings(m1)
	c.Assert(err, check.Equals, nil)

	limit, ok := getLimits("a1.medium")
	c.Assert(ok, check.Equals, true)
	c.Assert(limit.Adapters, check.Equals, 2)
	c.Assert(limit.IPv4, check.Equals, 4)
	c.Assert(limit.IPv6, check.Equals, 100)
}

func (e *ENISuite) TestParseLimitString(c *check.C) {
	limitString1 := "4,5 ,6"
	limitString2 := "4,5,a"
	limitString3 := "4,5"
	limitString4 := "45"
	limitString5 := ","
	limitString6 := ""

	limit, err := parseLimitString(limitString1)
	c.Assert(err, check.Equals, nil)
	c.Assert(limit.Adapters, check.Equals, 4)
	c.Assert(limit.IPv4, check.Equals, 5)
	c.Assert(limit.IPv6, check.Equals, 6)

	limit, err = parseLimitString(limitString2)
	c.Assert(err, check.Not(check.Equals), nil)

	limit, err = parseLimitString(limitString3)
	c.Assert(err.Error(), check.Equals, "invalid limit value")
	c.Assert(limit.Adapters, check.Not(check.Equals), 4)
	c.Assert(limit.IPv4, check.Not(check.Equals), 5)
	c.Assert(limit.IPv6, check.Equals, 0)

	limit, err = parseLimitString(limitString4)
	c.Assert(err.Error(), check.Equals, "invalid limit value")

	limit, err = parseLimitString(limitString5)
	c.Assert(err.Error(), check.Equals, "invalid limit value")

	limit, err = parseLimitString(limitString6)
	c.Assert(err.Error(), check.Equals, "invalid limit value")
}
