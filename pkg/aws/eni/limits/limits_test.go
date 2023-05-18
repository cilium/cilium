// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package limits

import (
	"testing"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/operator/option"
)

func Test(t *testing.T) {
	check.TestingT(t)
}

type ENILimitsSuite struct{}

var _ = check.Suite(&ENILimitsSuite{})

func (e *ENILimitsSuite) TestGet(c *check.C) {
	option.Config.AWSInstanceLimitMapping = map[string]string{"a2.custom2": "4,5,6"}

	_, ok := Get("unknown")
	c.Assert(ok, check.Equals, false)

	l, ok := Get("m3.large")
	c.Assert(ok, check.Equals, true)
	c.Assert(l.Adapters, check.Not(check.Equals), 0)
	c.Assert(l.IPv4, check.Not(check.Equals), 0)
	c.Assert(l.HypervisorType, check.Equals, "xen")

	UpdateFromUserDefinedMappings(option.Config.AWSInstanceLimitMapping)
	l, ok = Get("a2.custom2")
	c.Assert(ok, check.Equals, true)
	c.Assert(l.Adapters, check.Equals, 4)
	c.Assert(l.IPv4, check.Equals, 5)
	c.Assert(l.IPv6, check.Equals, 6)
}

func (e *ENILimitsSuite) TestUpdateFromUserDefinedMappings(c *check.C) {
	m1 := map[string]string{"a1.medium": "2,4,100"}

	err := UpdateFromUserDefinedMappings(m1)
	c.Assert(err, check.Equals, nil)

	limit, ok := Get("a1.medium")
	c.Assert(ok, check.Equals, true)
	c.Assert(limit.Adapters, check.Equals, 2)
	c.Assert(limit.IPv4, check.Equals, 4)
	c.Assert(limit.IPv6, check.Equals, 100)
}

func (e *ENILimitsSuite) TestParseLimitString(c *check.C) {
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
