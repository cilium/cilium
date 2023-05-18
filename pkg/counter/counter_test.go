// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package counter

import (
	"net/netip"
	"testing"

	"github.com/cilium/cilium/pkg/checker"

	. "github.com/cilium/checkmate"
)

type CounterTestSuite struct{}

var _ = Suite(&CounterTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (cs *CounterTestSuite) TestCounter(c *C) {
	sc := make(Counter[string])
	c.Assert(sc.Add("foo"), Equals, true)
	c.Assert(len(sc), Equals, 1)
	c.Assert(sc.Add("foo"), Equals, false)
	c.Assert(len(sc), Equals, 1)
	c.Assert(sc.Add("bar"), Equals, true)
	c.Assert(len(sc), Equals, 2)
	nsc := sc.DeepCopy()
	c.Assert(nsc, checker.DeepEquals, sc)
	c.Assert(sc.Delete("foo"), Equals, false)
	c.Assert(len(sc), Equals, 2)
	c.Assert(sc.Delete("bar"), Equals, true)
	c.Assert(len(sc), Equals, 1)
	c.Assert(sc.Delete("foo"), Equals, true)
	c.Assert(len(sc), Equals, 0)
	c.Assert(sc.Add("foo"), Equals, true)
	c.Assert(len(sc), Equals, 1)

	ic := make(Counter[int])
	c.Assert(ic.Add(42), Equals, true)
	c.Assert(len(ic), Equals, 1)
	c.Assert(ic.Add(42), Equals, false)
	c.Assert(len(ic), Equals, 1)
	c.Assert(ic.Add(100), Equals, true)
	c.Assert(len(ic), Equals, 2)
	nic := ic.DeepCopy()
	c.Assert(nic, checker.DeepEquals, ic)
	c.Assert(ic.Delete(42), Equals, false)
	c.Assert(len(ic), Equals, 2)
	c.Assert(ic.Delete(100), Equals, true)
	c.Assert(len(ic), Equals, 1)
	c.Assert(ic.Delete(42), Equals, true)
	c.Assert(len(ic), Equals, 0)
	c.Assert(ic.Add(100), Equals, true)
	c.Assert(len(ic), Equals, 1)

	ac := make(Counter[netip.Addr])
	c.Assert(ac.Add(netip.MustParseAddr("10.0.0.1")), Equals, true)
	c.Assert(len(ac), Equals, 1)
	c.Assert(ac.Add(netip.MustParseAddr("10.0.0.1")), Equals, false)
	c.Assert(len(ac), Equals, 1)
	c.Assert(ac.Add(netip.MustParseAddr("::1")), Equals, true)
	c.Assert(len(ac), Equals, 2)
	c.Assert(ac.Add(netip.MustParseAddr("192.168.0.1")), Equals, true)
	c.Assert(len(ac), Equals, 3)
	c.Assert(ac.Add(netip.MustParseAddr("::ffff:10.0.0.1")), Equals, true)
	c.Assert(len(ac), Equals, 4)
	nac := ac.DeepCopy()
	c.Assert(nac, checker.DeepEquals, ac)
	c.Assert(ac.Delete(netip.MustParseAddr("10.0.0.1")), Equals, false)
	c.Assert(len(ac), Equals, 4)
	c.Assert(ac.Delete(netip.MustParseAddr("10.0.0.1")), Equals, true)
	c.Assert(len(ac), Equals, 3)
}

func (cs *CounterTestSuite) TestStringCounter(c *C) {
	sc := make(StringCounter)
	c.Assert(sc.Add("foo"), Equals, true)
	c.Assert(len(sc), Equals, 1)
	c.Assert(sc.Add("foo"), Equals, false)
	c.Assert(len(sc), Equals, 1)
	c.Assert(sc.Add("bar"), Equals, true)
	c.Assert(len(sc), Equals, 2)
	c.Assert(sc.Delete("foo"), Equals, false)
	c.Assert(len(sc), Equals, 2)
	c.Assert(sc.Delete("bar"), Equals, true)
	c.Assert(len(sc), Equals, 1)
	c.Assert(sc.Delete("foo"), Equals, true)
	c.Assert(len(sc), Equals, 0)
}
