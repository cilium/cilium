// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"testing"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
)

// Hook up gocheck into the "go test" runner.
type CTMapTestSuite struct{}

var _ = Suite(&CTMapTestSuite{})

func init() {
	InitMapInfo(true, true, true)
}

func Test(t *testing.T) {
	TestingT(t)
}

func (t *CTMapTestSuite) TestCalculateInterval(c *C) {
	cachedGCInterval = time.Duration(0)

	c.Assert(calculateInterval(time.Minute, 0.1), Equals, time.Minute)  // no change
	c.Assert(calculateInterval(time.Minute, 0.2), Equals, time.Minute)  // no change
	c.Assert(calculateInterval(time.Minute, 0.25), Equals, time.Minute) // no change

	c.Assert(calculateInterval(time.Minute, 0.40), Equals, 36*time.Second)
	c.Assert(calculateInterval(time.Minute, 0.60), Equals, 24*time.Second)

	c.Assert(calculateInterval(10*time.Second, 0.01), Equals, 15*time.Second)
	c.Assert(calculateInterval(10*time.Second, 0.04), Equals, 15*time.Second)

	c.Assert(calculateInterval(1*time.Second, 0.9), Equals, defaults.ConntrackGCMinInterval)

	c.Assert(calculateInterval(24*time.Hour, 0.01), Equals, defaults.ConntrackGCMaxLRUInterval)
}

func (t *CTMapTestSuite) TestGetInterval(c *C) {
	cachedGCInterval = time.Minute
	c.Assert(GetInterval(cachedGCInterval, 0.1), Equals, time.Minute)

	// Setting ConntrackGCInterval overrides the calculation
	oldInterval := option.Config.ConntrackGCInterval
	option.Config.ConntrackGCInterval = 10 * time.Second
	c.Assert(GetInterval(cachedGCInterval, 0.1), Equals, 10*time.Second)
	option.Config.ConntrackGCInterval = oldInterval
	c.Assert(GetInterval(cachedGCInterval, 0.1), Equals, time.Minute)

	// Setting ConntrackGCMaxInterval limits the maximum interval
	oldMaxInterval := option.Config.ConntrackGCMaxInterval
	option.Config.ConntrackGCMaxInterval = 20 * time.Second
	c.Assert(GetInterval(cachedGCInterval, 0.1), Equals, 20*time.Second)
	option.Config.ConntrackGCMaxInterval = oldMaxInterval
	c.Assert(GetInterval(cachedGCInterval, 0.1), Equals, time.Minute)

	cachedGCInterval = time.Duration(0)
}

func (t *CTMapTestSuite) TestFilterMapsByProto(c *C) {
	maps := []*Map{
		newMap("tcp4", mapTypeIPv4TCPGlobal),
		newMap("any4", mapTypeIPv4AnyGlobal),
		newMap("tcp6", mapTypeIPv6TCPGlobal),
		newMap("any6", mapTypeIPv6AnyGlobal),
	}

	ctMapTCP, ctMapAny := FilterMapsByProto(maps, CTMapIPv4)
	c.Assert(ctMapTCP.mapType, Equals, mapTypeIPv4TCPGlobal)
	c.Assert(ctMapAny.mapType, Equals, mapTypeIPv4AnyGlobal)

	ctMapTCP, ctMapAny = FilterMapsByProto(maps, CTMapIPv6)
	c.Assert(ctMapTCP.mapType, Equals, mapTypeIPv6TCPGlobal)
	c.Assert(ctMapAny.mapType, Equals, mapTypeIPv6AnyGlobal)

	maps = maps[0:2] // remove ipv6 maps
	ctMapTCP, ctMapAny = FilterMapsByProto(maps, CTMapIPv6)
	c.Assert(ctMapTCP, IsNil)
	c.Assert(ctMapAny, IsNil)
}
