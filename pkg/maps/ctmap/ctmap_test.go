// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"strings"
	"testing"
	"time"
	"unsafe"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"
)

// Hook up gocheck into the "go test" runner.
type CTMapTestSuite struct{}

var _ = Suite(&CTMapTestSuite{})

func init() {
	InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
}

func Test(t *testing.T) {
	TestingT(t)
}

func (t *CTMapTestSuite) TestInit(c *C) {
	InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault, true, true, true)
	for mapType := mapType(0); mapType < mapTypeMax; mapType++ {
		info := mapInfo[mapType]
		if mapType.isIPv6() {
			c.Assert(info.keySize, Equals, int(unsafe.Sizeof(tuple.TupleKey6{})))
			c.Assert(strings.Contains(info.bpfDefine, "6"), Equals, true)
		}
		if mapType.isIPv4() {
			c.Assert(info.keySize, Equals, int(unsafe.Sizeof(tuple.TupleKey4{})))
			c.Assert(strings.Contains(info.bpfDefine, "4"), Equals, true)
		}
		if mapType.isTCP() {
			c.Assert(strings.Contains(info.bpfDefine, "TCP"), Equals, true)
		} else {
			c.Assert(strings.Contains(info.bpfDefine, "ANY"), Equals, true)
		}
		if mapType.isLocal() {
			c.Assert(info.maxEntries, Equals, mapNumEntriesLocal)
		}
		if mapType.isGlobal() {
			if mapType.isTCP() {
				c.Assert(info.maxEntries, Equals, option.CTMapEntriesGlobalTCPDefault)
			} else {
				c.Assert(info.maxEntries, Equals, option.CTMapEntriesGlobalAnyDefault)
			}
		}
	}
}

func (t *CTMapTestSuite) TestCalculateInterval(c *C) {
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
