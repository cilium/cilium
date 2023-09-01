// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build !privileged_tests

package ctmap

import (
	"strings"
	"testing"
	"time"
	"unsafe"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/bpf"
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
	cachedGCInterval = time.Duration(0)

	c.Assert(calculateInterval(bpf.MapTypeLRUHash, time.Minute, 0.1), Equals, time.Minute)  // no change
	c.Assert(calculateInterval(bpf.MapTypeLRUHash, time.Minute, 0.2), Equals, time.Minute)  // no change
	c.Assert(calculateInterval(bpf.MapTypeLRUHash, time.Minute, 0.25), Equals, time.Minute) // no change

	c.Assert(calculateInterval(bpf.MapTypeLRUHash, time.Minute, 0.40), Equals, 36*time.Second)
	c.Assert(calculateInterval(bpf.MapTypeLRUHash, time.Minute, 0.60), Equals, 24*time.Second)

	c.Assert(calculateInterval(bpf.MapTypeLRUHash, 10*time.Second, 0.01), Equals, 15*time.Second)
	c.Assert(calculateInterval(bpf.MapTypeLRUHash, 10*time.Second, 0.04), Equals, 15*time.Second)

	c.Assert(calculateInterval(bpf.MapTypeLRUHash, 1*time.Second, 0.9), Equals, defaults.ConntrackGCMinInterval)
	c.Assert(calculateInterval(bpf.MapTypeHash, 1*time.Second, 0.9), Equals, defaults.ConntrackGCMinInterval)

	c.Assert(calculateInterval(bpf.MapTypeLRUHash, 24*time.Hour, 0.01), Equals, defaults.ConntrackGCMaxLRUInterval)
	c.Assert(calculateInterval(bpf.MapTypeHash, 24*time.Hour, 0.01), Equals, defaults.ConntrackGCMaxInterval)
}

func (t *CTMapTestSuite) TestGetInterval(c *C) {
	cachedGCInterval = time.Minute
	c.Assert(GetInterval(bpf.MapTypeLRUHash, 0.1), Equals, time.Minute)

	// Setting ConntrackGCInterval overrides the calculation
	oldInterval := option.Config.ConntrackGCInterval
	option.Config.ConntrackGCInterval = 10 * time.Second
	c.Assert(GetInterval(bpf.MapTypeLRUHash, 0.1), Equals, 10*time.Second)
	option.Config.ConntrackGCInterval = oldInterval
	c.Assert(GetInterval(bpf.MapTypeLRUHash, 0.1), Equals, time.Minute)

	// Setting ConntrackGCMaxInterval limits the maximum interval
	oldMaxInterval := option.Config.ConntrackGCMaxInterval
	option.Config.ConntrackGCMaxInterval = 20 * time.Second
	c.Assert(GetInterval(bpf.MapTypeLRUHash, 0.1), Equals, 20*time.Second)
	option.Config.ConntrackGCMaxInterval = oldMaxInterval
	c.Assert(GetInterval(bpf.MapTypeLRUHash, 0.1), Equals, time.Minute)

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
