// Copyright 2016-2020 Authors of Cilium
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

package ctmap

import (
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/tuple"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type CTMapTestSuite struct{}

var _ = Suite(&CTMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (t *CTMapTestSuite) TestInit(c *C) {
	infos := getMapInfo(true)
	for mapType := MapType(0); mapType < MapTypeMax; mapType++ {
		info := infos[mapType]
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
			c.Assert(info.maxEntries, Equals, MapNumEntriesLocal)
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
