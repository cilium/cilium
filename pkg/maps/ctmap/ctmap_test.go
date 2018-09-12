// Copyright 2016-2018 Authors of Cilium
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

package ctmap

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/cilium/pkg/option"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type CTMapTestSuite struct{}

var _ = Suite(&CTMapTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (t *CTMapTestSuite) TestInit(c *C) {
	InitMapInfo(option.CTMapEntriesGlobalTCPDefault, option.CTMapEntriesGlobalAnyDefault)
	for mapType := MapType(0); mapType < MapTypeMax; mapType++ {
		info := mapInfo[mapType]
		if mapType.isIPv6() {
			c.Assert(info.keySize, Equals, int(unsafe.Sizeof(CtKey6{})))
			c.Assert(strings.Contains(info.bpfDefine, "6"), Equals, true)
		}
		if mapType.isIPv4() {
			c.Assert(info.keySize, Equals, int(unsafe.Sizeof(CtKey4{})))
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
