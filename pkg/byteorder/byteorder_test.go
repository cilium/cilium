// Copyright 2017-2021 Authors of Cilium
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

package byteorder

import (
	"encoding/binary"
	"net"
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type ByteorderSuite struct{}

var _ = Suite(&ByteorderSuite{})

func (b *ByteorderSuite) TestNativeIsInitialized(c *C) {
	c.Assert(Native, NotNil)
}

func (b *ByteorderSuite) TestHostToNetwork(c *C) {
	switch Native {
	case binary.LittleEndian:
		c.Assert(HostToNetwork16(0xAABB), Equals, uint16(0xBBAA))
		c.Assert(HostToNetwork32(0xAABBCCDD), Equals, uint32(0xDDCCBBAA))
	case binary.BigEndian:
		c.Assert(HostToNetwork16(0xAABB), Equals, uint16(0xAABB))
		c.Assert(HostToNetwork32(0xAABBCCDD), Equals, uint32(0xAABBCCDD))
	}
}

func (b *ByteorderSuite) TestNetIPv4ToHost32(c *C) {
	switch Native {
	case binary.LittleEndian:
		c.Assert(NetIPv4ToHost32(net.ParseIP("10.11.129.91")), Equals, uint32(0x5b810b0a))
		c.Assert(NetIPv4ToHost32(net.ParseIP("10.11.138.214")), Equals, uint32(0xd68a0b0a))
	case binary.BigEndian:
		c.Assert(NetIPv4ToHost32(net.ParseIP("10.11.129.91")), Equals, uint32(0x0a0b815b))
		c.Assert(NetIPv4ToHost32(net.ParseIP("10.11.138.214")), Equals, uint32(0x0a0b8ad6))
	}
}
