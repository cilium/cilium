// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package byteorder

import (
	"encoding/binary"
	"net"
	"testing"

	. "github.com/cilium/checkmate"
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
