// Copyright 2017 Authors of Cilium
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
	"net"
	"reflect"
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

func (b *ByteorderSuite) TestHostToNetworkSlice(c *C) {
	ip := net.ParseIP("b007::aaaa:bbbb:0:0")
	c.Assert(HostToNetworkSlice(ip[14:], reflect.Uint16), Equals, uint16(0))

	ip = net.ParseIP("b007::aaaa:bbbb:0:0")
	c.Assert(HostToNetworkSlice(ip[8:12], reflect.Uint32), Equals, uint32(0xaaaabbbb))
}

func (b *ByteorderSuite) TestHostToNetworkPutShort(c *C) {
	ip := net.ParseIP("b007::")
	HostToNetworkPut(ip[12:14], uint16(0xaabb))
	c.Assert(HostToNetworkSlice(ip[12:14], reflect.Uint16), Equals, uint16(0xaabb))
}

func (b *ByteorderSuite) TestHostToNetwork(c *C) {
	c.Assert(HostToNetwork(uint16(0xAABB)), Equals, uint16(0xBBAA),
		Commentf("TestHostToNetwork failed: HostToNetwork(0xAABB) != 0xBBAA"))

	c.Assert(HostToNetwork(uint32(0xAABBCCDD)), Equals, uint32(0xDDCCBBAA),
		Commentf("TestHostToNetwork failed: HostToNetwork(0xAABBCCDD) != 0xDDCCBBAA"))
}

func (b *ByteorderSuite) TestHostSliceToNetworkU32(c *C) {
	c.Assert(uint32(0x5b810b0a), Equals, HostSliceToNetwork(net.ParseIP("10.11.129.91"), reflect.Uint32).(uint32))
	c.Assert(uint32(0xd68a0b0a), Equals, HostSliceToNetwork(net.ParseIP("10.11.138.214"), reflect.Uint32).(uint32))
}
