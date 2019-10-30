// Copyright 2018-2019 Authors of Cilium
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

package watcher

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
type IPCacheTestSuite struct{}

var _ = Suite(&IPCacheTestSuite{})

func Test(t *testing.T) {
	TestingT(t)
}

func (s *IPCacheTestSuite) TestKeyToIPNet(c *C) {
	// Valid IPv6.
	validIPv6Key := "cilium/state/ip/v1/default/f00d::a00:0:0:c164"

	_, expectedIPv6, err := net.ParseCIDR("f00d::a00:0:0:c164/128")
	c.Assert(err, IsNil)

	ipv6, isHost, err := keyToIPNet(validIPv6Key)
	c.Assert(ipv6, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, true)
	c.Assert(ipv6, checker.DeepEquals, expectedIPv6)

	// Valid IPv6 prefix.
	validIPv6Key = "cilium/state/ip/v1/default/f00d::a00:0:0:0/64"

	_, expectedIPv6, err = net.ParseCIDR("f00d::a00:0:0:0/64")
	c.Assert(err, IsNil)

	ipv6, isHost, err = keyToIPNet(validIPv6Key)
	c.Assert(ipv6, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, false)
	c.Assert(ipv6, checker.DeepEquals, expectedIPv6)

	// Valid IPv4.
	validIPv4Key := "cilium/state/ip/v1/default/10.0.114.197"
	_, expectedIPv4, err := net.ParseCIDR("10.0.114.197/32")
	c.Assert(err, IsNil)
	ipv4, isHost, err := keyToIPNet(validIPv4Key)
	c.Assert(ipv4, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, true)
	c.Assert(ipv4, checker.DeepEquals, expectedIPv4)

	// Valid IPv4 prefix.
	validIPv4Key = "cilium/state/ip/v1/default/10.0.114.0/24"
	_, expectedIPv4, err = net.ParseCIDR("10.0.114.0/24")
	c.Assert(err, IsNil)
	ipv4, isHost, err = keyToIPNet(validIPv4Key)
	c.Assert(ipv4, Not(IsNil))
	c.Assert(err, IsNil)
	c.Assert(isHost, Equals, false)
	c.Assert(ipv4, checker.DeepEquals, expectedIPv4)

	// Invalid prefix.
	invalidPrefixKey := "cilium/state/foobar/v1/default/f00d::a00:0:0:c164"
	nilIP, isHost, err := keyToIPNet(invalidPrefixKey)
	c.Assert(nilIP, IsNil)
	c.Assert(err, Not(IsNil))
	c.Assert(isHost, Equals, false)

	// Invalid IP in key.
	invalidIPKey := "cilium/state/ip/v1/default/10.abfd.114.197"
	nilIP, isHost, err = keyToIPNet(invalidIPKey)
	c.Assert(nilIP, IsNil)
	c.Assert(err, Not(IsNil))
	c.Assert(isHost, Equals, false)

	// Invalid CIDR.
	invalidIPKey = "cilium/state/ip/v1/default/192.0.2.3/54"
	nilIP, isHost, err = keyToIPNet(invalidIPKey)
	c.Assert(nilIP, IsNil)
	c.Assert(err, Not(IsNil))
	c.Assert(isHost, Equals, false)
}
