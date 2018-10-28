// Copyright 2016-2017 Authors of Cilium
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

package addressing

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type AddressingSuite struct{}

var _ = Suite(&AddressingSuite{})

func (s *AddressingSuite) TestCiliumIPv6(c *C) {
	ip, err := NewCiliumIPv6("b007::")
	c.Assert(err, IsNil)
	ip2, _ := NewCiliumIPv6("")
	// Lacking a better Equals method, checking if the stringified IP is consistent
	c.Assert(ip.String() == ip2.String(), Equals, false)

	ip, err = NewCiliumIPv6("b007::aaaa:bbbb:0:0")
	c.Assert(err, IsNil)
	c.Assert(ip.String(), Equals, "b007::aaaa:bbbb:0:0")
}

func (s *AddressingSuite) TestCiliumIPv4(c *C) {
	ip, err := NewCiliumIPv4("10.1.0.0")
	c.Assert(err, IsNil)
	ip2, _ := NewCiliumIPv4("")
	// Lacking a better Equals method, checking if the stringified IP is consistent
	c.Assert(ip.String() == ip2.String(), Equals, false)

	ip, err = NewCiliumIPv4("b007::")
	c.Assert(err, Not(Equals), nil)
}

func (s *AddressingSuite) TestCiliumIPv6Negative(c *C) {
	ip, err := NewCiliumIPv6("")
	c.Assert(err, NotNil)
	c.Assert(ip, IsNil)
	c.Assert(ip.String(), Equals, "")

	ip, err = NewCiliumIPv6("192.168.0.1")
	c.Assert(err, NotNil)
	c.Assert(ip, IsNil)
}

func (s *AddressingSuite) TestCiliumIPv4Negative(c *C) {
	ip, err := NewCiliumIPv4("")
	c.Assert(err, NotNil)
	c.Assert(ip, IsNil)
	c.Assert(ip.String(), Equals, "")
}
