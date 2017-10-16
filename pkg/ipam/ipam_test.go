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

package ipam

import (
	"testing"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/nodeaddress"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) {
	TestingT(t)
}

type IPAMSuite struct{}

var _ = Suite(&IPAMSuite{})

func (s *IPAMSuite) TestLock(c *C) {
	nodeaddress.InitDefaultPrefix("")
	err := Init()
	c.Assert(err, IsNil)

	// Since the IPs we have allocated to the endpoints might or might not
	// be in the allocrange specified in cilium, we need to specify them
	// manually on the endpoint based on the alloc range.
	ipv4 := nodeaddress.GetIPv4AllocRange().IP
	nextIP(ipv4)
	epipv4, err := addressing.NewCiliumIPv4(ipv4.String())
	c.Assert(err, IsNil)

	ipv6 := nodeaddress.GetIPv6AllocRange().IP
	nextIP(ipv6)
	epipv6, err := addressing.NewCiliumIPv6(ipv6.String())
	c.Assert(err, IsNil)

	// Forcefully release possible allocated IPs
	err = ipamConf.IPv4Allocator.Release(epipv4.IP())
	c.Assert(err, IsNil)
	err = ipamConf.IPv6Allocator.Release(epipv6.IP())
	c.Assert(err, IsNil)

	// Let's allocate the IP first so we can see the tests failing
	err = ipamConf.IPv4Allocator.Allocate(epipv4.IP())
	c.Assert(err, IsNil)

	err = ipamConf.IPv4Allocator.Release(epipv4.IP())
	c.Assert(err, IsNil)
}
