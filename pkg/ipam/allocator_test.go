// Copyright 2018 Authors of Cilium
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

// +build !privileged_test

package ipam

import (
	"net"

	"github.com/cilium/cilium/common/addressing"
	"github.com/cilium/cilium/pkg/datapath/fake"

	. "gopkg.in/check.v1"
)

type ownerMock struct{}

func (o *ownerMock) K8sEventReceived(scope string, action string, valid, equal bool) {}
func (o *ownerMock) K8sEventProcessed(scope string, action string, status bool)      {}
func (o *ownerMock) UpdateCiliumNodeResource()                                       {}

func (s *IPAMSuite) TestAllocatedIPDump(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, Configuration{EnableIPv4: true, EnableIPv6: true}, &ownerMock{})

	ipv4 := fakeAddressing.IPv4().AllocationCIDR().IP
	ipv6 := fakeAddressing.IPv6().AllocationCIDR().IP

	for i := 0; i < 10; i++ {
		_, err := addressing.NewCiliumIPv4(ipv4.String())
		c.Assert(err, IsNil)
		nextIP(ipv4)

		_, err = addressing.NewCiliumIPv6(ipv6.String())
		c.Assert(err, IsNil)
		nextIP(ipv6)
	}

	allocv4, allocv6, status := ipam.Dump()
	c.Assert(status, Not(Equals), "")

	// Test the format of the dumped ip addresses
	for ip := range allocv4 {
		c.Assert(net.ParseIP(ip), NotNil)
	}
	for ip := range allocv6 {
		c.Assert(net.ParseIP(ip), NotNil)
	}
}
