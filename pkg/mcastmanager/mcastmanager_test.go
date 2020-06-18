// Copyright 2020 Authors of Cilium
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

package mcastmanager

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/addressing"
	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type McastManagerSuite struct {
}

var _ = Suite(&McastManagerSuite{})

func (m *McastManagerSuite) TestAddRemoveEndpoint(c *C) {
	ifaces, err := net.Interfaces()
	c.Assert(err, IsNil)

	if len(ifaces) == 0 {
		c.Skip("no interfaces to test")
	}

	var (
		ok bool

		iface = ifaces[0]
		mgr   = New(iface.Name)
	)

	// Add first endpoint
	mgr.AddAddress(ipv6("f00d::1234"))

	c.Assert(mgr.state, HasLen, 1)
	_, ok = mgr.state["ff02::1:ff00:1234"]
	c.Assert(ok, Equals, true)

	// Add another endpoint that shares the same maddr
	mgr.AddAddress(ipv6("f00d:aabb::1234"))

	c.Assert(mgr.state, HasLen, 1)

	// Remove the first endpoint
	mgr.RemoveAddress(ipv6("f00d::1234"))

	c.Assert(mgr.state, HasLen, 1)
	_, ok = mgr.state["ff02::1:ff00:1234"]
	c.Assert(ok, Equals, true)

	// Remove the second endpoint
	mgr.RemoveAddress(ipv6("f00d:aabb::1234"))

	c.Assert(mgr.state, HasLen, 0)
	_, ok = mgr.state["ff02::1:ff00:1234"]
	c.Assert(ok, Equals, false)
}

func (m *McastManagerSuite) TestAddRemoveNil(c *C) {
	ifaces, err := net.Interfaces()
	c.Assert(err, IsNil)

	if len(ifaces) == 0 {
		c.Skip("no interfaces to test")
	}

	var (
		iface = ifaces[0]
		mgr   = New(iface.Name)
	)

	mgr.AddAddress(nil)
	mgr.RemoveAddress(nil)
}

func ipv6(addr string) addressing.CiliumIPv6 {
	ret, _ := addressing.NewCiliumIPv6(addr)
	return ret
}
