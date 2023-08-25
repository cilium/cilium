// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package envoy

import (
	. "github.com/cilium/checkmate"
	envoyAPI "github.com/cilium/proxy/go/cilium/api"
)

type ResourcesSuite struct{}

var _ = Suite(&ResourcesSuite{})

func (s *SortSuite) TestHandleIPUpsert(c *C) {
	cache := newNPHDSCache(nil)

	msg, err := cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	c.Assert(err, IsNil)
	c.Assert(msg, IsNil)

	err = cache.handleIPUpsert(nil, "123", "1.2.3.0/32", 123)
	c.Assert(err, IsNil)

	msg, err = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	c.Assert(err, IsNil)
	c.Assert(msg, Not(IsNil))
	npHost := msg.(*envoyAPI.NetworkPolicyHosts)
	c.Assert(npHost, Not(IsNil))
	c.Assert(npHost.Policy, Equals, uint64(123))
	c.Assert(len(npHost.HostAddresses), Equals, 1)
	c.Assert(npHost.HostAddresses[0], Equals, "1.2.3.0/32")

	// Another address
	err = cache.handleIPUpsert(npHost, "123", "::1/128", 123)
	c.Assert(err, IsNil)

	msg, err = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	c.Assert(err, IsNil)
	c.Assert(msg, Not(IsNil))
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	c.Assert(npHost, Not(IsNil))
	c.Assert(npHost.Policy, Equals, uint64(123))
	c.Assert(len(npHost.HostAddresses), Equals, 2)
	c.Assert(npHost.HostAddresses[0], Equals, "1.2.3.0/32")
	c.Assert(npHost.HostAddresses[1], Equals, "::1/128")

	// Check that duplicates are not added, and not erroring out
	err = cache.handleIPUpsert(npHost, "123", "1.2.3.0/32", 123)
	c.Assert(err, IsNil)

	msg, err = cache.Lookup(NetworkPolicyHostsTypeURL, "123")
	c.Assert(err, IsNil)
	c.Assert(msg, Not(IsNil))
	npHost = msg.(*envoyAPI.NetworkPolicyHosts)
	c.Assert(npHost, Not(IsNil))
	c.Assert(npHost.Policy, Equals, uint64(123))
	c.Assert(len(npHost.HostAddresses), Equals, 2)
	c.Assert(npHost.HostAddresses[0], Equals, "1.2.3.0/32")
	c.Assert(npHost.HostAddresses[1], Equals, "::1/128")
}
