// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"net"
	"time"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/cidr"
	"github.com/cilium/cilium/pkg/datapath/fake"
	"github.com/cilium/cilium/pkg/k8s/watchers/subscriber"
	"github.com/cilium/cilium/pkg/mtu"
)

type ownerMock struct{}

func (o *ownerMock) K8sEventReceived(resourceApiGroup, scope string, action string, valid, equal bool) {
}
func (o *ownerMock) K8sEventProcessed(scope string, action string, status bool) {}
func (o *ownerMock) RegisterCiliumNodeSubscriber(s subscriber.CiliumNode)       {}

func (o *ownerMock) UpdateCiliumNodeResource()                                          {}
func (o *ownerMock) LocalAllocCIDRsUpdated(ipv4AllocCIDRs, ipv6AllocCIDRs []*cidr.CIDR) {}

var mtuMock = mtu.NewConfiguration(0, false, false, false, 1500, nil)

func (s *IPAMSuite) TestAllocatedIPDump(c *C) {
	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)

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

func (s *IPAMSuite) TestExpirationTimer(c *C) {
	ip := net.ParseIP("1.1.1.1")
	timeout := 50 * time.Millisecond

	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)

	err := ipam.AllocateIP(ip, "foo", PoolDefault)
	c.Assert(err, IsNil)

	uuid, err := ipam.StartExpirationTimer(ip, PoolDefault, timeout)
	c.Assert(err, IsNil)
	c.Assert(uuid, Not(Equals), "")
	// must fail, already registered
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault, timeout)
	c.Assert(err, Not(IsNil))
	c.Assert(uuid, Equals, "")
	// must fail, already in use
	err = ipam.AllocateIP(ip, "foo", PoolDefault)
	c.Assert(err, Not(IsNil))
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// Must succeed, IP must be released again
	err = ipam.AllocateIP(ip, "foo", PoolDefault)
	c.Assert(err, IsNil)
	// register new expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault, timeout)
	c.Assert(err, IsNil)
	c.Assert(uuid, Not(Equals), "")
	// attempt to stop with an invalid uuid, must fail
	err = ipam.StopExpirationTimer(ip, PoolDefault, "unknown-uuid")
	c.Assert(err, Not(IsNil))
	// stop expiration with valid uuid
	err = ipam.StopExpirationTimer(ip, PoolDefault, uuid)
	c.Assert(err, IsNil)
	// Let expiration timer expire
	time.Sleep(2 * timeout)
	// must fail as IP is properly in use now
	err = ipam.AllocateIP(ip, "foo", PoolDefault)
	c.Assert(err, Not(IsNil))
	// release IP for real
	err = ipam.ReleaseIP(ip, PoolDefault)
	c.Assert(err, IsNil)

	// allocate IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault)
	c.Assert(err, IsNil)
	// register expiration timer
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault, timeout)
	c.Assert(err, IsNil)
	c.Assert(uuid, Not(Equals), "")
	// release IP, must also stop expiration timer
	err = ipam.ReleaseIP(ip, PoolDefault)
	c.Assert(err, IsNil)
	// allocate same IP again
	err = ipam.AllocateIP(ip, "foo", PoolDefault)
	c.Assert(err, IsNil)
	// register expiration timer must succeed even though stop was never called
	uuid, err = ipam.StartExpirationTimer(ip, PoolDefault, timeout)
	c.Assert(err, IsNil)
	c.Assert(uuid, Not(Equals), "")
	// release IP
	err = ipam.ReleaseIP(ip, PoolDefault)
	c.Assert(err, IsNil)
}

func (s *IPAMSuite) TestAllocateNextWithExpiration(c *C) {
	timeout := 50 * time.Millisecond

	fakeAddressing := fake.NewNodeAddressing()
	ipam := NewIPAM(fakeAddressing, &testConfiguration{}, &ownerMock{}, &ownerMock{}, &mtuMock, nil)

	ipv4, ipv6, err := ipam.AllocateNextWithExpiration("", "foo", PoolDefault, timeout)
	c.Assert(err, IsNil)

	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault)
	c.Assert(err, Not(IsNil))
	// IPv6 address must be in use
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault)
	c.Assert(err, Not(IsNil))

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be available again
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault)
	c.Assert(err, IsNil)
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault)
	c.Assert(err, IsNil)
	// Release IPs
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault)
	c.Assert(err, IsNil)
	err = ipam.ReleaseIP(ipv6.IP, PoolDefault)
	c.Assert(err, IsNil)

	// Allocate IPs again and test stopping the expiration timer
	ipv4, ipv6, err = ipam.AllocateNextWithExpiration("", "foo", PoolDefault, timeout)
	c.Assert(err, IsNil)

	// Stop expiration timer for IPv4 address
	err = ipam.StopExpirationTimer(ipv4.IP, PoolDefault, ipv4.ExpirationUUID)
	c.Assert(err, IsNil)

	// Let expiration timer expire
	time.Sleep(time.Second)
	// IPv4 address must be in use
	err = ipam.AllocateIP(ipv4.IP, "foo", PoolDefault)
	c.Assert(err, Not(IsNil))
	// IPv6 address must be available again
	err = ipam.AllocateIP(ipv6.IP, "foo", PoolDefault)
	c.Assert(err, IsNil)
	// Release IPv4 address
	err = ipam.ReleaseIP(ipv4.IP, PoolDefault)
	c.Assert(err, IsNil)
}
