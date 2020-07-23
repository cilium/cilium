// Copyright 2016-2018 Authors of Cilium
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

package service

import (
	"net"
	"testing"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/loadbalancer"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type IDAllocTestSuite struct{}

var _ = Suite(&IDAllocTestSuite{})

func (e *IDAllocTestSuite) SetUpTest(c *C) {
	serviceIDAlloc.resetLocalID()
}

func (e *IDAllocTestSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
}

var (
	l3n4Addr1 = loadbalancer.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: loadbalancer.L4Addr{Port: 0, Protocol: "UDP"},
	}
	l3n4Addr2 = loadbalancer.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: loadbalancer.L4Addr{Port: 1, Protocol: "TCP"},
	}
	l3n4Addr3 = loadbalancer.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: loadbalancer.L4Addr{Port: 1, Protocol: "UDP"},
	}
	l3n4Addr4 = loadbalancer.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: loadbalancer.L4Addr{Port: 2, Protocol: "UDP"},
	}
	wantL3n4AddrID = &loadbalancer.L3n4AddrID{
		ID:       123,
		L3n4Addr: l3n4Addr2,
	}
)

func (s *IDAllocTestSuite) TestServices(c *C) {
	var nilL3n4AddrID *loadbalancer.L3n4AddrID
	// Set up last free ID with zero
	id, err := getMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, FirstFreeServiceID)

	ffsIDu16 := loadbalancer.ServiceID(uint16(FirstFreeServiceID))

	l3n4AddrID, err := AcquireID(l3n4Addr1, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, loadbalancer.ID(ffsIDu16))

	l3n4AddrID, err = AcquireID(l3n4Addr1, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, loadbalancer.ID(ffsIDu16))

	l3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, loadbalancer.ID(ffsIDu16+1))

	// different protocols should change the id
	l3n4AddrID, err = AcquireID(l3n4Addr3, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, loadbalancer.ID(ffsIDu16+2))

	gotL3n4AddrID, err := GetID(FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	wantL3n4AddrID.ID = loadbalancer.ID(ffsIDu16)
	wantL3n4AddrID.L3n4Addr = l3n4Addr1
	c.Assert(gotL3n4AddrID, checker.DeepEquals, wantL3n4AddrID)

	err = DeleteID(FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotL3n4AddrID, err = GetID(FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, Equals, nilL3n4AddrID)

	gotL3n4AddrID, err = GetID(FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	wantL3n4AddrID.ID = loadbalancer.ID(FirstFreeServiceID + 1)
	wantL3n4AddrID.L3n4Addr = l3n4Addr2
	c.Assert(gotL3n4AddrID, checker.DeepEquals, wantL3n4AddrID)

	err = DeleteID(FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = setIDSpace(FirstFreeServiceID, FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = DeleteID(FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotL3n4AddrID, err = GetID(FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, Equals, nilL3n4AddrID)

	gotL3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ID(FirstFreeServiceID+1))

	err = DeleteID(uint32(gotL3n4AddrID.ID))
	c.Assert(err, Equals, nil)
	err = DeleteID(FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	err = DeleteID(FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)

	gotL3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ID(ffsIDu16))

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 0)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ID(FirstFreeServiceID+1))

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 99)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ID(FirstFreeServiceID+1))

	err = DeleteID(uint32(FirstFreeServiceID + 1))
	c.Assert(err, Equals, nil)

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 99)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ID(99))

	// ID "99" has been already allocated to l3n4Addr1
	gotL3n4AddrID, err = AcquireID(l3n4Addr4, 99)
	c.Assert(err, NotNil)
	c.Assert(gotL3n4AddrID, IsNil)
}

func (s *IDAllocTestSuite) TestGetMaxServiceID(c *C) {
	lastID := uint32(MaxSetOfServiceID - 1)

	err := setIDSpace(lastID, MaxSetOfServiceID)
	c.Assert(err, IsNil)

	id, err := getMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (MaxSetOfServiceID - 1))
}

func (s *IDAllocTestSuite) TestBackendID(c *C) {
	firstBackendID := loadbalancer.BackendID(FirstFreeBackendID)

	id1, err := AcquireBackendID(l3n4Addr1)
	c.Assert(err, Equals, nil)
	c.Assert(id1, Equals, firstBackendID)

	id1, err = AcquireBackendID(l3n4Addr1)
	c.Assert(err, Equals, nil)
	c.Assert(id1, Equals, firstBackendID)

	id2, err := AcquireBackendID(l3n4Addr2)
	c.Assert(err, Equals, nil)
	c.Assert(id2, Equals, firstBackendID+1)

	existingID1, err := LookupBackendID(l3n4Addr1)
	c.Assert(err, Equals, nil)
	c.Assert(existingID1, Equals, id1)
}

func (s *IDAllocTestSuite) BenchmarkAllocation(c *C) {
	addr := loadbalancer.L3n4Addr{
		IP:     net.IPv6loopback,
		L4Addr: loadbalancer.L4Addr{Port: 0, Protocol: "UDP"},
	}

	c.ResetTimer()
	for i := 0; i < c.N; i++ {
		addr.L4Addr.Port = uint16(c.N)
		_, err := AcquireID(addr, 0)
		c.Assert(err, IsNil)
	}
	c.StopTimer()

}
