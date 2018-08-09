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

package service

import (
	"net"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/loadbalancer"

	. "gopkg.in/check.v1"
)

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
	wantL3n4AddrID = &loadbalancer.L3n4AddrID{
		ID:       123,
		L3n4Addr: l3n4Addr2,
	}
)

func (ds *ServiceTestSuite) TestServices(c *C) {
	var nilL3n4AddrID *loadbalancer.L3n4AddrID
	// Set up last free ID with zero
	id, err := getMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, common.FirstFreeServiceID)

	ffsIDu16 := loadbalancer.ServiceID(uint16(common.FirstFreeServiceID))

	l3n4AddrID, err := AcquireID(l3n4Addr1, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16)

	l3n4AddrID, err = AcquireID(l3n4Addr1, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16)

	l3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16+1)

	// l3n4Addr3 should have the same ID as l3n4Addr2 since we are omitting the
	// protocol type.
	l3n4AddrID, err = AcquireID(l3n4Addr3, 0)
	c.Assert(err, Equals, nil)
	c.Assert(l3n4AddrID.ID, Equals, ffsIDu16+1)

	gotL3n4AddrID, err := GetID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	wantL3n4AddrID.ID = ffsIDu16
	wantL3n4AddrID.L3n4Addr = l3n4Addr1
	c.Assert(gotL3n4AddrID, comparator.DeepEquals, wantL3n4AddrID)

	err = DeleteID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotL3n4AddrID, err = GetID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, Equals, nilL3n4AddrID)

	gotL3n4AddrID, err = GetID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	wantL3n4AddrID.ID = loadbalancer.ServiceID(common.FirstFreeServiceID + 1)
	wantL3n4AddrID.L3n4Addr = l3n4Addr2
	c.Assert(gotL3n4AddrID, comparator.DeepEquals, wantL3n4AddrID)

	err = DeleteID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = setIDSpace(common.FirstFreeServiceID, common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)

	err = DeleteID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	gotL3n4AddrID, err = GetID(common.FirstFreeServiceID)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID, Equals, nilL3n4AddrID)

	gotL3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ServiceID(common.FirstFreeServiceID+1))

	err = DeleteID(uint32(gotL3n4AddrID.ID))
	c.Assert(err, Equals, nil)
	err = DeleteID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)
	err = DeleteID(common.FirstFreeServiceID + 1)
	c.Assert(err, Equals, nil)

	gotL3n4AddrID, err = AcquireID(l3n4Addr2, 0)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, ffsIDu16)

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 0)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ServiceID(common.FirstFreeServiceID+1))

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 99)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ServiceID(common.FirstFreeServiceID+1))

	err = DeleteID(uint32(common.FirstFreeServiceID + 1))
	c.Assert(err, Equals, nil)

	gotL3n4AddrID, err = AcquireID(l3n4Addr1, 99)
	c.Assert(err, Equals, nil)
	c.Assert(gotL3n4AddrID.ID, Equals, loadbalancer.ServiceID(99))
}

func (ds *ServiceTestSuite) TestGetMaxServiceID(c *C) {
	lastID := uint32(common.MaxSetOfServiceID - 1)

	if enableGlobalServiceIDs {
		err := kvstore.Client().SetValue(common.LastFreeServiceIDKeyPath, lastID)
		c.Assert(err, IsNil)
	} else {
		err := setIDSpace(lastID, common.MaxSetOfServiceID)
		c.Assert(err, IsNil)
	}

	id, err := getMaxServiceID()
	c.Assert(err, Equals, nil)
	c.Assert(id, Equals, (common.MaxSetOfServiceID - 1))
}

func (ds *ServiceTestSuite) BenchmarkAllocation(c *C) {
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
