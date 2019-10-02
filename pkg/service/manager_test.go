// Copyright 2019 Authors of Cilium
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
	"fmt"
	"net"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	. "gopkg.in/check.v1"
)

type ManagerTestSuite struct {
	svc   *Service
	lbmap *lbmap.LBMockMap // for accessing public fields
}

var _ = Suite(&ManagerTestSuite{})

func (m *ManagerTestSuite) SetUpTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()

	m.svc = NewService()
	m.svc.lbmap = lbmap.NewLBMockMap()
	m.lbmap = m.svc.lbmap.(*lbmap.LBMockMap)
}

func (e *ManagerTestSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()
}

var (
	frontend1 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, 0)
	frontend2 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.2"), 80, 0)
	backends1 = []lb.LBBackEnd{
		*lb.NewLBBackEnd(0, lb.TCP, net.ParseIP("10.0.0.1"), 8080),
		*lb.NewLBBackEnd(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
	}
	backends2 = []lb.LBBackEnd{
		*lb.NewLBBackEnd(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
		*lb.NewLBBackEnd(0, lb.TCP, net.ParseIP("10.0.0.3"), 8080),
	}
)

func (m *ManagerTestSuite) TestUpsertAndDeleteService(c *C) {
	frontend1 := *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, 0)
	frontend2 := *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.2"), 80, 0)
	backends1 := []lb.LBBackEnd{
		*lb.NewLBBackEnd(0, lb.TCP, net.ParseIP("10.0.0.1"), 8080),
		*lb.NewLBBackEnd(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
	}

	// Should create a new service with two backends
	created, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].BES), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)

	// Should update nothing
	created, id1, err = m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].BES), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	// TODO(brb) test that backends are the same

	// Should remove one backend
	created, id1, err = m.svc.UpsertService(frontend1, backends1[0:1], lb.SVCTypeNodePort)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].BES), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 1)

	// Should add another service
	created, id2, err := m.svc.UpsertService(frontend2, backends1, lb.SVCTypeNodePort)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].BES), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)

	// Should remove the service and the backend, but keep another service and
	// its backends
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)

	// Should delete both backends of service
	created, id2, err = m.svc.UpsertService(frontend2, nil, lb.SVCTypeNodePort)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].BES), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) TestRestoreServices(c *C) {
	_, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort)
	c.Assert(err, IsNil)
	_, id2, err := m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP)
	c.Assert(err, IsNil)
	fmt.Println(id1, id2)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*lbmap.LBMockMap)
	m.svc = NewService()
	m.svc.lbmap = lbmap
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)

	// Backends have been restored
	c.Assert(len(m.svc.backendByHash), Equals, 3)
	backends := append(backends1, backends2...)
	for _, b := range backends {
		_, found := m.svc.backendByHash[b.SHA256Sum()]
		c.Assert(found, Equals, true)
	}

	// Services have been restored too
	c.Assert(len(m.svc.svcByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1], Equals, lbmap.ServiceByID[uint16(id1)])
	c.Assert(m.svc.svcByID[id2], Equals, lbmap.ServiceByID[uint16(id2)])
}
