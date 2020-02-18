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
	"net"

	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/service/healthserver"

	"github.com/cilium/cilium/pkg/checker"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"

	. "gopkg.in/check.v1"
)

type ManagerTestSuite struct {
	svc       *Service
	lbmap     *lbmap.LBMockMap // for accessing public fields
	svcHealth *healthserver.MockHealthHTTPServerFactory
}

var _ = Suite(&ManagerTestSuite{})

func (m *ManagerTestSuite) SetUpTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()

	m.svc = NewService(nil)
	m.svc.lbmap = lbmap.NewLBMockMap()
	m.lbmap = m.svc.lbmap.(*lbmap.LBMockMap)

	m.svcHealth = healthserver.NewMockHealthHTTPServerFactory()
	m.svc.healthServer = healthserver.WithHealthHTTPServerFactory(m.svcHealth)
}

func (e *ManagerTestSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()
}

var (
	frontend1 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, 0)
	frontend2 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.2"), 80, 0)
	backends1 = []lb.Backend{
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.1"), 8080),
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
	}
	backends2 = []lb.Backend{
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.3"), 8080),
	}
)

func (m *ManagerTestSuite) TestUpsertAndDeleteService(c *C) {
	// Should create a new service with two backends
	created, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcNamespace, Equals, "ns1")

	// Should update nothing
	created, id1, err = m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcNamespace, Equals, "ns1")
	// TODO(brb) test that backends are the same
	// TODO(brb) check that .backends =~ .backendsByHash

	// Should remove one backend
	created, id1, err = m.svc.UpsertService(frontend1, backends1[0:1], lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 1)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcNamespace, Equals, "ns1")

	// Should add another service
	created, id2, err := m.svc.UpsertService(frontend2, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "svc2", "ns2")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")

	// Should remove the service and the backend, but keep another service and
	// its backends
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)

	// Should delete both backends of service
	created, id2, err = m.svc.UpsertService(frontend2, nil, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) TestRestoreServices(c *C) {
	_, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)
	_, id2, err := m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*lbmap.LBMockMap)
	m.svc = NewService(nil)
	m.svc.lbmap = lbmap
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)

	// Backends have been restored
	c.Assert(len(m.svc.backendByHash), Equals, 3)
	backends := append(backends1, backends2...)
	for _, b := range backends {
		_, found := m.svc.backendByHash[b.Hash()]
		c.Assert(found, Equals, true)
	}

	// Services have been restored too
	c.Assert(len(m.svc.svcByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].frontend, checker.DeepEquals, lbmap.ServiceByID[uint16(id1)].Frontend)
	c.Assert(m.svc.svcByID[id1].backends, checker.DeepEquals, lbmap.ServiceByID[uint16(id1)].Backends)
	c.Assert(m.svc.svcByID[id2].frontend, checker.DeepEquals, lbmap.ServiceByID[uint16(id2)].Frontend)
	c.Assert(m.svc.svcByID[id2].backends, checker.DeepEquals, lbmap.ServiceByID[uint16(id2)].Backends)
}

func (m *ManagerTestSuite) TestSyncWithK8sFinished(c *C) {
	_, _, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)
	_, _, err = m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyCluster, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*lbmap.LBMockMap)
	m.svc = NewService(nil)
	m.svc.lbmap = lbmap
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)

	// Imitate a situation where svc1 was deleted while we were down.
	// In real life, the following upsert is called by k8s_watcher during
	// the sync period of the cilium-agent's k8s service cache which happens
	// during the initialization of cilium-agent.
	_, id2, err := m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyCluster, 0, "svc2", "ns2")
	c.Assert(err, IsNil)

	// cilium-agent finished the initialization, and thus SyncWithK8sFinished
	// is called
	err = m.svc.SyncWithK8sFinished()
	c.Assert(err, IsNil)

	// svc1 should be removed from cilium
	c.Assert(len(m.svc.svcByID), Equals, 1)
	_, found := m.svc.svcByID[id2]
	c.Assert(found, Equals, true)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")
}

func (m *ManagerTestSuite) TestHealthCheckNodePort(c *C) {
	// Create two node-local backends
	be1 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.1"), 8080)
	be2 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080)

	// Insert svc1 with local backends
	be2.NodeName = node.GetName()
	be1.NodeName = node.GetName()
	backends1 := []lb.Backend{be1, be2}

	_, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyLocal, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(backends1))

	// Insert svc1 with remote backends
	be1.NodeName = "remote-node"
	be2.NodeName = "remote-node"
	backends1 = []lb.Backend{be1, be2}
	c.Assert(node.GetName(), Not(Equals), "remote-node")

	new, _, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyLocal, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, 0)

	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)
}

func (m *ManagerTestSuite) TestGetDeepCopyServiceByAddr(c *C) {
	fe := frontend1.DeepCopy()
	var be []lb.Backend
	for _, backend := range backends1 {
		be = append(be, *backend.DeepCopy())
	}
	name := "svc1"
	namespace := "ns1"
	hcport := uint16(3)
	created, id1, err := m.svc.UpsertService(*fe, be, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, hcport, name, namespace)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	fe.ID = id1
	be[0].ID = 1
	be[1].ID = 2
	byid, ok := m.svc.GetDeepCopyServiceByID(lb.ServiceID(id1))
	c.Assert(ok, Equals, true)
	byaddr, ok := m.svc.GetDeepCopyServiceByAddr(frontend1.L3n4Addr)
	c.Assert(ok, Equals, true)
	c.Assert(byid, checker.DeepEquals, byaddr)
	c.Assert(byaddr.Frontend, checker.DeepEquals, *fe)
	c.Assert(byaddr.Backends, checker.DeepEquals, be)
	c.Assert(byaddr.Type, Equals, lb.SVCTypeNodePort)
	c.Assert(byaddr.TrafficPolicy, Equals, lb.SVCTrafficPolicyCluster)
	c.Assert(byaddr.HealthCheckNodePort, Equals, hcport)
	c.Assert(byaddr.Namespace, Equals, namespace)
	c.Assert(byaddr.Name, Equals, name)
}
