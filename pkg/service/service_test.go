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

	"github.com/cilium/cilium/pkg/checker"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"

	. "gopkg.in/check.v1"
)

type ManagerTestSuite struct {
	svc                       *Service
	lbmap                     *lbmap.LBMockMap // for accessing public fields
	svcHealth                 *healthserver.MockHealthHTTPServerFactory
	prevOptionSessionAffinity bool
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

	m.prevOptionSessionAffinity = option.Config.EnableSessionAffinity
	option.Config.EnableSessionAffinity = true
}

func (m *ManagerTestSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()
	option.Config.EnableSessionAffinity = m.prevOptionSessionAffinity
}

var (
	frontend1 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, lb.ScopeExternal, 0)
	frontend2 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.2"), 80, lb.ScopeExternal, 0)
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
	// Should create a new service with two backends and session affinity
	created, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, true, 100, 0, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcNamespace, Equals, "ns1")
	c.Assert(m.svc.svcByID[id1].sessionAffinity, Equals, true)
	c.Assert(m.svc.svcByID[id1].sessionAffinityTimeoutSec, Equals, uint32(100))
	c.Assert(m.lbmap.ServiceByID[uint16(id1)].SessionAffinity, Equals, true)
	c.Assert(m.lbmap.ServiceByID[uint16(id1)].SessionAffinityTimeoutSec, Equals, uint32(100))
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 2)
	for bID := range m.lbmap.BackendByID {
		c.Assert(m.lbmap.AffinityMatch[uint16(id1)][bID], Equals, struct{}{})
	}

	// Should remove session affinity
	created, id1, err = m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, false, 0, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcNamespace, Equals, "ns1")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 0)
	c.Assert(m.svc.svcByID[id1].sessionAffinity, Equals, false)
	c.Assert(m.lbmap.ServiceByID[uint16(id1)].SessionAffinity, Equals, false)
	// TODO(brb) test that backends are the same
	// TODO(brb) check that .backends =~ .backendsByHash

	// Should remove one backend and enable session affinity
	created, id1, err = m.svc.UpsertService(frontend1, backends1[0:1], lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, true, 200, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 1)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcNamespace, Equals, "ns1")
	c.Assert(m.svc.svcByID[id1].sessionAffinity, Equals, true)
	c.Assert(m.svc.svcByID[id1].sessionAffinityTimeoutSec, Equals, uint32(200))
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 1)
	for bID := range m.lbmap.BackendByID {
		c.Assert(m.lbmap.AffinityMatch[uint16(id1)][bID], Equals, struct{}{})
	}

	// Should add another service
	created, id2, err := m.svc.UpsertService(frontend2, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, true, 300, 0, "svc2", "ns2")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 2)

	// Should remove the service and the backend, but keep another service and
	// its backends. Also, should remove the affinity match.
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 0)

	// Should delete both backends of service
	created, id2, err = m.svc.UpsertService(frontend2, nil, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, true, 300, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 0)

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) TestRestoreServices(c *C) {
	_, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, false, 0, 0, "", "")
	c.Assert(err, IsNil)
	_, id2, err := m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyCluster, true, 200, 0, "", "")
	c.Assert(err, IsNil)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*lbmap.LBMockMap)
	m.svc = NewService(nil)
	m.svc.lbmap = lbmap

	// Add non-existing affinity matches
	lbmap.AddAffinityMatch(20, 300)
	lbmap.AddAffinityMatch(20, 301)
	lbmap.AddAffinityMatch(uint16(id1), 302)
	lbmap.AddAffinityMatch(uint16(id2), 305)

	// Restore services from lbmap
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

	// Session affinity too
	c.Assert(m.svc.svcByID[id1].sessionAffinity, Equals, false)
	c.Assert(m.svc.svcByID[id2].sessionAffinity, Equals, true)
	c.Assert(m.svc.svcByID[id2].sessionAffinityTimeoutSec, Equals, uint32(200))

	// Check that the non-existing affinity matches were removed
	matches, _ := lbmap.DumpAffinityMatches()
	c.Assert(len(matches), Equals, 1) // only the id2 svc has session affinity
	c.Assert(len(matches[uint16(id2)]), Equals, 2)
	for _, b := range lbmap.ServiceByID[uint16(id2)].Backends {
		c.Assert(m.lbmap.AffinityMatch[uint16(id1)][uint16(b.ID)], Equals, struct{}{})
	}

}

func (m *ManagerTestSuite) TestSyncWithK8sFinished(c *C) {
	_, id1, err := m.svc.UpsertService(frontend1, backends1, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, true, 300, 0, "", "")
	c.Assert(err, IsNil)
	_, _, err = m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyCluster, false, 0, 0, "", "")
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 2)

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
	_, id2, err := m.svc.UpsertService(frontend2, backends2, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyCluster, false, 0, 0, "svc2", "ns2")
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
	c.Assert(len(m.lbmap.AffinityMatch), Equals, 0)
}

func (m *ManagerTestSuite) TestHealthCheckNodePort(c *C) {
	// Create two frontends, one for LoadBalaner and one for ClusterIP.
	// This is used to emulate how we get K8s services from the K8s watcher,
	// i.e. one service per frontend (even if it is logically the same service)
	loadBalancerIP := *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, lb.ScopeExternal, 0)
	clusterIP := *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("10.20.30.40"), 80, lb.ScopeExternal, 0)

	// Create two node-local backends
	localBackend1 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.1"), 8080)
	localBackend2 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()
	localBackend2.NodeName = nodeTypes.GetName()
	localBackends := []lb.Backend{localBackend1, localBackend2}

	// Create three remote backends
	remoteBackend1 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.3"), 8080)
	remoteBackend2 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.4"), 8080)
	remoteBackend3 := *lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.5"), 8080)
	remoteBackend1.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend2.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend3.NodeName = "not-" + nodeTypes.GetName()
	remoteBackends := []lb.Backend{remoteBackend1, remoteBackend2, remoteBackend3}

	allBackends := []lb.Backend{localBackend1, localBackend2, remoteBackend1, remoteBackend2, remoteBackend3}

	// Insert svc1 as type LoadBalancer with some local backends
	_, id1, err := m.svc.UpsertService(loadBalancerIP, allBackends, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyLocal, false, 0, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localBackends))

	// Insert the the ClusterIP frontend of svc1
	_, id2, err := m.svc.UpsertService(clusterIP, allBackends, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyLocal, false, 0, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localBackends))

	// Update the HealthCheckNodePort for svc1
	new, _, err := m.svc.UpsertService(loadBalancerIP, allBackends, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyLocal, false, 0, 32000, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32000).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32000).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32000).LocalEndpoints, Equals, len(localBackends))
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Update the externalTrafficPolicy for svc1
	new, _, err = m.svc.UpsertService(loadBalancerIP, allBackends, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyCluster, false, 0, 0, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32000), IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Restore the original version of svc1
	new, _, err = m.svc.UpsertService(loadBalancerIP, allBackends, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyLocal, false, 0, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localBackends))

	// Upsert svc1 of type LoadBalancer with only remote backends
	new, _, err = m.svc.UpsertService(loadBalancerIP, remoteBackends, lb.SVCTypeLoadBalancer, lb.SVCTrafficPolicyLocal, false, 0, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, 0)

	// Upsert svc1 of type ClusterIP with only remote backends
	new, _, err = m.svc.UpsertService(clusterIP, remoteBackends, lb.SVCTypeClusterIP, lb.SVCTrafficPolicyLocal, false, 0, 32001, "svc1", "ns1")
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, 0)

	// Delete svc1 of type LoadBalancer
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Delete svc1 of type ClusterIP
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)
}

func (m *ManagerTestSuite) TestGetServiceNameByAddr(c *C) {
	fe := frontend1.DeepCopy()
	be := make([]lb.Backend, 0, len(backends1))
	for _, backend := range backends1 {
		be = append(be, *backend.DeepCopy())
	}
	name := "svc1"
	namespace := "ns1"
	hcport := uint16(3)
	created, id1, err := m.svc.UpsertService(*fe, be, lb.SVCTypeNodePort, lb.SVCTrafficPolicyCluster, false, 0, hcport, name, namespace)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	fe.ID = id1
	gotNamespace, gotName, ok := m.svc.GetServiceNameByAddr(frontend1.L3n4Addr)
	c.Assert(gotNamespace, Equals, namespace)
	c.Assert(gotName, Equals, name)
	c.Assert(ok, Equals, true)
	_, _, ok = m.svc.GetServiceNameByAddr(frontend2.L3n4Addr)
	c.Assert(ok, Equals, false)
}
