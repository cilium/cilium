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
	"github.com/cilium/cilium/pkg/cidr"
	datapathOpt "github.com/cilium/cilium/pkg/datapath/option"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"

	. "gopkg.in/check.v1"
)

type ManagerTestSuite struct {
	svc                       *Service
	lbmap                     *mockmaps.LBMockMap // for accessing public fields
	svcHealth                 *healthserver.MockHealthHTTPServerFactory
	prevOptionSessionAffinity bool
	prevOptionLBSourceRanges  bool
	prevOptionNPAlgo          string
	prevOptionDPMode          string
	ipv6                      bool
}

var _ = Suite(&ManagerTestSuite{})

func (m *ManagerTestSuite) SetUpTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()

	m.svc = NewService(nil)
	m.svc.lbmap = mockmaps.NewLBMockMap()
	m.lbmap = m.svc.lbmap.(*mockmaps.LBMockMap)

	m.svcHealth = healthserver.NewMockHealthHTTPServerFactory()
	m.svc.healthServer = healthserver.WithHealthHTTPServerFactory(m.svcHealth)

	m.prevOptionSessionAffinity = option.Config.EnableSessionAffinity
	option.Config.EnableSessionAffinity = true

	m.prevOptionLBSourceRanges = option.Config.EnableSVCSourceRangeCheck
	option.Config.EnableSVCSourceRangeCheck = true

	m.prevOptionNPAlgo = option.Config.NodePortAlg
	m.prevOptionDPMode = option.Config.DatapathMode

	m.ipv6 = option.Config.EnableIPv6
}

func (m *ManagerTestSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()
	option.Config.EnableSessionAffinity = m.prevOptionSessionAffinity
	option.Config.EnableSVCSourceRangeCheck = m.prevOptionLBSourceRanges
	option.Config.NodePortAlg = m.prevOptionNPAlgo
	option.Config.DatapathMode = m.prevOptionDPMode
	option.Config.EnableIPv6 = m.ipv6
}

var (
	frontend1 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.1"), 80, lb.ScopeExternal, 0)
	frontend2 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("1.1.1.2"), 80, lb.ScopeExternal, 0)
	frontend3 = *lb.NewL3n4AddrID(lb.UDP, net.ParseIP("1.1.1.2"), 80, lb.ScopeExternal, 0)
	frontend4 = *lb.NewL3n4AddrID(lb.TCP, net.ParseIP("f00d::1"), 80, lb.ScopeExternal, 0)

	backends1 = []lb.Backend{
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.1"), 8080),
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
	}
	backends2 = []lb.Backend{
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.2"), 8080),
		*lb.NewBackend(0, lb.TCP, net.ParseIP("10.0.0.3"), 8080),
	}
	backends3 = []lb.Backend{
		*lb.NewBackend(0, lb.UDP, net.ParseIP("10.0.0.2"), 8080),
		*lb.NewBackend(0, lb.UDP, net.ParseIP("10.0.0.3"), 8080),
	}
	backends4 = []lb.Backend{
		*lb.NewBackend(0, lb.TCP, net.ParseIP("fd00::2"), 8080),
		*lb.NewBackend(0, lb.TCP, net.ParseIP("fd00::3"), 8080),
	}
)

func (m *ManagerTestSuite) TestUpsertAndDeleteService(c *C) {
	m.testUpsertAndDeleteService(c)
}

func (m *ManagerTestSuite) TestUpsertAndDeleteServiceWithoutIPv6(c *C) {
	option.Config.EnableIPv6 = false
	m.testUpsertAndDeleteService(c)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService(c *C) {
	// Should create a new service with two backends and session affinity
	p := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeNodePort,
		TrafficPolicy:             lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      "svc1",
		Namespace:                 "ns1",
	}
	created, id1, err := m.svc.UpsertService(p)
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
	p.SessionAffinity = false
	created, id1, err = m.svc.UpsertService(p)
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
	p.Backends = backends1[0:1]
	p.SessionAffinity = true
	p.SessionAffinityTimeoutSec = 200
	created, id1, err = m.svc.UpsertService(p)
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
	c.Assert(err, IsNil)
	cidr1, err := cidr.ParseCIDR("10.0.0.0/8")
	c.Assert(err, IsNil)
	cidr2, err := cidr.ParseCIDR("192.168.1.0/24")
	c.Assert(err, IsNil)
	p2 := &lb.SVC{
		Frontend:                  frontend2,
		Backends:                  backends1,
		Type:                      lb.SVCTypeLoadBalancer,
		TrafficPolicy:             lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      "svc2",
		Namespace:                 "ns2",
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
	}
	created, id2, err := m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 2)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id2)]), Equals, 2)

	// Should add a similar service ot the others, different only by protocol;
	// the other service(s) should not be corrupted/affected.
	p3 := &lb.SVC{
		Frontend:                  frontend3,
		Backends:                  backends3,
		Type:                      lb.SVCTypeLoadBalancer,
		TrafficPolicy:             lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      "svc3",
		Namespace:                 "ns2",
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
	}
	created, id3, err := m.svc.UpsertService(p3)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id3, Equals, lb.ID(3))
	c.Assert(m.lbmap.ServiceByID[uint16(id3)].Frontend.Protocol, Equals, loadbalancer.UDP)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id3)].Backends), Equals, 2)
	c.Assert(m.lbmap.ServiceByID[uint16(id3)].Backends[0].Protocol, Equals, loadbalancer.UDP)
	c.Assert(m.lbmap.ServiceByID[uint16(id3)].Backends, Not(DeepEquals), m.lbmap.ServiceByID[uint16(id2)].Backends)
	c.Assert(len(m.lbmap.BackendByID), Equals, 4)
	c.Assert(m.svc.svcByID[id3].svcName, Equals, "svc3")
	c.Assert(m.svc.svcByID[id3].svcNamespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id3)]), Equals, 2)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id3)]), Equals, 2)
	// check that the similar service has not been overwritten
	c.Assert(m.lbmap.ServiceByID[uint16(id2)].Frontend.Protocol, Equals, loadbalancer.TCP)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 2)
	c.Assert(m.lbmap.ServiceByID[uint16(id2)].Backends[0].Protocol, Equals, loadbalancer.TCP)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 2)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id2)]), Equals, 2)
	// delete newest added service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id3))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id3)]), Equals, 0)

	// Should add IPv6 service only if IPv6 is enabled
	c.Assert(err, IsNil)
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	c.Assert(err, IsNil)
	p4 := &lb.SVC{
		Frontend:                  frontend4,
		Backends:                  backends4,
		Type:                      lb.SVCTypeLoadBalancer,
		TrafficPolicy:             lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      "svc4",
		Namespace:                 "ns3",
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1},
	}
	created, id4, err := m.svc.UpsertService(p4)
	if option.Config.EnableIPv6 {
		c.Assert(err, IsNil)
		c.Assert(created, Equals, true)
		c.Assert(id4, Equals, lb.ID(4))
		c.Assert(len(m.lbmap.ServiceByID[uint16(id4)].Backends), Equals, 2)
		c.Assert(len(m.lbmap.BackendByID), Equals, 4)
		c.Assert(m.svc.svcByID[id4].svcName, Equals, "svc4")
		c.Assert(m.svc.svcByID[id4].svcNamespace, Equals, "ns3")
		c.Assert(len(m.lbmap.AffinityMatch[uint16(id4)]), Equals, 2)
		c.Assert(len(m.lbmap.SourceRanges[uint16(id4)]), Equals, 1)

		// Should remove the IPv6 service
		found, err := m.svc.DeleteServiceByID(lb.ServiceID(id4))
		c.Assert(err, IsNil)
		c.Assert(found, Equals, true)
	} else {
		c.Assert(err, ErrorMatches, "Unable to upsert service .+ as IPv6 is disabled")
		c.Assert(created, Equals, false)
	}
	c.Assert(len(m.lbmap.ServiceByID), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)

	// Should remove the service and the backend, but keep another service and
	// its backends. Also, should remove the affinity match.
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 0)

	// Should delete both backends of service
	p2.Backends = nil
	p2.LoadBalancerSourceRanges = []*cidr.CIDR{cidr2}
	created, id2, err = m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id2].svcName, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcNamespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 0)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id2)]), Equals, 1)

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) TestRestoreServices(c *C) {
	p1 := &lb.SVC{
		Frontend:      frontend1,
		Backends:      backends1,
		Type:          lb.SVCTypeNodePort,
		TrafficPolicy: lb.SVCTrafficPolicyCluster,
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	cidr1, err := cidr.ParseCIDR("10.0.0.0/8")
	c.Assert(err, IsNil)
	cidr2, err := cidr.ParseCIDR("192.168.1.0/24")
	c.Assert(err, IsNil)
	p2 := &lb.SVC{
		Frontend:                  frontend2,
		Backends:                  backends2,
		Type:                      lb.SVCTypeLoadBalancer,
		TrafficPolicy:             lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 200,
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
	}
	_, id2, err := m.svc.UpsertService(p2)
	c.Assert(err, IsNil)

	// Restart service, but keep the lbmap to restore services from
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	option.Config.DatapathMode = datapathOpt.DatapathModeLBOnly
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
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

	// LoadBalancer source ranges too
	c.Assert(len(m.svc.svcByID[id2].loadBalancerSourceRanges), Equals, 2)
	for _, cidr := range []*cidr.CIDR{cidr1, cidr2} {
		found := false
		for _, c := range m.svc.svcByID[id2].loadBalancerSourceRanges {
			if c.String() == cidr.String() {
				found = true
				break
			}
		}
		c.Assert(found, Equals, true)
	}

	// Maglev lookup table too
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, len(backends1))
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id2)], Equals, len(backends2))

	// Check that the non-existing affinity matches were removed
	matches, _ := lbmap.DumpAffinityMatches()
	c.Assert(len(matches), Equals, 1) // only the id2 svc has session affinity
	c.Assert(len(matches[uint16(id2)]), Equals, 2)
	for _, b := range lbmap.ServiceByID[uint16(id2)].Backends {
		c.Assert(m.lbmap.AffinityMatch[uint16(id1)][uint16(b.ID)], Equals, struct{}{})
	}

}

func (m *ManagerTestSuite) TestSyncWithK8sFinished(c *C) {
	p1 := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeNodePort,
		TrafficPolicy:             lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	p2 := &lb.SVC{
		Frontend:      frontend2,
		Backends:      backends2,
		Type:          lb.SVCTypeClusterIP,
		TrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:          "svc2",
		Namespace:     "ns2",
	}
	_, _, err = m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 2)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.svc = NewService(nil)
	m.svc.lbmap = lbmap
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)

	// Imitate a situation where svc1 was deleted while we were down.
	// In real life, the following upsert is called by k8s_watcher during
	// the sync period of the cilium-agent's k8s service cache which happens
	// during the initialization of cilium-agent.
	_, id2, err := m.svc.UpsertService(p2)
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
	p1 := &lb.SVC{
		Frontend:            loadBalancerIP,
		Backends:            allBackends,
		Type:                lb.SVCTypeLoadBalancer,
		TrafficPolicy:       lb.SVCTrafficPolicyLocal,
		HealthCheckNodePort: 32001,
		Name:                "svc1",
		Namespace:           "ns1",
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localBackends))

	// Insert the the ClusterIP frontend of svc1
	p2 := &lb.SVC{
		Frontend:            clusterIP,
		Backends:            allBackends,
		Type:                lb.SVCTypeClusterIP,
		TrafficPolicy:       lb.SVCTrafficPolicyLocal,
		HealthCheckNodePort: 32001,
		Name:                "svc1",
		Namespace:           "ns1",
	}
	_, id2, err := m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localBackends))

	// Update the HealthCheckNodePort for svc1
	p1.HealthCheckNodePort = 32000
	new, _, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32000).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32000).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32000).LocalEndpoints, Equals, len(localBackends))
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Update the externalTrafficPolicy for svc1
	p1.TrafficPolicy = lb.SVCTrafficPolicyCluster
	p1.HealthCheckNodePort = 0
	new, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32000), IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Restore the original version of svc1
	p1.TrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.HealthCheckNodePort = 32001
	new, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localBackends))

	// Upsert svc1 of type LoadBalancer with only remote backends
	p1.Backends = remoteBackends
	new, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, 0)

	// Upsert svc1 of type ClusterIP with only remote backends
	p2.Backends = remoteBackends
	new, _, err = m.svc.UpsertService(p2)
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

func (m *ManagerTestSuite) TestHealthCheckNodePortDisabled(c *C) {
	// NewService sets healthServer to nil if EnableHealthCheckNodePort is
	// false at start time. We emulate this here by temporarily setting it nil.
	enableHealthCheckNodePort := option.Config.EnableHealthCheckNodePort
	healthServer := m.svc.healthServer
	option.Config.EnableHealthCheckNodePort = false
	m.svc.healthServer = nil
	defer func() {
		option.Config.EnableHealthCheckNodePort = enableHealthCheckNodePort
		m.svc.healthServer = healthServer
	}()

	p1 := &lb.SVC{
		Frontend:            frontend1,
		Backends:            backends1,
		Type:                lb.SVCTypeNodePort,
		TrafficPolicy:       lb.SVCTrafficPolicyLocal,
		HealthCheckNodePort: 32000,
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)

	// Unset HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 0
	p1.TrafficPolicy = lb.SVCTrafficPolicyCluster
	_, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)

	// Set HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 32000
	p1.TrafficPolicy = lb.SVCTrafficPolicyLocal
	_, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)

	// Delete service with active HealthCheckNodePort
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
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
	p := &lb.SVC{
		Frontend:            *fe,
		Backends:            be,
		Type:                lb.SVCTypeNodePort,
		TrafficPolicy:       lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: hcport,
		Name:                name,
		Namespace:           namespace,
	}
	created, id1, err := m.svc.UpsertService(p)
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

func (m *ManagerTestSuite) TestLocalRedirectLocalBackendSelection(c *C) {
	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	localBackends := []lb.Backend{localBackend}
	// Create two remote backends.
	remoteBackends := make([]lb.Backend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]lb.Backend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	// Create a service entry of type Local Redirect.
	p1 := &lb.SVC{
		Frontend:      frontend1,
		Backends:      allBackends,
		Type:          lb.SVCTypeLocalRedirect,
		TrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:          "svc1",
		Namespace:     "ns1",
	}
	// Insert the service entry of type Local Redirect.
	created, id, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id, Not(Equals), lb.ID(0))

	svc, ok := m.svc.svcByID[id]
	c.Assert(ok, Equals, true)
	c.Assert(svc.svcNamespace, Equals, "ns1")
	c.Assert(svc.svcName, Equals, "svc1")
	// Only node-local backends are selected
	c.Assert(len(svc.backends), Equals, len(localBackends))

	svcFromLbMap, ok := m.lbmap.ServiceByID[uint16(id)]
	c.Assert(ok, Equals, true)
	c.Assert(len(svcFromLbMap.Backends), Equals, len(svc.backends))
}

// Local redirect service should be able to override a ClusterIP service with same
// frontend, but reverse should produce an error. Also, it should not override
// any other type besides itself or clusterIP type.
func (m *ManagerTestSuite) TestLocalRedirectServiceOverride(c *C) {
	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	localBackends := []lb.Backend{localBackend}
	// Create two remote backends.
	remoteBackends := make([]lb.Backend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]lb.Backend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.SVC{
		Frontend:      frontend1,
		Backends:      allBackends,
		Type:          lb.SVCTypeClusterIP,
		TrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:          "svc1",
		Namespace:     "ns1",
	}

	// Insert the service entry of type ClusterIP.
	created, id, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id, Not(Equals), lb.ID(0))

	svc, ok := m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)

	// Insert the service entry of type Local Redirect.
	p1.Type = lb.SVCTypeLocalRedirect
	created, id, err = m.svc.UpsertService(p1)

	// Local redirect service should override the ClusterIP service with node-local backends.
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id, Not(Equals), lb.ID(0))
	svc, _ = m.svc.svcByID[id]
	// Only node-local backends are selected.
	c.Assert(len(svc.backends), Equals, len(localBackends))

	// Insert the service entry of type ClusterIP.
	p1.Type = lb.SVCTypeClusterIP
	created, _, err = m.svc.UpsertService(p1)

	c.Assert(err, NotNil)
	c.Assert(created, Equals, false)

	p2 := &lb.SVC{
		Frontend:      frontend2,
		Backends:      allBackends,
		Type:          lb.SVCTypeNodePort,
		TrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:          "svc2",
		Namespace:     "ns1",
	}

	// Insert the service entry of type NodePort.
	created, id, err = m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id, Not(Equals), lb.ID(0))

	svc, ok = m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)

	// Insert the service entry of type Local Redirect.
	p2.Type = lb.SVCTypeLocalRedirect
	created, _, err = m.svc.UpsertService(p2)

	// Local redirect service should not override the NodePort service.
	c.Assert(err, NotNil)
	c.Assert(created, Equals, false)
}
