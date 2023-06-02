// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"errors"
	"net"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/stretchr/testify/assert"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathOpt "github.com/cilium/cilium/pkg/datapath/option"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
)

func TestLocalRedirectServiceExistsError(t *testing.T) {
	addrCluster1 := cmtypes.MustParseAddrCluster("1.2.3.4")
	addrCluster2 := cmtypes.MustParseAddrCluster("5.6.7.8")
	name1 := "my-svc-1"
	name2 := "my-svc-2"

	// same frontend, same name
	err1 := NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 := NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	assert.Equal(t, err1, err2)
	assert.True(t, errors.Is(err1, err2))

	// same frontend, different name
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name2},
	)
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// different frontend, same name
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster2, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// different frontend, different name
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster2, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name2},
	)
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// different error types
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = errors.New("another error")
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// different error types
	err1 = errors.New("another error")
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// an error is nil
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = nil
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// an error is nil
	err1 = nil
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))

	// We don't match against strings. It must be the sentinel value.
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = errors.New(err1.Error())
	assert.NotEqual(t, err1, err2)
	assert.False(t, errors.Is(err1, err2))
}

type ManagerTestSuite struct {
	svc                         *Service
	lbmap                       *mockmaps.LBMockMap // for accessing public fields
	svcHealth                   *healthserver.MockHealthHTTPServerFactory
	prevOptionSessionAffinity   bool
	prevOptionLBSourceRanges    bool
	prevOptionNPAlgo            string
	prevOptionDPMode            string
	prevOptionExternalClusterIP bool
	ipv6                        bool
}

var _ = Suite(&ManagerTestSuite{})

func (m *ManagerTestSuite) SetUpTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()

	m.lbmap = mockmaps.NewLBMockMap()
	m.svc = NewService(nil, nil, m.lbmap)

	m.svcHealth = healthserver.NewMockHealthHTTPServerFactory()
	m.svc.healthServer = healthserver.WithHealthHTTPServerFactory(m.svcHealth)

	m.prevOptionSessionAffinity = option.Config.EnableSessionAffinity
	option.Config.EnableSessionAffinity = true

	m.prevOptionLBSourceRanges = option.Config.EnableSVCSourceRangeCheck
	option.Config.EnableSVCSourceRangeCheck = true

	m.prevOptionNPAlgo = option.Config.NodePortAlg
	m.prevOptionDPMode = option.Config.DatapathMode
	m.prevOptionExternalClusterIP = option.Config.ExternalClusterIP

	m.ipv6 = option.Config.EnableIPv6
}

func (m *ManagerTestSuite) TearDownTest(c *C) {
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()
	option.Config.EnableSessionAffinity = m.prevOptionSessionAffinity
	option.Config.EnableSVCSourceRangeCheck = m.prevOptionLBSourceRanges
	option.Config.NodePortAlg = m.prevOptionNPAlgo
	option.Config.DatapathMode = m.prevOptionDPMode
	option.Config.ExternalClusterIP = m.prevOptionExternalClusterIP
	option.Config.EnableIPv6 = m.ipv6
}

var (
	surrogateFE = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 80, lb.ScopeExternal, 0)
	frontend1   = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)
	frontend2   = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, lb.ScopeExternal, 0)
	frontend3   = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("f00d::1"), 80, lb.ScopeExternal, 0)
	backends1   = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080),
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080),
	}
	backends2 = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080),
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080),
	}
	backends3 = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("fd00::2"), 8080),
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("fd00::3"), 8080),
	}
	backends4 = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.4"), 8080),
	}
	backends5 = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.5"), 8080),
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.6"), 8080),
	}
	backends6 = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.7"), 8080),
	}
)

func (m *ManagerTestSuite) TestUpsertAndDeleteService(c *C) {
	m.testUpsertAndDeleteService(c)
}

func (m *ManagerTestSuite) TestUpsertAndDeleteServiceWithoutIPv6(c *C) {
	option.Config.EnableIPv6 = false
	m.testUpsertAndDeleteService(c)
}

func (m *ManagerTestSuite) TestUpsertAndDeleteServiceNat46(c *C) {
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
	option.Config.NodePortNat46X64 = true
	m.testUpsertAndDeleteService46(c)
}

func (m *ManagerTestSuite) TestUpsertAndDeleteServiceNat64(c *C) {
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
	option.Config.NodePortNat46X64 = true
	m.testUpsertAndDeleteService64(c)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService46(c *C) {
	// Should create a new v4 service with two v6 backends
	p := &lb.SVC{
		Frontend:         frontend1,
		Backends:         backends3,
		Type:             lb.SVCTypeNodePort,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	created, id1, err := m.svc.UpsertService(p)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(m.svc.svcByID[id1].svcNatPolicy, Equals, lb.SVCNatPolicyNat46)

	// Should delete both backends of service
	p.Backends = nil
	created, id2, err := m.svc.UpsertService(p)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id2, Equals, id1)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id2].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id2].svcName.Namespace, Equals, "ns1")
	c.Assert(m.svc.svcByID[id2].svcNatPolicy, Equals, lb.SVCNatPolicyNone)

	// Should delete the remaining service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService64(c *C) {
	// Should create a new v6 service with two v4 backends
	p := &lb.SVC{
		Frontend:         frontend3,
		Backends:         backends1,
		Type:             lb.SVCTypeNodePort,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	created, id1, err := m.svc.UpsertService(p)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(m.svc.svcByID[id1].svcNatPolicy, Equals, lb.SVCNatPolicyNat64)

	// Should delete both backends of service
	p.Backends = nil
	created, id2, err := m.svc.UpsertService(p)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id2, Equals, id1)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id2].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id2].svcName.Namespace, Equals, "ns1")
	c.Assert(m.svc.svcByID[id2].svcNatPolicy, Equals, lb.SVCNatPolicyNone)

	// Should delete the remaining service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService(c *C) {
	// Should create a new service with two backends and session affinity
	p := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	created, id1, err := m.svc.UpsertService(p)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
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
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
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
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
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
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      lb.ServiceName{Name: "svc2", Namespace: "ns2"},
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
	}
	created, id2, err := m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id2].svcName.Name, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcName.Namespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 2)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id2)]), Equals, 2)

	// Should add IPv6 service only if IPv6 is enabled
	c.Assert(err, IsNil)
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	c.Assert(err, IsNil)
	p3 := &lb.SVC{
		Frontend:                  frontend3,
		Backends:                  backends3,
		Type:                      lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      lb.ServiceName{Name: "svc3", Namespace: "ns3"},
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1},
	}
	created, id3, err := m.svc.UpsertService(p3)
	if option.Config.EnableIPv6 {
		c.Assert(err, IsNil)
		c.Assert(created, Equals, true)
		c.Assert(id3, Equals, lb.ID(3))
		c.Assert(len(m.lbmap.ServiceByID[uint16(id3)].Backends), Equals, 2)
		c.Assert(len(m.lbmap.BackendByID), Equals, 4)
		c.Assert(m.svc.svcByID[id3].svcName.Name, Equals, "svc3")
		c.Assert(m.svc.svcByID[id3].svcName.Namespace, Equals, "ns3")
		c.Assert(len(m.lbmap.AffinityMatch[uint16(id3)]), Equals, 2)
		c.Assert(len(m.lbmap.SourceRanges[uint16(id3)]), Equals, 1)

		// Should remove the IPv6 service
		found, err := m.svc.DeleteServiceByID(lb.ServiceID(id3))
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
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
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
	c.Assert(m.svc.svcByID[id2].svcName.Name, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcName.Namespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id2)]), Equals, 0)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id2)]), Equals, 1)

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)

	// Should ignore the source range if it does not match FE's ip family
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	c.Assert(err, IsNil)
	cidr2, err = cidr.ParseCIDR("192.168.1.0/24")
	c.Assert(err, IsNil)

	p4 := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      lb.ServiceName{Name: "svc3", Namespace: "ns3"},
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
	}
	created, id4, err := m.svc.UpsertService(p4)
	c.Assert(created, Equals, true)
	c.Assert(err, IsNil)
	c.Assert(len(m.lbmap.SourceRanges[uint16(id4)]), Equals, 1)
}

func (m *ManagerTestSuite) TestRestoreServices(c *C) {
	p1 := &lb.SVC{
		Frontend:         frontend1,
		Backends:         backends1,
		Type:             lb.SVCTypeNodePort,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
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
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
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
	m.svc = NewService(nil, nil, lbmap)

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
}

func (m *ManagerTestSuite) TestSyncWithK8sFinished(c *C) {
	p1 := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	p2 := &lb.SVC{
		Frontend:         frontend2,
		Backends:         backends2,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc2", Namespace: "ns2"},
	}
	_, _, err = m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 2)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.svc = NewService(nil, nil, lbmap)
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)

	// Imitate a situation where svc1 was deleted while we were down.
	// In real life, the following upsert is called by k8s_watcher during
	// the sync period of the cilium-agent's k8s service cache which happens
	// during the initialization of cilium-agent. P2 svc updated affinity is synced.
	p2.SessionAffinity = true
	p2.SessionAffinityTimeoutSec = 100
	_, id2, err := m.svc.UpsertService(p2)
	c.Assert(err, IsNil)

	// Add non-existing affinity matches
	lbmap.AddAffinityMatch(20, 300)
	lbmap.AddAffinityMatch(20, 301)
	lbmap.AddAffinityMatch(uint16(id1), 302)
	lbmap.AddAffinityMatch(uint16(id2), 305)

	// cilium-agent finished the initialization, and thus SyncWithK8sFinished
	// is called
	err = m.svc.SyncWithK8sFinished()
	c.Assert(err, IsNil)

	// svc1 should be removed from cilium while svc2 is synced
	c.Assert(len(m.svc.svcByID), Equals, 1)
	_, found := m.svc.svcByID[id2]
	c.Assert(found, Equals, true)
	_, found = m.svc.svcByID[id1]
	c.Assert(found, Equals, false)
	c.Assert(m.svc.svcByID[id2].svcName.Name, Equals, "svc2")
	c.Assert(m.svc.svcByID[id2].svcName.Namespace, Equals, "ns2")
	c.Assert(len(m.lbmap.AffinityMatch), Equals, 1)
	// Check that the non-existing affinity matches were removed
	matches, _ := lbmap.DumpAffinityMatches()
	c.Assert(len(matches), Equals, 1) // id2 svc has updated session affinity
	c.Assert(len(matches[uint16(id2)]), Equals, 2)
	for _, b := range lbmap.ServiceByID[uint16(id2)].Backends {
		c.Assert(m.lbmap.AffinityMatch[uint16(id2)][b.ID], Equals, struct{}{})
	}
}

func (m *ManagerTestSuite) TestHealthCheckNodePort(c *C) {
	// Create two frontends, one for LoadBalaner and one for ClusterIP.
	// This is used to emulate how we get K8s services from the K8s watcher,
	// i.e. one service per frontend (even if it is logically the same service)
	loadBalancerIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)
	clusterIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("10.20.30.40"), 80, lb.ScopeExternal, 0)

	// Create two node-local backends
	localBackend1 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080)
	localBackend2 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080)
	localTerminatingBackend3 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()
	localBackend2.NodeName = nodeTypes.GetName()
	localTerminatingBackend3.NodeName = nodeTypes.GetName()
	localActiveBackends := []*lb.Backend{localBackend1, localBackend2}

	// Create three remote backends
	remoteBackend1 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080)
	remoteBackend2 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.4"), 8080)
	remoteBackend3 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.5"), 8080)
	remoteBackend1.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend2.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend3.NodeName = "not-" + nodeTypes.GetName()
	remoteBackends := []*lb.Backend{remoteBackend1, remoteBackend2, remoteBackend3}

	allBackends := []*lb.Backend{localBackend1, localBackend2, localTerminatingBackend3, remoteBackend1, remoteBackend2, remoteBackend3}

	// Insert svc1 as type LoadBalancer with some local backends
	p1 := &lb.SVC{
		Frontend:            loadBalancerIP,
		Backends:            allBackends,
		Type:                lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:    lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: 32001,
		Name:                lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")

	p1.Backends[2].State = lb.BackendStateTerminating
	_, _, _ = m.svc.UpsertService(p1)
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localActiveBackends))

	// Insert the the ClusterIP frontend of svc1
	p2 := &lb.SVC{
		Frontend:            clusterIP,
		Backends:            allBackends,
		Type:                lb.SVCTypeClusterIP,
		ExtTrafficPolicy:    lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: 32001,
		Name:                lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	_, id2, err := m.svc.UpsertService(p2)
	c.Assert(err, IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localActiveBackends))

	// Update the HealthCheckNodePort for svc1
	p1.HealthCheckNodePort = 32000
	new, _, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32000).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32000).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32000).LocalEndpoints, Equals, len(localActiveBackends))
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Update the externalTrafficPolicy for svc1
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	p1.HealthCheckNodePort = 0
	new, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32000), IsNil)
	c.Assert(m.svcHealth.ServiceByPort(32001), IsNil)

	// Restore the original version of svc1
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.HealthCheckNodePort = 32001
	new, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(new, Equals, false)
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Name, Equals, "svc1")
	c.Assert(m.svcHealth.ServiceByPort(32001).Service.Namespace, Equals, "ns1")
	c.Assert(m.svcHealth.ServiceByPort(32001).LocalEndpoints, Equals, len(localActiveBackends))

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
		ExtTrafficPolicy:    lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: 32000,
	}
	_, id1, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)

	// Unset HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 0
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	_, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)

	// Set HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 32000
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	_, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)

	// Delete service with active HealthCheckNodePort
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
}

func (m *ManagerTestSuite) TestGetServiceNameByAddr(c *C) {
	fe := frontend1.DeepCopy()
	be := make([]*lb.Backend, 0, len(backends1))
	for _, backend := range backends1 {
		be = append(be, backend.DeepCopy())
	}
	name := "svc1"
	namespace := "ns1"
	hcport := uint16(3)
	p := &lb.SVC{
		Frontend:            *fe,
		Backends:            be,
		Type:                lb.SVCTypeNodePort,
		ExtTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: hcport,
		Name:                lb.ServiceName{Name: name, Namespace: namespace},
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
	localBackends := []*lb.Backend{localBackend}
	// Create two remote backends.
	remoteBackends := make([]*lb.Backend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.Backend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	// Create a service entry of type Local Redirect.
	p1 := &lb.SVC{
		Frontend:         frontend1,
		Backends:         allBackends,
		Type:             lb.SVCTypeLocalRedirect,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	// Insert the service entry of type Local Redirect.
	created, id, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id, Not(Equals), lb.ID(0))

	svc, ok := m.svc.svcByID[id]
	c.Assert(ok, Equals, true)
	c.Assert(svc.svcName.Namespace, Equals, "ns1")
	c.Assert(svc.svcName.Name, Equals, "svc1")
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
	localBackends := []*lb.Backend{localBackend}
	// Create two remote backends.
	remoteBackends := make([]*lb.Backend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.Backend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.SVC{
		Frontend:         frontend1,
		Backends:         allBackends,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
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
		Frontend:         frontend2,
		Backends:         allBackends,
		Type:             lb.SVCTypeNodePort,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc2", Namespace: "ns1"},
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

// Tests whether upsert service handles terminating backends, whereby terminating
// backends are not added to the service map, but are added to the backends and
// affinity maps.
func (m *ManagerTestSuite) TestUpsertServiceWithTerminatingBackends(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends4, backends1...)
	p := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	// Reset state as backends are pointers to lb.Backend
	p.Backends[0].State = lb.BackendStateActive
	p.Backends[1].State = lb.BackendStateActive
	p.Backends[2].State = lb.BackendStateActive

	created, id1, err := m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, len(backends))

	p.Backends[0].State = lb.BackendStateTerminating

	_, _, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, len(backends1))
	// Sorted active backends by ID first followed by non-active
	c.Assert(m.lbmap.ServiceByID[uint16(id1)].Backends[0].ID, Equals, lb.BackendID(2))
	c.Assert(m.lbmap.ServiceByID[uint16(id1)].Backends[1].ID, Equals, lb.BackendID(3))
	c.Assert(m.lbmap.ServiceByID[uint16(id1)].Backends[2].ID, Equals, lb.BackendID(1))
	c.Assert(len(m.lbmap.BackendByID), Equals, 3)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 3)
	for bID := range m.lbmap.BackendByID {
		c.Assert(m.lbmap.AffinityMatch[uint16(id1)][bID], Equals, struct{}{})
	}
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, len(backends1))

	// Delete terminating backends.
	p.Backends = []*lb.Backend{}

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 0)
}

// TestUpsertServiceWithOnlyTerminatingBackends tests that a terminating backend is still
// used if there are not active backends.
func (m *ManagerTestSuite) TestUpsertServiceWithOnlyTerminatingBackends(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := backends1 // There are 2 backends
	p := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	// Reset state as backends are pointers to lb.Backend
	p.Backends[0].State = lb.BackendStateActive
	p.Backends[1].State = lb.BackendStateActive

	created, id1, err := m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")

	// The terminating backend should not be considered
	p.Backends[1].State = lb.BackendStateTerminating

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, 1)

	// Delete terminating backends.
	p.Backends = p.Backends[:1]

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 1)
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 1)

	// The terminating backend should be considered since there are no more active
	p.Backends[0].State = lb.BackendStateTerminating

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 1)
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, 0)

	// Delete terminating backends.
	p.Backends = []*lb.Backend{}

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(len(m.lbmap.AffinityMatch[uint16(id1)]), Equals, 0)
}

// Tests whether upsert service provisions the Maglev LUT for ClusterIP,
// if ExternalClusterIP is true
func (m *ManagerTestSuite) TestUpsertServiceWithExternalClusterIP(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	option.Config.ExternalClusterIP = true
	p := &lb.SVC{
		Frontend:         frontend1,
		Backends:         backends1,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	created, id1, err := m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, len(backends1))
}

// Tests whether upsert service doesn't provision the Maglev LUT for ClusterIP,
// if ExternalClusterIP is false
func (m *ManagerTestSuite) TestUpsertServiceWithOutExternalClusterIP(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	p := &lb.SVC{
		Frontend:         frontend1,
		Backends:         backends1,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	created, id1, err := m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName.Name, Equals, "svc1")
	c.Assert(m.svc.svcByID[id1].svcName.Namespace, Equals, "ns1")
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, 0)
}

// Tests terminating backend entries are not removed after service restore.
func (m *ManagerTestSuite) TestRestoreServiceWithTerminatingBackends(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends4, backends1...)
	p := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	// Reset state as backends are pointers to lb.Backend
	p.Backends[0].State = lb.BackendStateActive
	p.Backends[1].State = lb.BackendStateActive
	p.Backends[2].State = lb.BackendStateActive

	created, id1, err := m.svc.UpsertService(p)

	c.Log(m.lbmap.ServiceByID[0])
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, len(backends))

	p.Backends[0].State = lb.BackendStateTerminating

	_, _, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)

	// Simulate agent restart.
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.svc = NewService(nil, nil, lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)

	// Backends including terminating ones have been restored
	c.Assert(len(m.svc.backendByHash), Equals, 3)
	for _, b := range backends1 {
		_, found := m.svc.backendByHash[b.Hash()]
		c.Assert(found, Equals, true)
	}

	// Affinity matches including terminating ones were restored
	matches, _ := m.lbmap.DumpAffinityMatches()
	c.Assert(len(matches), Equals, 1)
	c.Assert(len(matches[uint16(id1)]), Equals, 3)
	for _, b := range m.lbmap.ServiceByID[uint16(id1)].Backends {
		c.Assert(m.lbmap.AffinityMatch[uint16(id1)][b.ID], Equals, struct{}{})
	}
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, len(backends1))
}

// l7 load balancer service should be able to override any service type
// (Cluster IP, NodePort, etc.) with same frontend.
func (m *ManagerTestSuite) TestL7LoadBalancerServiceOverride(c *C) {
	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	// Create two remote backends.
	remoteBackends := make([]*lb.Backend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.Backend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.SVC{
		Frontend:         frontend1,
		Backends:         allBackends,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"},
	}

	// Insert the service entry of type ClusterIP.
	created, id, err := m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id, Not(Equals), lb.ID(0))

	svc, ok := m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)
	c.Assert(svc.l7LBProxyPort, Equals, uint16(0))

	// registering without redirecting
	echoOtherNode := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	resource1 := lb.ServiceName{Name: "testOwner1", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceBackendSync(echoOtherNode, resource1, nil)
	c.Assert(err, IsNil)

	svc, ok = m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)
	c.Assert(svc.l7LBProxyPort, Equals, uint16(0))

	// registering with redirection stores the proxy port
	resource2 := lb.ServiceName{Name: "testOwner2", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBService(echoOtherNode, resource2, nil, uint16(9090))
	c.Assert(err, IsNil)

	svc, ok = m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)
	c.Assert(svc.l7LBProxyPort, Equals, uint16(9090))

	// Remove with an unregistered owner name does not remove
	resource3 := lb.ServiceName{Name: "testOwner3", Namespace: "cilium-test"}
	err = m.svc.RemoveL7LBService(echoOtherNode, resource3)
	c.Assert(err, IsNil)

	svc, ok = m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)
	c.Assert(svc.l7LBProxyPort, Equals, uint16(9090))

	// Removing registration without redirection does not remove the proxy port
	err = m.svc.RemoveL7LBService(echoOtherNode, resource1)
	c.Assert(err, IsNil)

	svc, ok = m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)
	c.Assert(svc.l7LBProxyPort, Equals, uint16(9090))

	// removing the registration with redirection removes the proxy port
	err = m.svc.RemoveL7LBService(echoOtherNode, resource2)
	c.Assert(err, IsNil)

	svc, ok = m.svc.svcByID[id]
	c.Assert(len(svc.backends), Equals, len(allBackends))
	c.Assert(ok, Equals, true)
	c.Assert(svc.l7LBProxyPort, Equals, uint16(0))
}

// Tests that services with the given backends are updated with the new backend
// state.
func (m *ManagerTestSuite) TestUpdateBackendsState(c *C) {
	backends := backends1
	p1 := &lb.SVC{
		Frontend: frontend1,
		Backends: backends,
		Type:     lb.SVCTypeClusterIP,
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	p2 := &lb.SVC{
		Frontend: frontend2,
		Backends: backends,
		Type:     lb.SVCTypeClusterIP,
		Name:     lb.ServiceName{Name: "svc2", Namespace: "ns1"},
	}

	_, id1, err1 := m.svc.UpsertService(p1)
	_, id2, err2 := m.svc.UpsertService(p2)

	c.Assert(err1, IsNil)
	c.Assert(err2, IsNil)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(id2, Equals, lb.ID(2))
	c.Assert(m.svc.svcByID[id1].backends[0].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id1].backends[1].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id2].backends[0].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id2].backends[1].State, Equals, lb.BackendStateActive)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id2)], Equals, len(backends))
	c.Assert(len(m.lbmap.BackendByID), Equals, len(backends))
	// Backend states are persisted in the map.
	c.Assert(m.lbmap.BackendByID[1].State, Equals, lb.BackendStateActive)
	c.Assert(m.lbmap.BackendByID[2].State, Equals, lb.BackendStateActive)

	// Update the state for one of the backends.
	updated := []*lb.Backend{backends[0]}
	updated[0].State = lb.BackendStateQuarantined

	err := m.svc.UpdateBackendsState(updated)

	c.Assert(err, IsNil)
	// Both the services are updated with the update backend state.
	c.Assert(m.svc.svcByID[id1].backends[0].State, Equals, lb.BackendStateQuarantined)
	c.Assert(m.svc.svcByID[id1].backends[1].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id2].backends[0].State, Equals, lb.BackendStateQuarantined)
	c.Assert(m.svc.svcByID[id2].backends[1].State, Equals, lb.BackendStateActive)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, 1)
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id2)], Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, len(backends))
	// Updated backend states are persisted in the map.
	c.Assert(m.lbmap.BackendByID[1].State, Equals, lb.BackendStateQuarantined)
	c.Assert(m.lbmap.BackendByID[2].State, Equals, lb.BackendStateActive)

	// Update the state again.
	updated = []*lb.Backend{backends[0]}
	updated[0].State = lb.BackendStateActive

	err = m.svc.UpdateBackendsState(updated)

	c.Assert(err, IsNil)
	// Both the services are updated with the update backend state.
	c.Assert(m.svc.svcByID[id1].backends[0].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id1].backends[1].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id2].backends[0].State, Equals, lb.BackendStateActive)
	c.Assert(m.svc.svcByID[id2].backends[1].State, Equals, lb.BackendStateActive)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id2)].Backends), Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id1)], Equals, len(backends))
	c.Assert(m.lbmap.SvcActiveBackendsCount[uint16(id2)], Equals, len(backends))
	c.Assert(len(m.lbmap.BackendByID), Equals, len(backends))
	// Updated backend states are persisted in the map.
	c.Assert(m.lbmap.BackendByID[1].State, Equals, lb.BackendStateActive)
	c.Assert(m.lbmap.BackendByID[2].State, Equals, lb.BackendStateActive)
}

// Tests that backend states are restored.
func (m *ManagerTestSuite) TestRestoreServiceWithBackendStates(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends1, backends4...)
	p1 := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
	}
	created, id1, err := m.svc.UpsertService(p1)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(len(m.svc.backendByHash), Equals, len(backends))

	// Update backend states.
	var updates []*lb.Backend
	backends[0].State = lb.BackendStateQuarantined
	backends[1].State = lb.BackendStateMaintenance
	updates = append(updates, backends[0], backends[1])
	err = m.svc.UpdateBackendsState(updates)

	c.Assert(err, IsNil)

	// Simulate agent restart.
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.svc = NewService(nil, nil, lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	c.Assert(err, IsNil)

	// Check that backends along with their states have been restored
	c.Assert(len(m.svc.backendByHash), Equals, len(backends))
	statesMatched := 0
	for _, b := range backends {
		be, found := m.svc.backendByHash[b.Hash()]
		c.Assert(found, Equals, true)
		if be.String() == b.String() {
			c.Assert(be.State, Equals, b.State, Commentf("before %+v restored %+v", b, be))
			statesMatched++
		}
	}
	c.Assert(statesMatched, Equals, len(backends))
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, 1)
}

func (m *ManagerTestSuite) TestUpsertServiceWithZeroWeightBackends(c *C) {
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends1, backends4...)
	backends[0].State = lb.BackendStateActive
	backends[1].Weight = 0
	backends[1].State = lb.BackendStateMaintenance
	backends[2].Weight = 1
	backends[2].State = lb.BackendStateActive

	p := &lb.SVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name: lb.ServiceName{
			Name:      "svc1",
			Namespace: "ns1",
		},
	}

	created, id1, err := m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 3)
	c.Assert(len(m.lbmap.BackendByID), Equals, 3)
	hash := backends[1].L3n4Addr.Hash()
	c.Assert(m.svc.backendByHash[hash].State, Equals, lb.BackendStateMaintenance)
	hash = backends[2].L3n4Addr.Hash()
	c.Assert(m.svc.backendByHash[hash].State, Equals, lb.BackendStateActive)
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, 2)

	// Update existing backend weight
	p.Backends[2].Weight = 0
	p.Backends[2].State = lb.BackendStateMaintenance

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 3)
	c.Assert(len(m.lbmap.BackendByID), Equals, 3)
	c.Assert(m.svc.backendByHash[hash].State, Equals, lb.BackendStateMaintenance)
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, 1)

	// Delete backends with weight 0
	p.Backends = backends[:1]

	created, id1, err = m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, false)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 1)
	c.Assert(len(m.lbmap.BackendByID), Equals, 1)
	c.Assert(m.lbmap.DummyMaglevTable[uint16(id1)], Equals, 1)
}

func Test_filterServiceBackends(t *testing.T) {
	t.Run("filter by port number", func(t *testing.T) {
		svc := &svcInfo{
			frontend: lb.L3n4AddrID{
				L3n4Addr: lb.L3n4Addr{
					L4Addr: lb.L4Addr{
						Port: 8080,
					},
				},
			},
			backends: []*lb.Backend{
				{
					FEPortName: "http",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 3000,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends[anyPort], 1)
		})
		t.Run("only http port", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"8080"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["8080"], 1)
		})
		t.Run("no match", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"8000"})
			assert.Len(t, backends, 0)
		})
	})

	t.Run("filter by port named", func(t *testing.T) {
		svc := &svcInfo{
			frontend: lb.L3n4AddrID{
				L3n4Addr: lb.L3n4Addr{
					L4Addr: lb.L4Addr{
						Port: 8000,
					},
				},
			},
			backends: []*lb.Backend{
				{
					FEPortName: "http",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8080,
						},
					},
				},
				{
					FEPortName: "https",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8443,
						},
					},
				},
				{
					FEPortName: "metrics",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8081,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends[anyPort], 3)
		})
		t.Run("only http named port", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["http"], 1)
		})
		t.Run("multiple named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http", "metrics"})
			assert.Len(t, backends, 2)

			assert.Len(t, backends["http"], 1)
			assert.Equal(t, (int)(backends["http"][0].Port), 8080)

			assert.Len(t, backends["metrics"], 1)
			assert.Equal(t, (int)(backends["metrics"][0].Port), 8081)
		})
	})

	t.Run("filter with preferred backend", func(t *testing.T) {
		svc := &svcInfo{
			frontend: lb.L3n4AddrID{
				L3n4Addr: lb.L3n4Addr{
					L4Addr: lb.L4Addr{
						Port: 8000,
					},
				},
			},
			backends: []*lb.Backend{
				{
					FEPortName: "http",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8080,
						},
					},
					Preferred: lb.Preferred(true),
				},
				{
					FEPortName: "http",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8081,
						},
					},
				},
				{
					FEPortName: "https",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 443,
						},
					},
				},
				{
					FEPortName: "80",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8080,
						},
					},
					Preferred: lb.Preferred(true),
				},
				{
					FEPortName: "80",
					L3n4Addr: lb.L3n4Addr{
						L4Addr: lb.L4Addr{
							Port: 8081,
						},
					},
				},
			},
		}

		t.Run("all ports are allowed", func(t *testing.T) {
			backends := filterServiceBackends(svc, nil)
			assert.Len(t, backends, 1)
			assert.Len(t, backends[anyPort], 2)
		})

		t.Run("only named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http"})
			assert.Len(t, backends, 1)
			assert.Len(t, backends["http"], 1)
		})
		t.Run("multiple named ports", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"http", "https"})
			assert.Len(t, backends, 1)

			assert.Len(t, backends["http"], 1)
			assert.Equal(t, (int)(backends["http"][0].Port), 8080)
		})

		t.Run("only port number", func(t *testing.T) {
			backends := filterServiceBackends(svc, []string{"80"})
			assert.Len(t, backends, 1)

			assert.Len(t, backends["80"], 1)
			assert.Equal(t, (int)(backends["80"][0].Port), 8080)
		})
	})
}

type mockNodeAddressingFamily struct {
	ips []net.IP
}

func (n *mockNodeAddressingFamily) Router() net.IP                    { panic("Not implemented") }
func (n *mockNodeAddressingFamily) PrimaryExternal() net.IP           { panic("Not implemented") }
func (n *mockNodeAddressingFamily) AllocationCIDR() *cidr.CIDR        { panic("Not implemented") }
func (n *mockNodeAddressingFamily) LocalAddresses() ([]net.IP, error) { panic("Not implemented") }
func (n *mockNodeAddressingFamily) LoadBalancerNodeAddresses() []net.IP {
	return n.ips
}

type mockNodeAddressing struct {
	ip4 datapathTypes.NodeAddressingFamily
	ip6 datapathTypes.NodeAddressingFamily
}

func (na *mockNodeAddressing) IPv4() datapathTypes.NodeAddressingFamily {
	return na.ip4
}
func (na *mockNodeAddressing) IPv6() datapathTypes.NodeAddressingFamily {
	return na.ip6
}

// Test the service sync on device/addressing change
func (m *ManagerTestSuite) TestSyncServices(c *C) {
	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
	option.Config.NodePortNat46X64 = true

	surrogate := &lb.SVC{
		Frontend: surrogateFE,
		Backends: backends1,
		Type:     lb.SVCTypeNodePort,
	}
	_, surrID, err := m.svc.UpsertService(surrogate)
	c.Assert(err, IsNil)
	p1 := &lb.SVC{
		Frontend: frontend1,
		Backends: backends1,
		Type:     lb.SVCTypeNodePort,
	}
	_, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)

	// With no addresses all frontends (except surrogates) should be removed.
	nodeAddrs := &mockNodeAddressing{
		ip4: &mockNodeAddressingFamily{[]net.IP{}},
		ip6: &mockNodeAddressingFamily{[]net.IP{}},
	}
	m.svc.SyncServicesOnDeviceChange(nodeAddrs)
	c.Assert(len(m.svc.svcByID), Equals, 1)
	_, ok := m.svc.svcByID[surrID]
	c.Assert(ok, Equals, true)

	// With a new frontend addresses services should be created.
	_, _, err = m.svc.UpsertService(p1)
	c.Assert(err, IsNil)
	c.Assert(len(m.svc.svcByID), Equals, 2)

	nodeAddrs = &mockNodeAddressing{
		ip4: &mockNodeAddressingFamily{[]net.IP{frontend1.AddrCluster.AsNetIP(), frontend2.AddrCluster.AsNetIP()}},
		ip6: &mockNodeAddressingFamily{[]net.IP{frontend3.AddrCluster.AsNetIP()}},
	}
	m.svc.SyncServicesOnDeviceChange(nodeAddrs)
	c.Assert(len(m.svc.svcByID), Equals, 4)

	_, _, found := m.svc.GetServiceNameByAddr(frontend1.L3n4Addr)
	c.Assert(found, Equals, true)
	_, _, found = m.svc.GetServiceNameByAddr(frontend2.L3n4Addr)
	c.Assert(found, Equals, true)
	_, _, found = m.svc.GetServiceNameByAddr(frontend3.L3n4Addr)
	c.Assert(found, Equals, true)

}

func (m *ManagerTestSuite) TestTrafficPolicy(c *C) {
	internalIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeInternal, 0)
	externalIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)

	localBackend1 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080)
	localBackend2 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()
	localBackend2.NodeName = nodeTypes.GetName()
	localBackends := []*lb.Backend{localBackend1, localBackend2}

	remoteBackend1 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080)
	remoteBackend2 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.4"), 8080)
	remoteBackend3 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.5"), 8080)
	remoteBackend1.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend2.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend3.NodeName = "not-" + nodeTypes.GetName()
	remoteBackends := []*lb.Backend{remoteBackend1, remoteBackend2, remoteBackend3}

	allBackends := make([]*lb.Backend, 0, len(remoteBackends)+len(remoteBackends))
	allBackends = append(allBackends, localBackends...)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.SVC{
		Frontend:         internalIP,
		Backends:         allBackends,
		Type:             lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyLocal,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	created, id1, err := m.svc.UpsertService(p1)
	c.Assert(created, Equals, true)
	c.Assert(err, IsNil)

	p2 := &lb.SVC{
		Frontend:         externalIP,
		Backends:         allBackends,
		Type:             lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyLocal,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	created, id2, err := m.svc.UpsertService(p2)
	c.Assert(created, Equals, true)
	c.Assert(err, IsNil)

	svcFromLbMap1, ok := m.lbmap.ServiceByID[uint16(id1)]
	c.Assert(ok, Equals, true)
	c.Assert(len(svcFromLbMap1.Backends), Equals, len(localBackends))

	svcFromLbMap2, ok := m.lbmap.ServiceByID[uint16(id2)]
	c.Assert(ok, Equals, true)
	c.Assert(len(svcFromLbMap2.Backends), Equals, len(allBackends))

	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.IntTrafficPolicy = lb.SVCTrafficPolicyCluster
	created, id3, err := m.svc.UpsertService(p1)
	c.Assert(created, Equals, false)
	c.Assert(err, IsNil)
	c.Assert(id3, Equals, id1)

	svcFromLbMap3, ok := m.lbmap.ServiceByID[uint16(id1)]
	c.Assert(ok, Equals, true)
	c.Assert(len(svcFromLbMap3.Backends), Equals, len(allBackends))

	p2.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p2.IntTrafficPolicy = lb.SVCTrafficPolicyCluster
	created, id4, err := m.svc.UpsertService(p2)
	c.Assert(created, Equals, false)
	c.Assert(err, IsNil)
	c.Assert(id4, Equals, id2)

	svcFromLbMap4, ok := m.lbmap.ServiceByID[uint16(id2)]
	c.Assert(ok, Equals, true)
	c.Assert(len(svcFromLbMap4.Backends), Equals, len(localBackends))

	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
}

// Tests whether delete service handles non-active backends.
func (m *ManagerTestSuite) TestDeleteServiceWithTerminatingBackends(c *C) {
	backends := backends5
	backends[0].State = lb.BackendStateTerminating
	p := &lb.SVC{
		Frontend: frontend1,
		Backends: backends,
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	created, id1, err := m.svc.UpsertService(p)

	c.Assert(err, IsNil)
	c.Assert(created, Equals, true)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, 2)
	c.Assert(len(m.lbmap.BackendByID), Equals, 2)
	c.Assert(m.svc.svcByID[id1].svcName, Equals, lb.ServiceName{Name: "svc1", Namespace: "ns1"})

	// Delete service.
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))

	c.Assert(err, IsNil)
	c.Assert(found, Equals, true)
	c.Assert(len(m.lbmap.ServiceByID), Equals, 0)
	c.Assert(len(m.lbmap.BackendByID), Equals, 0)
}

func (m *ManagerTestSuite) TestRestoreServicesWithLeakedBackends(c *C) {
	backends := make([]*lb.Backend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	p1 := &lb.SVC{
		Frontend: frontend1,
		Backends: backends,
		Type:     lb.SVCTypeClusterIP,
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	_, id1, err1 := m.svc.UpsertService(p1)

	c.Assert(err1, IsNil)
	c.Assert(id1, Equals, lb.ID(1))
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	c.Assert(len(m.lbmap.BackendByID), Equals, len(backends))

	// Simulate leaked backends with various leaked scenarios.
	// Backend2 is a duplicate leaked backend with the same L3nL4Addr as backends[0]
	// that's associated with the service.
	// Backend3 is a leaked backend with no associated service.
	// Backend4 and Backend5 are duplicate leaked backends with no associated service.
	backend2 := backends[0].DeepCopy()
	backend2.ID = lb.BackendID(10)
	backend3 := backends2[0].DeepCopy()
	backend4 := backends6[0].DeepCopy()
	backend4.ID = lb.BackendID(20)
	backend5 := backends6[0].DeepCopy()
	backend5.ID = lb.BackendID(30)
	m.svc.lbmap.AddBackend(backend2, backend2.L3n4Addr.IsIPv6())
	m.svc.lbmap.AddBackend(backend3, backend3.L3n4Addr.IsIPv6())
	m.svc.lbmap.AddBackend(backend4, backend4.L3n4Addr.IsIPv6())
	m.svc.lbmap.AddBackend(backend5, backend5.L3n4Addr.IsIPv6())
	c.Assert(len(m.lbmap.BackendByID), Equals, len(backends)+4)
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.svc = NewService(nil, nil, lbmap)

	// Restore services from lbmap
	err := m.svc.RestoreServices()
	c.Assert(err, IsNil)
	c.Assert(len(m.lbmap.ServiceByID[uint16(id1)].Backends), Equals, len(backends))
	// Leaked backends should be deleted.
	c.Assert(len(m.lbmap.BackendByID), Equals, len(backends))
}
