// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/maps"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathOpt "github.com/cilium/cilium/pkg/datapath/option"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	testsockets "github.com/cilium/cilium/pkg/testutils/sockets"
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

var (
	surrogateFE    = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 80, lb.ScopeExternal, 0)
	surrogateFEv6  = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("::"), 80, lb.ScopeExternal, 0)
	frontend1      = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)
	frontend1_8080 = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 8080, lb.ScopeExternal, 0)
	frontend2      = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, lb.ScopeExternal, 0)
	frontend3      = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("f00d::1"), 80, lb.ScopeExternal, 0)

	backends1, backends2, backends3, backends4, backends5, backends6 []*lb.Backend
)

func setupManagerTestSuite(tb testing.TB) *ManagerTestSuite {
	m := &ManagerTestSuite{}
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()

	m.lbmap = mockmaps.NewLBMockMap()
	m.newServiceMock(m.lbmap)

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
	backends1 = []*lb.Backend{
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

	tb.Cleanup(func() {
		serviceIDAlloc.resetLocalID()
		backendIDAlloc.resetLocalID()
		option.Config.EnableSessionAffinity = m.prevOptionSessionAffinity
		option.Config.EnableSVCSourceRangeCheck = m.prevOptionLBSourceRanges
		option.Config.NodePortAlg = m.prevOptionNPAlgo
		option.Config.DatapathMode = m.prevOptionDPMode
		option.Config.ExternalClusterIP = m.prevOptionExternalClusterIP
		option.Config.EnableIPv6 = m.ipv6
	})

	return m
}

func (m *ManagerTestSuite) newServiceMock(lbmap datapathTypes.LBMap) {
	m.svc = newService(&FakeMonitorAgent{}, lbmap, nil, nil, true)
	m.svc.backendConnectionHandler = testsockets.NewMockSockets(make([]*testsockets.MockSocket, 0))
}

func TestUpsertAndDeleteService(t *testing.T) {
	m := setupManagerTestSuite(t)
	m.testUpsertAndDeleteService(t)
}

func TestUpsertAndDeleteServiceWithoutIPv6(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.EnableIPv6 = false
	m.testUpsertAndDeleteService(t)
}

func TestUpsertAndDeleteServiceNat46(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
	option.Config.NodePortNat46X64 = true
	m.testUpsertAndDeleteService46(t)
}

func TestUpsertAndDeleteServiceNat64(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.EnableIPv4 = true
	option.Config.EnableIPv6 = true
	option.Config.NodePortNat46X64 = true
	m.testUpsertAndDeleteService64(t)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService46(t *testing.T) {
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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNat46, m.svc.svcByID[id1].svcNatPolicy)

	// Should delete both backends of service
	p.Backends = nil
	created, id2, err := m.svc.UpsertService(p)
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, id1, id2)
	require.Equal(t, 0, len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNone, m.svc.svcByID[id2].svcNatPolicy)

	// Should delete the remaining service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Equal(t, 0, len(m.lbmap.ServiceByID))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
}

func (m *ManagerTestSuite) testUpsertAndDeleteService64(t *testing.T) {
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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNat64, m.svc.svcByID[id1].svcNatPolicy)

	// Should delete both backends of service
	p.Backends = nil
	created, id2, err := m.svc.UpsertService(p)
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, id1, id2)
	require.Equal(t, 0, len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNone, m.svc.svcByID[id2].svcNatPolicy)

	// Should delete the remaining service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Equal(t, 0, len(m.lbmap.ServiceByID))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
}

func (m *ManagerTestSuite) testUpsertAndDeleteService(t *testing.T) {
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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, true, m.svc.svcByID[id1].sessionAffinity)
	require.Equal(t, uint32(100), m.svc.svcByID[id1].sessionAffinityTimeoutSec)
	require.Equal(t, true, m.lbmap.ServiceByID[uint16(id1)].SessionAffinity)
	require.Equal(t, uint32(100), m.lbmap.ServiceByID[uint16(id1)].SessionAffinityTimeoutSec)
	require.Equal(t, 2, len(m.lbmap.AffinityMatch[uint16(id1)]))
	for bID := range m.lbmap.BackendByID {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][bID])
	}

	// Should remove session affinity
	p.SessionAffinity = false
	created, id1, err = m.svc.UpsertService(p)
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, 0, len(m.lbmap.AffinityMatch[uint16(id1)]))
	require.Equal(t, false, m.svc.svcByID[id1].sessionAffinity)
	require.Equal(t, false, m.lbmap.ServiceByID[uint16(id1)].SessionAffinity)
	// TODO(brb) test that backends are the same
	// TODO(brb) check that .backends =~ .backendsByHash

	// Should remove one backend and enable session affinity
	p.Backends = backends1[0:1]
	p.SessionAffinity = true
	p.SessionAffinityTimeoutSec = 200
	created, id1, err = m.svc.UpsertService(p)
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 1, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 1, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, true, m.svc.svcByID[id1].sessionAffinity)
	require.Equal(t, uint32(200), m.svc.svcByID[id1].sessionAffinityTimeoutSec)
	require.Equal(t, 1, len(m.lbmap.AffinityMatch[uint16(id1)]))
	for bID := range m.lbmap.BackendByID {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][bID])
	}

	// Should add another service
	require.Nil(t, err)
	cidr1, err := cidr.ParseCIDR("10.0.0.0/8")
	require.Nil(t, err)
	cidr2, err := cidr.ParseCIDR("192.168.1.0/24")
	require.Nil(t, err)
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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(2), id2)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc2", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns2", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, 2, len(m.lbmap.AffinityMatch[uint16(id2)]))
	require.Equal(t, 2, len(m.lbmap.SourceRanges[uint16(id2)]))

	// Should add IPv6 service only if IPv6 is enabled
	require.Nil(t, err)
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	require.Nil(t, err)
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
		require.Nil(t, err)
		require.Equal(t, true, created)
		require.Equal(t, lb.ID(3), id3)
		require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id3)].Backends))
		require.Equal(t, 4, len(m.lbmap.BackendByID))
		require.Equal(t, "svc3", m.svc.svcByID[id3].svcName.Name)
		require.Equal(t, "ns3", m.svc.svcByID[id3].svcName.Namespace)
		require.Equal(t, 2, len(m.lbmap.AffinityMatch[uint16(id3)]))
		require.Equal(t, 1, len(m.lbmap.SourceRanges[uint16(id3)]))

		// Should remove the IPv6 service
		found, err := m.svc.DeleteServiceByID(lb.ServiceID(id3))
		require.Nil(t, err)
		require.Equal(t, true, found)
	} else {
		require.ErrorContains(t, err, "Unable to upsert service")
		require.ErrorContains(t, err, "as IPv6 is disabled")
		require.Equal(t, false, created)
	}
	require.Equal(t, 2, len(m.lbmap.ServiceByID))
	require.Equal(t, 2, len(m.lbmap.BackendByID))

	// Should remove the service and the backend, but keep another service and
	// its backends. Also, should remove the affinity match.
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Equal(t, 1, len(m.lbmap.ServiceByID))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, 0, len(m.lbmap.AffinityMatch[uint16(id1)]))

	// Should delete both backends of service
	p2.Backends = nil
	p2.LoadBalancerSourceRanges = []*cidr.CIDR{cidr2}
	created, id2, err = m.svc.UpsertService(p2)
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(2), id2)
	require.Equal(t, 0, len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
	require.Equal(t, "svc2", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns2", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, 0, len(m.lbmap.AffinityMatch[uint16(id2)]))
	require.Equal(t, 1, len(m.lbmap.SourceRanges[uint16(id2)]))

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Equal(t, 0, len(m.lbmap.ServiceByID))
	require.Equal(t, 0, len(m.lbmap.BackendByID))

	// Should ignore the source range if it does not match FE's ip family
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	require.Nil(t, err)
	cidr2, err = cidr.ParseCIDR("192.168.1.0/24")
	require.Nil(t, err)

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
	require.Equal(t, true, created)
	require.Nil(t, err)
	require.Equal(t, 1, len(m.lbmap.SourceRanges[uint16(id4)]))
}

func TestRestoreServices(t *testing.T) {
	m := setupManagerTestSuite(t)

	p1 := &lb.SVC{
		Frontend:         frontend1,
		Backends:         backends1,
		Type:             lb.SVCTypeNodePort,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
	}
	_, id1, err := m.svc.UpsertService(p1)
	require.Nil(t, err)
	cidr1, err := cidr.ParseCIDR("10.0.0.0/8")
	require.Nil(t, err)
	cidr2, err := cidr.ParseCIDR("192.168.1.0/24")
	require.Nil(t, err)
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
	require.Nil(t, err)

	// Restart service, but keep the lbmap to restore services from
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	option.Config.DatapathMode = datapathOpt.DatapathModeLBOnly
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.newServiceMock(lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	require.Nil(t, err)

	// Backends have been restored
	require.Equal(t, 3, len(m.svc.backendByHash))
	backends := append(backends1, backends2...)
	for _, b := range backends {
		_, found := m.svc.backendByHash[b.Hash()]
		require.Equal(t, true, found)
	}

	// Services have been restored too
	require.Equal(t, 2, len(m.svc.svcByID))
	require.EqualValues(t, lbmap.ServiceByID[uint16(id1)].Frontend, m.svc.svcByID[id1].frontend)
	require.EqualValues(t, lbmap.ServiceByID[uint16(id1)].Backends, m.svc.svcByID[id1].backends)
	require.EqualValues(t, lbmap.ServiceByID[uint16(id2)].Frontend, m.svc.svcByID[id2].frontend)
	require.EqualValues(t, lbmap.ServiceByID[uint16(id2)].Backends, m.svc.svcByID[id2].backends)

	// Session affinity too
	require.Equal(t, false, m.svc.svcByID[id1].sessionAffinity)
	require.Equal(t, true, m.svc.svcByID[id2].sessionAffinity)
	require.Equal(t, uint32(200), m.svc.svcByID[id2].sessionAffinityTimeoutSec)

	// LoadBalancer source ranges too
	require.Equal(t, 2, len(m.svc.svcByID[id2].loadBalancerSourceRanges))
	for _, cidr := range []*cidr.CIDR{cidr1, cidr2} {
		found := false
		for _, c := range m.svc.svcByID[id2].loadBalancerSourceRanges {
			if c.String() == cidr.String() {
				found = true
				break
			}
		}
		require.Equal(t, true, found)
	}

	// Maglev lookup table too
	require.Equal(t, len(backends1), m.lbmap.DummyMaglevTable[uint16(id1)])
	require.Equal(t, len(backends2), m.lbmap.DummyMaglevTable[uint16(id2)])
}

func TestSyncWithK8sFinished(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	p2 := &lb.SVC{
		Frontend:         frontend2,
		Backends:         backends2,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc2", Namespace: "ns2"},
	}
	_, _, err = m.svc.UpsertService(p2)
	require.Nil(t, err)
	require.Equal(t, 2, len(m.svc.svcByID))
	require.Equal(t, 2, len(m.lbmap.AffinityMatch[uint16(id1)]))

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.newServiceMock(lbmap)
	err = m.svc.RestoreServices()
	require.Nil(t, err)
	require.Equal(t, 2, len(m.svc.svcByID))

	// Imitate a situation where svc1 was deleted while we were down.
	// In real life, the following upsert is called by k8s_watcher during
	// the sync period of the cilium-agent's k8s service cache which happens
	// during the initialization of cilium-agent. P2 svc updated affinity is synced.
	p2.SessionAffinity = true
	p2.SessionAffinityTimeoutSec = 100
	_, id2, err := m.svc.UpsertService(p2)
	require.Nil(t, err)

	// Add non-existing affinity matches
	lbmap.AddAffinityMatch(20, 300)
	lbmap.AddAffinityMatch(20, 301)
	lbmap.AddAffinityMatch(uint16(id1), 302)
	lbmap.AddAffinityMatch(uint16(id2), 305)

	// cilium-agent finished the initialization, and thus SyncWithK8sFinished
	// is called
	stale, err := m.svc.SyncWithK8sFinished(false, nil)
	require.Nil(t, stale)
	require.Nil(t, err)

	// svc1 should be removed from cilium while svc2 is synced
	require.Equal(t, 1, len(m.svc.svcByID))
	_, found := m.svc.svcByID[id2]
	require.Equal(t, true, found)
	_, found = m.svc.svcByID[id1]
	require.Equal(t, false, found)
	require.Equal(t, "svc2", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns2", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, 1, len(m.lbmap.AffinityMatch))
	// Check that the non-existing affinity matches were removed
	matches, _ := lbmap.DumpAffinityMatches()
	require.Equal(t, 1, len(matches)) // id2 svc has updated session affinity
	require.Equal(t, 2, len(matches[uint16(id2)]))
	for _, b := range lbmap.ServiceByID[uint16(id2)].Backends {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id2)][b.ID])
	}
}

func TestRestoreServiceWithStaleBackends(t *testing.T) {
	backendAddrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	finalBackendAddrs := []string{"10.0.0.2", "10.0.0.3", "10.0.0.5"}

	service := func(ns, name, frontend string, backends ...string) *lb.SVC {
		var bes []*lb.Backend
		for _, backend := range backends {
			bes = append(bes, lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster(backend), 8080))
		}

		return &lb.SVC{
			Frontend:         *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster(frontend), 80, lb.ScopeExternal, 0),
			Backends:         bes,
			Type:             lb.SVCTypeClusterIP,
			ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
			IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
			Name:             lb.ServiceName{Name: name, Namespace: ns},
		}
	}

	toBackendAddrs := func(backends []*lb.Backend) (addrs []string) {
		for _, be := range backends {
			addrs = append(addrs, be.L3n4Addr.AddrCluster.Addr().String())
		}
		return
	}

	tests := []struct {
		name                string
		localOnly           bool
		isLocal             bool
		expectStaleBackends bool
	}{
		{
			name:                "local only, local service",
			localOnly:           true,
			isLocal:             true,
			expectStaleBackends: false,
		},
		{
			name:                "local only, global service",
			localOnly:           true,
			isLocal:             false,
			expectStaleBackends: true,
		},
		{
			name:                "all, local service",
			localOnly:           false,
			isLocal:             true,
			expectStaleBackends: false,
		},
		{
			name:                "all, global service",
			localOnly:           false,
			isLocal:             false,
			expectStaleBackends: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lbmap := mockmaps.NewLBMockMap()
			svc := newService(&FakeMonitorAgent{}, lbmap, nil, nil, true)

			_, id1, err := svc.upsertService(service("foo", "bar", "172.16.0.1", backendAddrs...))
			require.NoError(t, err, "Failed to upsert service")

			require.Contains(t, lbmap.ServiceByID, uint16(id1), "lbmap not populated correctly")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "lbmap not populated correctly")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(maps.Values(lbmap.BackendByID)), "lbmap not populated correctly")

			// Recreate the Service structure, but keep the lbmap to restore services from
			svc = newService(&FakeMonitorAgent{}, lbmap, nil, nil, true)
			require.NoError(t, svc.RestoreServices(), "Failed to restore services")

			// Simulate a set of service updates. Until synchronization completes, a given service
			// might not yet contain all backends, in case they either belong to different endpointslices
			// or different clusters.
			_, id1bis, err := svc.upsertService(service("foo", "bar", "172.16.0.1", "10.0.0.3"))
			require.NoError(t, err, "Failed to upsert service")
			require.Equal(t, id1, id1bis, "Service ID changed unexpectedly")

			// No backend should have been removed yet
			require.Contains(t, lbmap.ServiceByID, uint16(id1), "lbmap incorrectly modified")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "lbmap incorrectly modified")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(maps.Values(lbmap.BackendByID)), "lbmap incorrectly modified")

			// Let's do it once more
			_, id1ter, err := svc.upsertService(service("foo", "bar", "172.16.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"))
			require.NoError(t, err, "Failed to upsert service")
			require.Equal(t, id1, id1ter, "Service ID changed unexpectedly")

			// No backend should have been removed yet
			require.Contains(t, lbmap.ServiceByID, uint16(id1), "lbmap incorrectly modified")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "lbmap incorrectly modified")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(maps.Values(lbmap.BackendByID)), "lbmap incorrectly modified")

			svcID := k8s.ServiceID{Namespace: "foo", Name: "bar"}
			localServices := sets.New[k8s.ServiceID]()
			if tt.isLocal {
				localServices.Insert(svcID)
			}

			stale, err := svc.SyncWithK8sFinished(tt.localOnly, localServices)
			require.NoError(t, err, "Failed to trigger garbage collection")

			require.Contains(t, lbmap.ServiceByID, uint16(id1), "service incorrectly removed from lbmap")

			// Stale backends should now have been removed (if appropriate)
			if tt.expectStaleBackends {
				require.Empty(t, stale)
				require.ElementsMatch(t, backendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "stale backends should not have been removed from lbmap")
				require.ElementsMatch(t, backendAddrs, toBackendAddrs(maps.Values(lbmap.BackendByID)), "stale backends should not have been removed from lbmap")
			} else {
				require.ElementsMatch(t, stale, []k8s.ServiceID{svcID})

				// Trigger a new upsertion: this mimics what would eventually happen when calling ServiceCache.EnsureService()
				_, _, err := svc.upsertService(service("foo", "bar", "172.16.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"))
				require.NoError(t, err, "Failed to upsert service")

				require.ElementsMatch(t, finalBackendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "stale backends not correctly removed from lbmap")
				require.ElementsMatch(t, finalBackendAddrs, toBackendAddrs(maps.Values(lbmap.BackendByID)), "stale backends not correctly removed from lbmap")
			}
		})
	}
}

func TestHealthCheckNodePort(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)

	p1.Backends[2].State = lb.BackendStateTerminating
	_, _, _ = m.svc.UpsertService(p1)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Insert the ClusterIP frontend of svc1
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
	require.Nil(t, err)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Update the HealthCheckNodePort for svc1
	p1.HealthCheckNodePort = 32000
	new, _, err := m.svc.UpsertService(p1)
	require.Nil(t, err)
	require.Equal(t, false, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32000).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32000).Service.Namespace)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32000).LocalEndpoints)
	require.Nil(t, m.svcHealth.ServiceByPort(32001))

	// Update the externalTrafficPolicy for svc1
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	p1.HealthCheckNodePort = 0
	new, _, err = m.svc.UpsertService(p1)
	require.Nil(t, err)
	require.Equal(t, false, new)
	require.Nil(t, m.svcHealth.ServiceByPort(32000))
	require.Nil(t, m.svcHealth.ServiceByPort(32001))

	// Restore the original version of svc1
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.HealthCheckNodePort = 32001
	new, _, err = m.svc.UpsertService(p1)
	require.Nil(t, err)
	require.Equal(t, false, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Upsert svc1 of type LoadBalancer with only remote backends
	p1.Backends = remoteBackends
	new, _, err = m.svc.UpsertService(p1)
	require.Nil(t, err)
	require.Equal(t, false, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, 0, m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Upsert svc1 of type ClusterIP with only remote backends
	p2.Backends = remoteBackends
	new, _, err = m.svc.UpsertService(p2)
	require.Nil(t, err)
	require.Equal(t, false, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, 0, m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Delete svc1 of type LoadBalancer
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Nil(t, m.svcHealth.ServiceByPort(32001))

	// Delete svc1 of type ClusterIP
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Nil(t, m.svcHealth.ServiceByPort(32001))
}

// Define a mock implementation of the NodeMetaCollector interface for testing
type mockNodeMetaCollector struct {
	ipv4 net.IP
	ipv6 net.IP
}

func (m *mockNodeMetaCollector) GetIPv4() net.IP {
	return m.ipv4
}

func (m *mockNodeMetaCollector) GetIPv6() net.IP {
	return m.ipv6
}

func TestHealthCheckLoadBalancerIP(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.EnableHealthCheckLoadBalancerIP = true

	mockCollector := &mockNodeMetaCollector{
		ipv4: net.ParseIP("192.0.2.0"),
		ipv6: net.ParseIP("2001:db8::1"),
	}

	loadBalancerIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)

	localBackend1 := lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()

	allBackends := []*lb.Backend{localBackend1}

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

	svc, _, _, _, _ := m.svc.createSVCInfoIfNotExist(p1)
	err := m.svc.upsertNodePortHealthService(svc, mockCollector)

	require.Nil(t, err)
	require.NotEqual(t, "", svc.healthcheckFrontendHash)
	require.Equal(t, "svc1-healthCheck", m.svc.svcByHash[svc.healthcheckFrontendHash].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByHash[svc.healthcheckFrontendHash].svcName.Namespace)
	require.Equal(t, svc.svcHealthCheckNodePort, m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.Port)
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.AddrCluster.Addr())
	require.Equal(t, cmtypes.AddrClusterFrom(netip.MustParseAddr("192.0.2.0"), option.Config.ClusterID), m.svc.svcByHash[svc.healthcheckFrontendHash].backends[0].AddrCluster)

	// Update the externalTrafficPolicy for svc1
	svc.frontend.Scope = lb.ScopeExternal
	svc.svcHealthCheckNodePort = 0
	oldHealthHash := svc.healthcheckFrontendHash
	err = m.svc.upsertNodePortHealthService(svc, mockCollector)
	require.Nil(t, err)
	require.Equal(t, "", svc.healthcheckFrontendHash)
	require.Nil(t, m.svc.svcByHash[oldHealthHash])

	// Restore the original version of svc1
	svc.frontend.Scope = lb.ScopeInternal
	svc.svcHealthCheckNodePort = 32001
	err = m.svc.upsertNodePortHealthService(svc, mockCollector)
	require.Nil(t, err)
	require.NotEqual(t, "", svc.healthcheckFrontendHash)
	require.Equal(t, "svc1-healthCheck", m.svc.svcByHash[svc.healthcheckFrontendHash].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByHash[svc.healthcheckFrontendHash].svcName.Namespace)
	require.Equal(t, svc.svcHealthCheckNodePort, m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.Port)
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.AddrCluster.Addr())
	require.Equal(t, cmtypes.AddrClusterFrom(netip.MustParseAddr("192.0.2.0"), option.Config.ClusterID), m.svc.svcByHash[svc.healthcheckFrontendHash].backends[0].AddrCluster)

	// IPv6 NodePort Backend
	oldHealthHash = svc.healthcheckFrontendHash
	svc.frontend = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("2001:db8:1::1"), 80, lb.ScopeExternal, 0)
	err = m.svc.upsertNodePortHealthService(svc, mockCollector)
	require.Nil(t, err)
	require.Equal(t, cmtypes.AddrClusterFrom(netip.MustParseAddr("2001:db8::1"), option.Config.ClusterID), m.svc.svcByHash[svc.healthcheckFrontendHash].backends[0].AddrCluster)
	require.Nil(t, m.svc.svcByHash[oldHealthHash])

	var ok bool
	// Delete
	ok, err = m.svc.DeleteService(m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.L3n4Addr)
	require.Equal(t, true, ok)
	require.Nil(t, err)

	option.Config.EnableHealthCheckLoadBalancerIP = false
}

func TestHealthCheckNodePortDisabled(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)

	// Unset HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 0
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	_, _, err = m.svc.UpsertService(p1)
	require.Nil(t, err)

	// Set HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 32000
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	_, _, err = m.svc.UpsertService(p1)
	require.Nil(t, err)

	// Delete service with active HealthCheckNodePort
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.Nil(t, err)
	require.Equal(t, true, found)
}

func TestGetServiceNameByAddr(t *testing.T) {
	m := setupManagerTestSuite(t)

	fe := frontend1.DeepCopy()
	name := "svc1"
	namespace := "ns1"
	hcport := uint16(3)
	p := &lb.SVC{
		Frontend:            *fe,
		Backends:            backends1,
		Type:                lb.SVCTypeNodePort,
		ExtTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: hcport,
		Name:                lb.ServiceName{Name: name, Namespace: namespace},
	}
	created, id1, err := m.svc.UpsertService(p)
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	fe.ID = id1
	gotNamespace, gotName, ok := m.svc.GetServiceNameByAddr(frontend1.L3n4Addr)
	require.Equal(t, namespace, gotNamespace)
	require.Equal(t, name, gotName)
	require.Equal(t, true, ok)
	_, _, ok = m.svc.GetServiceNameByAddr(frontend2.L3n4Addr)
	require.Equal(t, false, ok)
}

func TestLocalRedirectLocalBackendSelection(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Equal(t, true, ok)
	require.Equal(t, "ns1", svc.svcName.Namespace)
	require.Equal(t, "svc1", svc.svcName.Name)
	// Only node-local backends are selected
	require.Equal(t, len(localBackends), len(svc.backends))

	svcFromLbMap, ok := m.lbmap.ServiceByID[uint16(id)]
	require.Equal(t, true, ok)
	require.Equal(t, len(svc.backends), len(svcFromLbMap.Backends))
}

// Local redirect service should be able to override a ClusterIP service with same
// frontend, but reverse should produce an error. Also, it should not override
// any other type besides itself or clusterIP type.
func TestLocalRedirectServiceOverride(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)

	// Insert the service entry of type Local Redirect.
	p1.Type = lb.SVCTypeLocalRedirect
	created, id, err = m.svc.UpsertService(p1)

	// Local redirect service should override the ClusterIP service with node-local backends.
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.NotEqual(t, lb.ID(0), id)
	svc = m.svc.svcByID[id]
	// Only node-local backends are selected.
	require.Equal(t, len(localBackends), len(svc.backends))

	// Insert the service entry of type ClusterIP.
	p1.Type = lb.SVCTypeClusterIP
	created, _, err = m.svc.UpsertService(p1)

	require.Error(t, err)
	require.Equal(t, false, created)

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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)

	// Insert the service entry of type Local Redirect.
	p2.Type = lb.SVCTypeLocalRedirect
	created, _, err = m.svc.UpsertService(p2)

	// Local redirect service should not override the NodePort service.
	require.Error(t, err)
	require.Equal(t, false, created)
}

// Tests whether upsert service handles terminating backends, whereby terminating
// backends are not added to the service map, but are added to the backends and
// affinity maps.
func TestUpsertServiceWithTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

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

	created, id1, err := m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	p.Backends[0].State = lb.BackendStateTerminating

	_, _, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends1), m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	// Sorted active backends by ID first followed by non-active
	require.Equal(t, lb.BackendID(2), m.lbmap.ServiceByID[uint16(id1)].Backends[0].ID)
	require.Equal(t, lb.BackendID(3), m.lbmap.ServiceByID[uint16(id1)].Backends[1].ID)
	require.Equal(t, lb.BackendID(1), m.lbmap.ServiceByID[uint16(id1)].Backends[2].ID)
	require.Equal(t, 3, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, 3, len(m.lbmap.AffinityMatch[uint16(id1)]))
	for bID := range m.lbmap.BackendByID {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][bID])
	}
	require.Equal(t, len(backends1), m.lbmap.DummyMaglevTable[uint16(id1)])

	// Delete terminating backends.
	p.Backends = []*lb.Backend{}

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 0, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, 0, len(m.lbmap.AffinityMatch[uint16(id1)]))
}

// TestUpsertServiceWithOnlyTerminatingBackends tests that a terminating backend is still
// used if there are not active backends.
func TestUpsertServiceWithOnlyTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

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

	created, id1, err := m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)

	// The terminating backend should not be considered
	p.Backends[1].State = lb.BackendStateTerminating

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	// Delete terminating backends.
	p.Backends = p.Backends[:1]

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 1, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 1, len(m.lbmap.BackendByID))
	require.Equal(t, 1, len(m.lbmap.AffinityMatch[uint16(id1)]))

	// The terminating backend should be considered since there are no more active
	p.Backends[0].State = lb.BackendStateTerminating

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 1, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 1, len(m.lbmap.BackendByID))
	require.Equal(t, 0, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	// Delete terminating backends.
	p.Backends = []*lb.Backend{}

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 0, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, 0, len(m.lbmap.AffinityMatch[uint16(id1)]))
}

// Tests whether upsert service provisions the Maglev LUT for ClusterIP,
// if ExternalClusterIP is true
func TestUpsertServiceWithExternalClusterIP(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	option.Config.ExternalClusterIP = true
	backends := make([]*lb.Backend, 0, len(backends1))
	for _, b := range backends1 {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	p := &lb.SVC{
		Frontend:         frontend1,
		Backends:         backends,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	created, id1, err := m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, len(backends), m.lbmap.DummyMaglevTable[uint16(id1)])
}

// Tests whether upsert service doesn't provision the Maglev LUT for ClusterIP,
// if ExternalClusterIP is false
func TestUpsertServiceWithOutExternalClusterIP(t *testing.T) {
	m := setupManagerTestSuite(t)

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

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, 0, m.lbmap.DummyMaglevTable[uint16(id1)])
}

// Tests terminating backend entries are not removed after service restore.
func TestRestoreServiceWithTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

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

	created, id1, err := m.svc.UpsertService(p)

	t.Log(m.lbmap.ServiceByID[0])
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	p.Backends[0].State = lb.BackendStateTerminating

	_, _, err = m.svc.UpsertService(p)

	require.Nil(t, err)

	// Simulate agent restart.
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.newServiceMock(lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	require.Nil(t, err)

	// Backends including terminating ones have been restored
	require.Equal(t, 3, len(m.svc.backendByHash))
	for _, b := range backends1 {
		_, found := m.svc.backendByHash[b.Hash()]
		require.Equal(t, true, found)
	}

	// Affinity matches including terminating ones were restored
	matches, _ := m.lbmap.DumpAffinityMatches()
	require.Equal(t, 1, len(matches))
	require.Equal(t, 3, len(matches[uint16(id1)]))
	for _, b := range m.lbmap.ServiceByID[uint16(id1)].Backends {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][b.ID])
	}
	require.Equal(t, len(backends1), m.lbmap.DummyMaglevTable[uint16(id1)])
}

// l7 load balancer service should be able to override any service type
// (Cluster IP, NodePort, etc.) with same frontend.
func TestL7LoadBalancerServiceOverride(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// registering redirection with proxy port 0 should result in an error
	echoOtherNode := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	resource1 := L7LBResourceName{Name: "testOwner1", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource1, 0, nil)
	require.Error(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// Registering with redirection stores the proxy port.
	resource2 := L7LBResourceName{Name: "testOwner2", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource2, 9090, nil)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// registering redirection for a Service that already has a redirect registration
	// should result in an error.
	resource3 := L7LBResourceName{Name: "testOwner3", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource3, 10000, nil)
	require.Error(t, err)

	// Remove with an unregistered owner name does not remove
	resource4 := L7LBResourceName{Name: "testOwner4", Namespace: "cilium-test"}
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource4)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// Removing registration without redirection does not remove the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource1)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// removing the registration with redirection removes the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource2)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)
}

// l7 load balancer service with ports should only override the given frontend ports.
func TestL7LoadBalancerServiceOverrideWithPorts(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	echoOtherNode := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	resource1 := L7LBResourceName{Name: "testOwner1", Namespace: "cilium-test"}

	// Registering with redirection stores the proxy port.
	resource2 := L7LBResourceName{Name: "testOwner2", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource2, 9090, []uint16{80})
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// removing the registration with redirection removes the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource2)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// Registering with non-matching port does not store the proxy port.
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource2, 9090, []uint16{8080})
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// registering redirection for a Service that already has a redirect registration
	// should result in an error.
	resource3 := L7LBResourceName{Name: "testOwner3", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource3, 10000, nil)
	require.Error(t, err)

	// Adding a matching frontend gets proxy port

	p2 := &lb.SVC{
		Frontend:         frontend1_8080,
		Backends:         allBackends,
		Type:             lb.SVCTypeClusterIP,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
		Name:             lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"},
	}

	// Insert the service entry of type ClusterIP.
	created, id2, err := m.svc.UpsertService(p2)
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id2)

	svc, ok = m.svc.svcByID[id2]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// Remove with an unregistered owner name does not remove
	resource4 := L7LBResourceName{Name: "testOwner4", Namespace: "cilium-test"}
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource4)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id2]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// Removing registration without redirection does not remove the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource1)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id2]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// removing the registration with redirection removes the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource2)
	require.Nil(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	svc, ok = m.svc.svcByID[id2]
	require.Equal(t, len(allBackends), len(svc.backends))
	require.Equal(t, true, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)
}

// L7 LB proxies should be able to register callback based backend sync registration
func TestL7LoadBalancerServiceBackendSyncRegistration(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Nil(t, err)
	require.Equal(t, true, created)
	require.NotEqual(t, lb.ID(0), id)

	// Registering L7LB backend sync should register backend sync and trigger an initial synchronization
	service := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	backendSyncer := &FakeBackendSyncer{}
	err = m.svc.RegisterL7LBServiceBackendSync(service, backendSyncer)
	require.Nil(t, err)

	require.Equal(t, 1, len(m.svc.l7lbSvcs))
	require.Equal(t, 1, len(m.svc.l7lbSvcs[service].backendSyncRegistrations))
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 1, backendSyncer.nrOfSyncs)

	// Re-Registering L7LB backend sync should keep the existing registration and trigger an implicit re-synchronization
	err = m.svc.RegisterL7LBServiceBackendSync(service, backendSyncer)
	require.Nil(t, err)

	require.Equal(t, 1, len(m.svc.l7lbSvcs))
	require.Equal(t, 1, len(m.svc.l7lbSvcs[service].backendSyncRegistrations))
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 2, backendSyncer.nrOfSyncs)

	// Upserting a service should trigger a sync for the registered backend sync registrations
	allBackends = append(allBackends, backends4...)
	p1.Backends = allBackends
	created, id, err = m.svc.UpsertService(p1)
	require.Nil(t, err)
	require.Equal(t, false, created)
	require.NotEqual(t, lb.ID(0), id)

	require.Equal(t, 1, len(m.svc.l7lbSvcs))
	require.Equal(t, 1, len(m.svc.l7lbSvcs[service].backendSyncRegistrations))
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 3, backendSyncer.nrOfSyncs)

	// De-registering a backend sync should delete the backend sync registration
	err = m.svc.DeregisterL7LBServiceBackendSync(service, backendSyncer)
	require.Nil(t, err)

	require.Equal(t, 0, len(m.svc.l7lbSvcs))
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 3, backendSyncer.nrOfSyncs)
}

// Tests that services with the given backends are updated with the new backend
// state.
func TestUpdateBackendsState(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.Backend, 0, len(backends1))
	for _, b := range backends1 {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
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

	require.Nil(t, err1)
	require.Nil(t, err2)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, lb.ID(2), id2)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[1].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[1].State)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id2)])
	require.Equal(t, len(backends), len(m.lbmap.BackendByID))
	// Backend states are persisted in the map.
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[1].State)
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[2].State)

	// Update the state for one of the backends.
	updated := []*lb.Backend{backends[0]}
	updated[0].State = lb.BackendStateQuarantined

	svcs, err := m.svc.UpdateBackendsState(updated)

	require.Nil(t, err)
	// Both the services are updated with the update backend state.
	require.Equal(t, lb.BackendStateQuarantined, m.svc.svcByID[id1].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[1].State)
	require.Equal(t, lb.BackendStateQuarantined, m.svc.svcByID[id2].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[1].State)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id2)])
	require.Equal(t, len(backends), len(m.lbmap.BackendByID))
	require.ElementsMatch(t, svcs, []lb.L3n4Addr{p1.Frontend.L3n4Addr, p2.Frontend.L3n4Addr})
	// Updated backend states are persisted in the map.
	require.Equal(t, lb.BackendStateQuarantined, m.lbmap.BackendByID[1].State)
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[2].State)

	// Update the state again.
	updated = []*lb.Backend{backends[0]}
	updated[0].State = lb.BackendStateActive

	svcs, err = m.svc.UpdateBackendsState(updated)

	require.Nil(t, err)
	// Both the services are updated with the update backend state.
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[1].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[1].State)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id2)])
	require.Equal(t, len(backends), len(m.lbmap.BackendByID))
	require.ElementsMatch(t, svcs, []lb.L3n4Addr{p1.Frontend.L3n4Addr, p2.Frontend.L3n4Addr})
	// Updated backend states are persisted in the map.
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[1].State)
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[2].State)
}

// Tests that backend states are restored.
func TestRestoreServiceWithBackendStates(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	bs := append(backends1, backends4...)
	backends := make([]*lb.Backend, 0, len(bs))
	for _, b := range bs {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	backends[2].State = lb.BackendStateActive

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

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), len(m.svc.backendByHash))

	// Update backend states.
	var updates []*lb.Backend
	backends[0].State = lb.BackendStateQuarantined
	backends[1].State = lb.BackendStateMaintenance
	updates = append(updates, backends[0], backends[1])
	_, err = m.svc.UpdateBackendsState(updates)

	require.Nil(t, err)

	// Simulate agent restart.
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.newServiceMock(lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	require.Nil(t, err)

	// Check that backends along with their states have been restored
	require.Equal(t, len(backends), len(m.svc.backendByHash))
	statesMatched := 0
	for _, b := range backends {
		be, found := m.svc.backendByHash[b.Hash()]
		require.Equal(t, true, found)
		if be.String() == b.String() {
			require.Equal(t, b.State, be.State, "before %+v restored %+v", b, be)
			statesMatched++
		}
	}
	require.Equal(t, len(backends), statesMatched)
	require.Equal(t, 1, m.lbmap.DummyMaglevTable[uint16(id1)])
}

func TestUpsertServiceWithZeroWeightBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends1, backends4...)
	backends[1].Weight = 0
	backends[1].State = lb.BackendStateMaintenance
	backends[2].Weight = 1

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

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, 3, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 3, len(m.lbmap.BackendByID))
	hash := backends[1].L3n4Addr.Hash()
	require.Equal(t, lb.BackendStateMaintenance, m.svc.backendByHash[hash].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByID[id1].backendByHash[hash].State)
	hash2 := backends[2].L3n4Addr.Hash()
	require.Equal(t, lb.BackendStateActive, m.svc.backendByHash[hash2].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backendByHash[hash2].State)
	require.Equal(t, 2, m.lbmap.DummyMaglevTable[uint16(id1)])

	// Update existing backend weight
	p.Backends[2].Weight = 0
	p.Backends[2].State = lb.BackendStateMaintenance

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, 3, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 3, len(m.lbmap.BackendByID))
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByID[id1].backendByHash[hash2].State)
	require.Equal(t, 1, m.lbmap.DummyMaglevTable[uint16(id1)])

	// Delete backends with weight 0
	p.Backends = backends[:1]

	created, id1, err = m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, false, created)
	require.Equal(t, 1, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 1, len(m.lbmap.BackendByID))
	require.Equal(t, 1, m.lbmap.DummyMaglevTable[uint16(id1)])
}

func TestUpdateBackendsStateWithBackendSharedAcrossServices(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	be := append(backends1, backends4...)
	backends := make([]*lb.Backend, 0, len(be))
	for _, b := range be {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	backends[2].State = lb.BackendStateMaintenance
	hash0 := backends[0].L3n4Addr.Hash()
	hash1 := backends[1].L3n4Addr.Hash()
	hash2 := backends[2].L3n4Addr.Hash()

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
	r := &lb.SVC{
		Frontend:                  frontend2,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name: lb.ServiceName{
			Name:      "svc2",
			Namespace: "ns1",
		},
	}
	svcHash2 := r.Frontend.Hash()

	_, _, err := m.svc.UpsertService(p)
	require.Nil(t, err)
	_, _, err = m.svc.UpsertService(r)
	require.Nil(t, err)
	_, id1, err := m.svc.UpsertService(r)

	// Assert expected backend states after consecutive upsert service calls that share the backends.
	require.Nil(t, err)
	require.Equal(t, 3, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 3, len(m.lbmap.BackendByID))
	require.Equal(t, lb.BackendStateActive, m.svc.backendByHash[hash0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.backendByHash[hash1].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.backendByHash[hash2].State)

	backends[1].State = lb.BackendStateMaintenance
	_, err = m.svc.UpdateBackendsState(backends)

	require.Nil(t, err)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.backendByHash[hash1].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByHash[svcHash2].backends[1].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByHash[svcHash2].backendByHash[hash1].State)
}

func TestSyncNodePortFrontends(t *testing.T) {
	m := setupManagerTestSuite(t)

	// Add a IPv4 surrogate frontend
	surrogate := &lb.SVC{
		Frontend: surrogateFE,
		Backends: backends1,
		Type:     lb.SVCTypeNodePort,
	}
	_, surrID, err := m.svc.UpsertService(surrogate)
	require.Nil(t, err)
	p1 := &lb.SVC{
		Frontend: frontend1,
		Backends: backends1,
		Type:     lb.SVCTypeNodePort,
	}
	_, _, err = m.svc.UpsertService(p1)
	require.Nil(t, err)
	require.Equal(t, 2, len(m.svc.svcByID))

	// With no addresses all frontends (except surrogates) should be removed.
	err = m.svc.SyncNodePortFrontends(sets.New[netip.Addr]())
	require.Nil(t, err)

	require.Equal(t, 1, len(m.svc.svcByID))
	_, ok := m.svc.svcByID[surrID]
	require.Equal(t, true, ok)

	// With a new frontend addresses services should be re-created.
	nodeAddrs := sets.New(
		frontend1.AddrCluster.Addr(),
		frontend2.AddrCluster.Addr(),
		// IPv6 address should be ignored initially without IPv6 surrogate
		frontend3.AddrCluster.Addr(),
	)
	m.svc.SyncNodePortFrontends(nodeAddrs)
	require.Equal(t, 2+1 /* surrogate */, len(m.svc.svcByID))

	_, _, found := m.svc.GetServiceNameByAddr(frontend1.L3n4Addr)
	require.Equal(t, true, found)
	_, _, found = m.svc.GetServiceNameByAddr(frontend2.L3n4Addr)
	require.Equal(t, true, found)

	// Add an IPv6 surrogate
	surrogate = &lb.SVC{
		Frontend: surrogateFEv6,
		Backends: backends3,
		Type:     lb.SVCTypeNodePort,
	}
	_, _, err = m.svc.UpsertService(surrogate)
	require.Nil(t, err)

	err = m.svc.SyncNodePortFrontends(nodeAddrs)
	require.Nil(t, err)
	require.Equal(t, 3+2 /* surrogates */, len(m.svc.svcByID))
}

func TestTrafficPolicy(t *testing.T) {
	m := setupManagerTestSuite(t)

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
	require.Equal(t, true, created)
	require.Nil(t, err)

	p2 := &lb.SVC{
		Frontend:         externalIP,
		Backends:         allBackends,
		Type:             lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy: lb.SVCTrafficPolicyLocal,
		Name:             lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	created, id2, err := m.svc.UpsertService(p2)
	require.Equal(t, true, created)
	require.Nil(t, err)

	svcFromLbMap1, ok := m.lbmap.ServiceByID[uint16(id1)]
	require.Equal(t, true, ok)
	require.Equal(t, len(localBackends), len(svcFromLbMap1.Backends))

	svcFromLbMap2, ok := m.lbmap.ServiceByID[uint16(id2)]
	require.Equal(t, true, ok)
	require.Equal(t, len(allBackends), len(svcFromLbMap2.Backends))

	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.IntTrafficPolicy = lb.SVCTrafficPolicyCluster
	created, id3, err := m.svc.UpsertService(p1)
	require.Equal(t, false, created)
	require.Nil(t, err)
	require.Equal(t, id1, id3)

	svcFromLbMap3, ok := m.lbmap.ServiceByID[uint16(id1)]
	require.Equal(t, true, ok)
	require.Equal(t, len(allBackends), len(svcFromLbMap3.Backends))

	p2.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p2.IntTrafficPolicy = lb.SVCTrafficPolicyCluster
	created, id4, err := m.svc.UpsertService(p2)
	require.Equal(t, false, created)
	require.Nil(t, err)
	require.Equal(t, id2, id4)

	svcFromLbMap4, ok := m.lbmap.ServiceByID[uint16(id2)]
	require.Equal(t, true, ok)
	require.Equal(t, len(localBackends), len(svcFromLbMap4.Backends))

	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.Nil(t, err)
	require.Equal(t, true, found)
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	require.Nil(t, err)
	require.Equal(t, true, found)
}

// Tests whether delete service handles non-active backends.
func TestDeleteServiceWithTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := backends5
	backends[0].State = lb.BackendStateTerminating
	p := &lb.SVC{
		Frontend: frontend1,
		Backends: backends,
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	created, id1, err := m.svc.UpsertService(p)

	require.Nil(t, err)
	require.Equal(t, true, created)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, 2, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 2, len(m.lbmap.BackendByID))
	require.Equal(t, lb.ServiceName{Name: "svc1", Namespace: "ns1"}, m.svc.svcByID[id1].svcName)

	// Delete service.
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))

	require.Nil(t, err)
	require.Equal(t, true, found)
	require.Equal(t, 0, len(m.lbmap.ServiceByID))
	require.Equal(t, 0, len(m.lbmap.BackendByID))
}

func TestRestoreServicesWithLeakedBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

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

	require.Nil(t, err1)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, len(backends), len(m.lbmap.BackendByID))

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
	require.Equal(t, len(backends)+4, len(m.lbmap.BackendByID))
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	m.svc = newService(&FakeMonitorAgent{}, lbmap, nil, nil, true)

	// Restore services from lbmap
	err := m.svc.RestoreServices()
	require.Nil(t, err)
	require.Equal(t, len(backends), len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	// Leaked backends should be deleted.
	require.Equal(t, len(backends), len(m.lbmap.BackendByID))
}

// Tests backend connections getting destroyed.
func TestUpsertServiceWithDeletedBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.EnableSocketLB = true
	backends := []*lb.Backend{
		lb.NewBackend(0, lb.UDP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080),
		lb.NewBackend(0, lb.UDP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080),
	}
	cookie1 := [2]uint32{1234, 0}
	cookie2 := [2]uint32{1235, 0}
	id1 := netlink.SocketID{
		DestinationPort: 8080,
		Destination:     backends[0].L3n4Addr.AddrCluster.Addr().AsSlice(),
		Cookie:          cookie1,
	}
	id2 := netlink.SocketID{
		DestinationPort: 8080,
		Destination:     backends[1].L3n4Addr.AddrCluster.Addr().AsSlice(),
		Cookie:          cookie2,
	}
	// Socket connected to backend1
	s1 := testsockets.MockSocket{
		SockID: id1, Family: syscall.AF_INET, Protocol: unix.IPPROTO_UDP,
	}
	// Socket connected to backend2
	s2 := testsockets.MockSocket{
		SockID: id2, Family: syscall.AF_INET, Protocol: unix.IPPROTO_UDP,
	}
	svc := &lb.SVC{
		Frontend: frontend1,
		Backends: backends,
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}
	key1 := *lbmap.NewSockRevNat4Key(1234, s1.SockID.Destination, s1.SockID.DestinationPort)
	key2 := *lbmap.NewSockRevNat4Key(1235, s2.SockID.Destination, s2.SockID.DestinationPort)
	m.lbmap.SockRevNat4[key1] = lbmap.SockRevNat4Value{}
	m.lbmap.SockRevNat4[key2] = lbmap.SockRevNat4Value{}
	sockets := []*testsockets.MockSocket{&s1, &s2}
	m.svc.backendConnectionHandler = testsockets.NewMockSockets(sockets)

	created, _, err := m.svc.UpsertService(svc)

	require.Nil(t, err)
	require.Equal(t, true, created)

	// Delete one of the backends.
	svc = &lb.SVC{
		Frontend: frontend1,
		Backends: []*lb.Backend{backends[1]},
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	created, _, err = m.svc.UpsertService(svc)

	require.Nil(t, err)
	require.Equal(t, false, created)

	// Only the sockets connected to the deleted backend are destroyed.
	for _, socket := range sockets {
		if socket.Equal(sockets[0]) {
			require.Equal(t, true, socket.Destroyed)
		} else {
			require.Equal(t, false, socket.Destroyed)
		}
	}
}

type FakeBackendSyncer struct {
	nrOfBackends int
	nrOfSyncs    int
}

var _ BackendSyncer = &FakeBackendSyncer{}

func (r *FakeBackendSyncer) ProxyName() string {
	return "Fake"
}

func (r *FakeBackendSyncer) Sync(svc *lb.SVC) error {
	r.nrOfBackends = len(svc.Backends)
	r.nrOfSyncs++

	return nil
}

type FakeMonitorAgent struct{}

var _ monitorAgent.Agent = &FakeMonitorAgent{}

func (f *FakeMonitorAgent) AttachToEventsMap(nPages int) error {
	return nil
}

func (f *FakeMonitorAgent) RegisterNewConsumer(newConsumer consumer.MonitorConsumer) {
}

func (f *FakeMonitorAgent) RegisterNewListener(newListener listener.MonitorListener) {
}

func (f *FakeMonitorAgent) RemoveConsumer(mc consumer.MonitorConsumer) {
}

func (f *FakeMonitorAgent) RemoveListener(ml listener.MonitorListener) {
}

func (f *FakeMonitorAgent) SendEvent(typ int, event interface{}) error {
	return nil
}

func (f *FakeMonitorAgent) State() *models.MonitorStatus {
	return nil
}

func TestHealthCheckCB(t *testing.T) {
	m := setupManagerTestSuite(t)

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

	require.NoError(t, err1)
	require.Equal(t, id1, lb.ID(1))
	require.Equal(t, len(m.lbmap.ServiceByID[uint16(id1)].Backends), len(backends))
	require.Equal(t, len(m.lbmap.BackendByID), len(backends))
	require.Equal(t, m.svc.svcByID[id1].backends[0].State, lb.BackendStateActive)

	be := backends[0]
	m.svc.HealthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend1.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateQuarantined,
		})

	require.Equal(t, len(m.lbmap.BackendByID), len(backends))
	require.Equal(t, m.svc.svcByID[id1].backends[0].State, lb.BackendStateQuarantined)
	require.Equal(t, m.lbmap.SvcActiveBackendsCount[uint16(id1)], 1)
}

func TestHealthCheckInitialSync(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.Backend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	p1 := &lb.SVC{
		Frontend: frontend1,
		Backends: backends,
		Type:     lb.SVCTypeClusterIP,
		Name:     lb.ServiceName{Name: "svc1", Namespace: "ns1"},
	}

	_, _, err := m.svc.UpsertService(p1)
	require.NoError(t, err)

	// Test the Subscribe call replays the current state
	receivedServices := make([]lb.ServiceName, 0)

	// Upsert the service before subscription
	m.svc.UpsertService(p1)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m.svc.Subscribe(ctx, func(svcInfo HealthUpdateSvcInfo) {
		receivedServices = append(receivedServices, svcInfo.Name)
	})

	require.Len(t, receivedServices, 1, "Unexpected number of events received")
	require.Equal(t, receivedServices[0], p1.Name, "Received an unexpected service")
}

func TestNotifyHealthCheckUpdatesSubscriber(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.Backend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	// Add two services with common backend.
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
		Name:     lb.ServiceName{Name: "svc2", Namespace: "ns2"},
	}
	cbCh1 := make(chan struct{})
	cbCh2 := make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(2)
	// Ensure that callbacks are received for all the services.
	cb := func(svcInfo HealthUpdateSvcInfo) {
		require.Equal(t, len(svcInfo.ActiveBackends), 1)
		require.Equal(t, svcInfo.ActiveBackends[0].L3n4Addr, backends[1].L3n4Addr)
		require.Equal(t, svcInfo.ActiveBackends[0].State, lb.BackendStateActive)
		if svcInfo.Name == p1.Name {
			require.Equal(t, svcInfo.Addr, frontend1.L3n4Addr)
			require.Equal(t, svcInfo.SvcType, lb.SVCTypeClusterIP)
			// No duplicate updates
			close(cbCh1)
		} else if svcInfo.Name == p2.Name {
			require.Equal(t, svcInfo.Addr, frontend2.L3n4Addr)
			require.Equal(t, svcInfo.SvcType, lb.SVCTypeClusterIP)
			// No duplicate updates
			close(cbCh2)
		} else {
			t.Fatalf("Unexpected service info update %v", svcInfo)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.svc.Subscribe(ctx, cb)

	_, id1, err1 := m.svc.UpsertService(p1)

	require.NoError(t, err1)
	require.Equal(t, id1, lb.ID(1))
	require.Equal(t, len(m.lbmap.ServiceByID[uint16(id1)].Backends), len(backends))
	require.Equal(t, len(m.lbmap.BackendByID), len(backends))
	require.Equal(t, m.lbmap.SvcActiveBackendsCount[uint16(id1)], 2)

	_, id2, err2 := m.svc.UpsertService(p2)

	require.NoError(t, err2)
	require.Equal(t, id2, lb.ID(2))
	require.Equal(t, len(m.lbmap.ServiceByID[uint16(id2)].Backends), len(backends))
	require.Equal(t, len(m.lbmap.BackendByID), len(backends))
	require.Equal(t, m.lbmap.SvcActiveBackendsCount[uint16(id1)], 2)

	go func() {
		_, ok := <-cbCh1
		// The channel is closed in the subscriber callback.
		assert.False(t, ok)
		wg.Done()
	}()
	go func() {
		_, ok := <-cbCh2
		// The channel is closed in the subscriber callback.
		assert.False(t, ok)
		wg.Done()
	}()

	// Health check CB with one of the backends quarantined
	be := backends[0]
	m.svc.HealthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend1.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateQuarantined,
		})
	m.svc.HealthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend2.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateQuarantined,
		})

	require.Equal(t, m.lbmap.SvcActiveBackendsCount[uint16(id1)], 1)

	wg.Wait()

	// Subscriber stops callbacks.
	cancel()
	ctx.Done()

	be = backends[0]
	m.svc.HealthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend1.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateActive,
		})
	require.Equal(t, m.lbmap.SvcActiveBackendsCount[uint16(id1)], 2)

	// Subscriber callback is not executed.

	// Test HealthCheckCBSvcEvent.
	// Add a service with a quarantined backend.
	backends = []*lb.Backend{
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.20"), 8080),
		lb.NewBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.21"), 8080),
	}
	backends[0].State = lb.BackendStateQuarantined
	frontendFoo := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.11"), 80, lb.ScopeExternal, 0)
	p1 = &lb.SVC{
		Frontend: frontendFoo,
		Backends: backends,
		Type:     lb.SVCTypeClusterIP,
		Name:     lb.ServiceName{Name: "svc10", Namespace: "ns1"},
	}
	cbCh1 = make(chan struct{})
	cb = func(svcInfo HealthUpdateSvcInfo) {
		if svcInfo.Name == p1.Name {
			require.Equal(t, svcInfo.Addr, frontendFoo.L3n4Addr)
			require.Equal(t, svcInfo.SvcType, lb.SVCTypeClusterIP)
			require.Equal(t, len(svcInfo.ActiveBackends), 1)
			require.Equal(t, svcInfo.ActiveBackends[0].L3n4Addr, backends[1].L3n4Addr)
			require.Equal(t, svcInfo.ActiveBackends[0].State, lb.BackendStateActive)
			// No duplicate updates
			close(cbCh1)
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	m.svc.Subscribe(ctx, cb)

	_, id1, err1 = m.svc.UpsertService(p1)

	require.Nil(t, err1)
	require.Equal(t, id1, lb.ID(3))
	require.Equal(t, len(m.lbmap.ServiceByID[uint16(id1)].Backends), len(backends))
	require.Equal(t, m.lbmap.SvcActiveBackendsCount[uint16(id1)], 1)

	// Send a CB service event
	m.svc.HealthCheckCallback(HealthCheckCBSvcEvent,
		HealthCheckCBSvcEventData{
			SvcAddr: p1.Frontend.L3n4Addr,
		})

	// The subscriber callback function asserts expected callbacks, and also
	// closes the channel.
	<-cbCh1
}
