// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package service

import (
	"context"
	"errors"
	"iter"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync"
	"syscall"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
	"k8s.io/apimachinery/pkg/util/sets"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/cidr"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	datapathTypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/k8s"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	monitorAgent "github.com/cilium/cilium/pkg/monitor/agent"
	"github.com/cilium/cilium/pkg/monitor/agent/consumer"
	"github.com/cilium/cilium/pkg/monitor/agent/listener"
	"github.com/cilium/cilium/pkg/netns"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/service/healthserver"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/testutils/mockmaps"
	testsockets "github.com/cilium/cilium/pkg/testutils/sockets"
	"github.com/cilium/cilium/pkg/time"
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
	assert.ErrorIs(t, err1, err2)

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
	assert.NotErrorIs(t, err1, err2)

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
	assert.NotErrorIs(t, err1, err2)

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
	assert.NotErrorIs(t, err1, err2)

	// different error types
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = errors.New("another error")
	assert.NotEqual(t, err1, err2)
	assert.NotErrorIs(t, err1, err2)

	// different error types
	err1 = errors.New("another error")
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	assert.NotEqual(t, err1, err2)
	assert.NotErrorIs(t, err1, err2)

	// an error is nil
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = nil
	assert.NotEqual(t, err1, err2)
	assert.NotErrorIs(t, err1, err2)

	// an error is nil
	err1 = nil
	err2 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	assert.NotEqual(t, err1, err2)
	assert.NotErrorIs(t, err1, err2)

	// We don't match against strings. It must be the sentinel value.
	err1 = NewErrLocalRedirectServiceExists(
		*lb.NewL3n4AddrID(lb.TCP, addrCluster1, 8080, lb.ScopeInternal, 1),
		lb.ServiceName{Namespace: "default", Name: name1},
	)
	err2 = errors.New(err1.Error())
	assert.NotEqual(t, err1, err2)
	assert.NotErrorIs(t, err1, err2)
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
	logger                      *slog.Logger
}

var (
	surrogateFE    = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("0.0.0.0"), 80, lb.ScopeExternal, 0)
	surrogateFEv6  = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("::"), 80, lb.ScopeExternal, 0)
	frontend1      = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)
	frontend1_8080 = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 8080, lb.ScopeExternal, 0)
	frontend2      = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.2"), 80, lb.ScopeExternal, 0)
	frontend3      = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("f00d::1"), 80, lb.ScopeExternal, 0)

	backends1, backends2, backends3, backends4, backends5, backends6 []*lb.LegacyBackend
)

func setupManagerTestSuite(tb testing.TB) *ManagerTestSuite {
	logger := hivetest.Logger(tb)

	m := &ManagerTestSuite{logger: logger}
	serviceIDAlloc.resetLocalID()
	backendIDAlloc.resetLocalID()

	ctx, cancel := context.WithCancel(context.Background())

	m.lbmap = mockmaps.NewLBMockMap()
	m.newServiceMock(ctx, m.lbmap)

	m.svcHealth = healthserver.NewMockHealthHTTPServerFactory(logger)
	m.svc.healthServer = healthserver.WithHealthHTTPServerFactory(logger, m.svcHealth)

	m.prevOptionSessionAffinity = option.Config.EnableSessionAffinity
	option.Config.EnableSessionAffinity = true

	m.prevOptionLBSourceRanges = option.Config.EnableSVCSourceRangeCheck
	option.Config.EnableSVCSourceRangeCheck = true

	m.prevOptionNPAlgo = option.Config.NodePortAlg
	m.prevOptionDPMode = option.Config.DatapathMode
	m.prevOptionExternalClusterIP = option.Config.ExternalClusterIP

	option.Config.EnableInternalTrafficPolicy = true

	m.ipv6 = option.Config.EnableIPv6
	backends1 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080),
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080),
	}
	backends2 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080),
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080),
	}
	backends3 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("fd00::2"), 8080),
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("fd00::3"), 8080),
	}
	backends4 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.4"), 8080),
	}
	backends5 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.5"), 8080),
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.6"), 8080),
	}
	backends6 = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.7"), 8080),
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
		cancel()
	})

	return m
}

func (m *ManagerTestSuite) newServiceMock(ctx context.Context, lbmap datapathTypes.LBMap) {
	m.svc = newService(m.logger, &FakeMonitorAgent{}, lbmap, nil, nil, true, option.Config)
	m.svc.backendConnectionHandler = testsockets.NewMockSockets(make([]*testsockets.MockSocket, 0))
	health, _ := cell.NewSimpleHealth()
	go m.svc.handleHealthCheckEvent(ctx, health)
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
	p := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends3,
		Type:                  lb.SVCTypeNodePort,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	created, id1, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNat46, m.svc.svcByID[id1].svcNatPolicy)

	// Should delete both backends of service
	p.Backends = nil
	created, id2, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, id1, id2)
	require.Empty(t, m.lbmap.ServiceByID[uint16(id2)].Backends)
	require.Empty(t, m.lbmap.BackendByID)
	require.Equal(t, "svc1", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNone, m.svc.svcByID[id2].svcNatPolicy)

	// Should delete the remaining service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, m.lbmap.ServiceByID)
	require.Empty(t, m.lbmap.BackendByID)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService64(t *testing.T) {
	// Should create a new v6 service with two v4 backends
	p := &lb.LegacySVC{
		Frontend:              frontend3,
		Backends:              backends1,
		Type:                  lb.SVCTypeNodePort,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	created, id1, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNat64, m.svc.svcByID[id1].svcNatPolicy)

	// Should delete both backends of service
	p.Backends = nil
	created, id2, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, id1, id2)
	require.Empty(t, m.lbmap.ServiceByID[uint16(id2)].Backends)
	require.Empty(t, m.lbmap.BackendByID)
	require.Equal(t, "svc1", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id2].svcName.Namespace)
	require.Equal(t, lb.SVCNatPolicyNone, m.svc.svcByID[id2].svcNatPolicy)

	// Should delete the remaining service
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, m.lbmap.ServiceByID)
	require.Empty(t, m.lbmap.BackendByID)
}

func (m *ManagerTestSuite) testUpsertAndDeleteService(t *testing.T) {
	// Should create a new service with two backends and session affinity
	p := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	created, id1, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.True(t, m.svc.svcByID[id1].sessionAffinity)
	require.Equal(t, uint32(100), m.svc.svcByID[id1].sessionAffinityTimeoutSec)
	require.True(t, m.lbmap.ServiceByID[uint16(id1)].SessionAffinity)
	require.Equal(t, uint32(100), m.lbmap.ServiceByID[uint16(id1)].SessionAffinityTimeoutSec)
	require.Len(t, m.lbmap.AffinityMatch[uint16(id1)], 2)
	for bID := range m.lbmap.BackendByID {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][bID])
	}

	// Should remove session affinity
	p.SessionAffinity = false
	created, id1, err = m.svc.UpsertService(p)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Empty(t, m.lbmap.AffinityMatch[uint16(id1)])
	require.False(t, m.svc.svcByID[id1].sessionAffinity)
	require.False(t, m.lbmap.ServiceByID[uint16(id1)].SessionAffinity)
	// TODO(brb) test that backends are the same
	// TODO(brb) check that .backends =~ .backendsByHash

	// Should remove one backend and enable session affinity
	p.Backends = backends1[0:1]
	p.SessionAffinity = true
	p.SessionAffinityTimeoutSec = 200
	created, id1, err = m.svc.UpsertService(p)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 1)
	require.Len(t, m.lbmap.BackendByID, 1)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.True(t, m.svc.svcByID[id1].sessionAffinity)
	require.Equal(t, uint32(200), m.svc.svcByID[id1].sessionAffinityTimeoutSec)
	require.Len(t, m.lbmap.AffinityMatch[uint16(id1)], 1)
	for bID := range m.lbmap.BackendByID {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][bID])
	}

	// Should add another service
	require.NoError(t, err)
	cidr1, err := cidr.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	cidr2, err := cidr.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)
	p2 := &lb.LegacySVC{
		Frontend:                  frontend2,
		Backends:                  backends1,
		Type:                      lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      lb.ServiceName{Name: "svc2", Namespace: "ns2"},
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	created, id2, err := m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(2), id2)
	require.Len(t, m.lbmap.ServiceByID[uint16(id2)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc2", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns2", m.svc.svcByID[id2].svcName.Namespace)
	require.Len(t, m.lbmap.AffinityMatch[uint16(id2)], 2)
	require.Len(t, m.lbmap.SourceRanges[uint16(id2)], 2)

	// Should add IPv6 service only if IPv6 is enabled
	require.NoError(t, err)
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	require.NoError(t, err)
	p3 := &lb.LegacySVC{
		Frontend:                  frontend3,
		Backends:                  backends3,
		Type:                      lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      lb.ServiceName{Name: "svc3", Namespace: "ns3"},
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	created, id3, err := m.svc.UpsertService(p3)
	if option.Config.EnableIPv6 {
		require.NoError(t, err)
		require.True(t, created)
		require.Equal(t, lb.ID(3), id3)
		require.Len(t, m.lbmap.ServiceByID[uint16(id3)].Backends, 2)
		require.Len(t, m.lbmap.BackendByID, 4)
		require.Equal(t, "svc3", m.svc.svcByID[id3].svcName.Name)
		require.Equal(t, "ns3", m.svc.svcByID[id3].svcName.Namespace)
		require.Len(t, m.lbmap.AffinityMatch[uint16(id3)], 2)
		require.Len(t, m.lbmap.SourceRanges[uint16(id3)], 1)

		// Should remove the IPv6 service
		found, err := m.svc.DeleteServiceByID(lb.ServiceID(id3))
		require.NoError(t, err)
		require.True(t, found)
	} else {
		require.ErrorContains(t, err, "Unable to upsert service")
		require.ErrorContains(t, err, "as IPv6 is disabled")
		require.False(t, created)
	}
	require.Len(t, m.lbmap.ServiceByID, 2)
	require.Len(t, m.lbmap.BackendByID, 2)

	// Should remove the service and the backend, but keep another service and
	// its backends. Also, should remove the affinity match.
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.NoError(t, err)
	require.True(t, found)
	require.Len(t, m.lbmap.ServiceByID, 1)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Empty(t, m.lbmap.AffinityMatch[uint16(id1)])

	// Should delete both backends of service
	p2.Backends = nil
	p2.LoadBalancerSourceRanges = []*cidr.CIDR{cidr2}
	created, id2, err = m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(2), id2)
	require.Empty(t, m.lbmap.ServiceByID[uint16(id2)].Backends)
	require.Empty(t, m.lbmap.BackendByID)
	require.Equal(t, "svc2", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns2", m.svc.svcByID[id2].svcName.Namespace)
	require.Empty(t, m.lbmap.AffinityMatch[uint16(id2)])
	require.Len(t, m.lbmap.SourceRanges[uint16(id2)], 1)

	// Should delete the remaining service
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, m.lbmap.ServiceByID)
	require.Empty(t, m.lbmap.BackendByID)

	// Should ignore the source range if it does not match FE's ip family
	cidr1, err = cidr.ParseCIDR("fd00::/8")
	require.NoError(t, err)
	cidr2, err = cidr.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)

	p4 := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		Name:                      lb.ServiceName{Name: "svc3", Namespace: "ns3"},
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	created, id4, err := m.svc.UpsertService(p4)
	require.True(t, created)
	require.NoError(t, err)
	require.Len(t, m.lbmap.SourceRanges[uint16(id4)], 1)
}

func TestRestoreServices(t *testing.T) {
	m := setupManagerTestSuite(t)

	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends1,
		Type:                  lb.SVCTypeNodePort,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, id1, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	cidr1, err := cidr.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)
	cidr2, err := cidr.ParseCIDR("192.168.1.0/24")
	require.NoError(t, err)
	p2 := &lb.LegacySVC{
		Frontend:                  frontend2,
		Backends:                  backends2,
		Type:                      lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 200,
		LoadBalancerSourceRanges:  []*cidr.CIDR{cidr1, cidr2},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	_, id2, err := m.svc.UpsertService(p2)
	require.NoError(t, err)

	// Restart service, but keep the lbmap to restore services from
	option.Config.NodePortAlg = option.NodePortAlgMaglev
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)

	ctx := t.Context()

	m.newServiceMock(ctx, lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	require.NoError(t, err)

	// Backends have been restored
	require.Len(t, m.svc.backendByHash, 3)
	backends := append(backends1, backends2...)
	for _, b := range backends {
		_, found := m.svc.backendByHash[b.Hash()]
		require.True(t, found)
	}

	// Services have been restored too
	require.Len(t, m.svc.svcByID, 2)
	require.Equal(t, lbmap.ServiceByID[uint16(id1)].Frontend, m.svc.svcByID[id1].frontend)
	require.Equal(t, lbmap.ServiceByID[uint16(id1)].Backends, m.svc.svcByID[id1].backends)
	require.Equal(t, lbmap.ServiceByID[uint16(id2)].Frontend, m.svc.svcByID[id2].frontend)
	require.Equal(t, lbmap.ServiceByID[uint16(id2)].Backends, m.svc.svcByID[id2].backends)

	// Session affinity too
	require.False(t, m.svc.svcByID[id1].sessionAffinity)
	require.True(t, m.svc.svcByID[id2].sessionAffinity)
	require.Equal(t, uint32(200), m.svc.svcByID[id2].sessionAffinityTimeoutSec)

	// LoadBalancer source ranges too
	require.Len(t, m.svc.svcByID[id2].loadBalancerSourceRanges, 2)
	for _, cidr := range []*cidr.CIDR{cidr1, cidr2} {
		found := false
		for _, c := range m.svc.svcByID[id2].loadBalancerSourceRanges {
			if c.String() == cidr.String() {
				found = true
				break
			}
		}
		require.True(t, found)
	}

	// Maglev lookup table too
	require.Equal(t, len(backends1), m.lbmap.DummyMaglevTable[uint16(id1)])
	require.Equal(t, len(backends2), m.lbmap.DummyMaglevTable[uint16(id2)])
}

func TestSyncWithK8sFinished(t *testing.T) {
	m := setupManagerTestSuite(t)

	p1 := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends1,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 300,
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	_, id1, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	p2 := &lb.LegacySVC{
		Frontend:              frontend2,
		Backends:              backends2,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc2", Namespace: "ns2"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, _, err = m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.Len(t, m.svc.svcByID, 2)
	require.Len(t, m.lbmap.AffinityMatch[uint16(id1)], 2)

	// Restart service, but keep the lbmap to restore services from
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)

	ctx := t.Context()

	m.newServiceMock(ctx, lbmap)

	err = m.svc.RestoreServices()
	require.NoError(t, err)
	require.Len(t, m.svc.svcByID, 2)

	// Imitate a situation where svc1 was deleted while we were down.
	// In real life, the following upsert is called by k8s_watcher during
	// the sync period of the cilium-agent's k8s service cache which happens
	// during the initialization of cilium-agent. P2 svc updated affinity is synced.
	p2.SessionAffinity = true
	p2.SessionAffinityTimeoutSec = 100
	_, id2, err := m.svc.UpsertService(p2)
	require.NoError(t, err)

	// Add non-existing affinity matches
	lbmap.AddAffinityMatch(20, 300)
	lbmap.AddAffinityMatch(20, 301)
	lbmap.AddAffinityMatch(uint16(id1), 302)
	lbmap.AddAffinityMatch(uint16(id2), 305)

	// cilium-agent finished the initialization, and thus SyncWithK8sFinished
	// is called
	stale, err := m.svc.SyncWithK8sFinished(false, nil)
	require.Nil(t, stale)
	require.NoError(t, err)

	// svc1 should be removed from cilium while svc2 is synced
	require.Len(t, m.svc.svcByID, 1)
	_, found := m.svc.svcByID[id2]
	require.True(t, found)
	_, found = m.svc.svcByID[id1]
	require.False(t, found)
	require.Equal(t, "svc2", m.svc.svcByID[id2].svcName.Name)
	require.Equal(t, "ns2", m.svc.svcByID[id2].svcName.Namespace)
	require.Len(t, m.lbmap.AffinityMatch, 1)
	// Check that the non-existing affinity matches were removed
	matches, _ := lbmap.DumpAffinityMatches()
	require.Len(t, matches, 1) // id2 svc has updated session affinity
	require.Len(t, matches[uint16(id2)], 2)
	for _, b := range lbmap.ServiceByID[uint16(id2)].Backends {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id2)][b.ID])
	}
}

func TestRestoreServiceWithStaleBackends(t *testing.T) {
	backendAddrs := []string{"10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5"}
	finalBackendAddrs := []string{"10.0.0.2", "10.0.0.3", "10.0.0.5"}

	service := func(ns, name, frontend string, backends ...string) *lb.LegacySVC {
		var bes []*lb.LegacyBackend
		for _, backend := range backends {
			bes = append(bes, lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster(backend), 8080))
		}

		return &lb.LegacySVC{
			Frontend:         *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster(frontend), 80, lb.ScopeExternal, 0),
			Backends:         bes,
			Type:             lb.SVCTypeClusterIP,
			ExtTrafficPolicy: lb.SVCTrafficPolicyCluster,
			IntTrafficPolicy: lb.SVCTrafficPolicyCluster,
			Name:             lb.ServiceName{Name: name, Namespace: ns},
		}
	}

	toBackendAddrs := func(backends []*lb.LegacyBackend) (addrs []string) {
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
			logger := hivetest.Logger(t)
			svc := newService(logger, &FakeMonitorAgent{}, lbmap, nil, nil, true, option.Config)

			_, id1, err := svc.upsertService(service("foo", "bar", "172.16.0.1", backendAddrs...))
			require.NoError(t, err, "Failed to upsert service")

			require.Contains(t, lbmap.ServiceByID, uint16(id1), "lbmap not populated correctly")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "lbmap not populated correctly")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(slices.Collect(maps.Values(lbmap.BackendByID))), "lbmap not populated correctly")

			// Recreate the Service structure, but keep the lbmap to restore services from
			svc = newService(logger, &FakeMonitorAgent{}, lbmap, nil, nil, true, option.Config)
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
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(slices.Collect(maps.Values(lbmap.BackendByID))), "lbmap incorrectly modified")

			// Let's do it once more
			_, id1ter, err := svc.upsertService(service("foo", "bar", "172.16.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"))
			require.NoError(t, err, "Failed to upsert service")
			require.Equal(t, id1, id1ter, "Service ID changed unexpectedly")

			// No backend should have been removed yet
			require.Contains(t, lbmap.ServiceByID, uint16(id1), "lbmap incorrectly modified")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "lbmap incorrectly modified")
			require.ElementsMatch(t, backendAddrs, toBackendAddrs(slices.Collect(maps.Values(lbmap.BackendByID))), "lbmap incorrectly modified")

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
				require.ElementsMatch(t, backendAddrs, toBackendAddrs(slices.Collect(maps.Values(lbmap.BackendByID))), "stale backends should not have been removed from lbmap")
			} else {
				require.ElementsMatch(t, stale, []k8s.ServiceID{svcID})

				// Trigger a new upsertion: this mimics what would eventually happen when calling ServiceCache.EnsureService()
				_, _, err := svc.upsertService(service("foo", "bar", "172.16.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.5"))
				require.NoError(t, err, "Failed to upsert service")

				require.ElementsMatch(t, finalBackendAddrs, toBackendAddrs(lbmap.ServiceByID[uint16(id1)].Backends), "stale backends not correctly removed from lbmap")
				require.ElementsMatch(t, finalBackendAddrs, toBackendAddrs(slices.Collect(maps.Values(lbmap.BackendByID))), "stale backends not correctly removed from lbmap")
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
	localBackend1 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080)
	localBackend2 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080)
	localTerminatingBackend3 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()
	localBackend2.NodeName = nodeTypes.GetName()
	localTerminatingBackend3.NodeName = nodeTypes.GetName()
	localActiveBackends := []*lb.LegacyBackend{localBackend1, localBackend2}

	// Create three remote backends
	remoteBackend1 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080)
	remoteBackend2 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.4"), 8080)
	remoteBackend3 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.5"), 8080)
	remoteBackend1.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend2.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend3.NodeName = "not-" + nodeTypes.GetName()
	remoteBackends := []*lb.LegacyBackend{remoteBackend1, remoteBackend2, remoteBackend3}

	allBackends := []*lb.LegacyBackend{localBackend1, localBackend2, localTerminatingBackend3, remoteBackend1, remoteBackend2, remoteBackend3}

	// Insert svc1 as type LoadBalancer with some local backends
	p1 := &lb.LegacySVC{
		Frontend:              loadBalancerIP,
		Backends:              allBackends,
		Type:                  lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort:   32001,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, id1, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)

	p1.Backends[2].State = lb.BackendStateTerminating
	_, _, _ = m.svc.UpsertService(p1)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Insert the ClusterIP frontend of svc1
	p2 := &lb.LegacySVC{
		Frontend:              clusterIP,
		Backends:              allBackends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort:   32001,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, id2, err := m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Update the HealthCheckNodePort for svc1
	p1.HealthCheckNodePort = 32000
	new, _, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.False(t, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32000).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32000).Service.Namespace)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32000).LocalEndpoints)
	require.Nil(t, m.svcHealth.ServiceByPort(32001))

	// Update the externalTrafficPolicy for svc1
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	p1.HealthCheckNodePort = 0
	new, _, err = m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.False(t, new)
	require.Nil(t, m.svcHealth.ServiceByPort(32000))
	require.Nil(t, m.svcHealth.ServiceByPort(32001))

	// Restore the original version of svc1
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.HealthCheckNodePort = 32001
	new, _, err = m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.False(t, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, len(localActiveBackends), m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Upsert svc1 of type LoadBalancer with only remote backends
	p1.Backends = remoteBackends
	new, _, err = m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.False(t, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, 0, m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Upsert svc1 of type ClusterIP with only remote backends
	p2.Backends = remoteBackends
	new, _, err = m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.False(t, new)
	require.Equal(t, "svc1", m.svcHealth.ServiceByPort(32001).Service.Name)
	require.Equal(t, "ns1", m.svcHealth.ServiceByPort(32001).Service.Namespace)
	require.Equal(t, 0, m.svcHealth.ServiceByPort(32001).LocalEndpoints)

	// Delete svc1 of type LoadBalancer
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.NoError(t, err)
	require.True(t, found)
	require.Nil(t, m.svcHealth.ServiceByPort(32001))

	// Delete svc1 of type ClusterIP
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	require.NoError(t, err)
	require.True(t, found)
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

	localBackend1 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()

	allBackends := []*lb.LegacyBackend{localBackend1}

	// Insert svc1 as type LoadBalancer with some local backends
	p1 := &lb.LegacySVC{
		Frontend:              loadBalancerIP,
		Backends:              allBackends,
		Type:                  lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort:   32001,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	svc, _, _, _, _ := m.svc.createSVCInfoIfNotExist(p1)
	err := m.svc.upsertNodePortHealthService(svc, mockCollector)

	require.NoError(t, err)
	require.NotEmpty(t, svc.healthcheckFrontendHash)
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
	require.NoError(t, err)
	require.Empty(t, svc.healthcheckFrontendHash)
	require.Nil(t, m.svc.svcByHash[oldHealthHash])

	// Restore the original version of svc1
	svc.frontend.Scope = lb.ScopeInternal
	svc.svcHealthCheckNodePort = 32001
	err = m.svc.upsertNodePortHealthService(svc, mockCollector)
	require.NoError(t, err)
	require.NotEmpty(t, svc.healthcheckFrontendHash)
	require.Equal(t, "svc1-healthCheck", m.svc.svcByHash[svc.healthcheckFrontendHash].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByHash[svc.healthcheckFrontendHash].svcName.Namespace)
	require.Equal(t, svc.svcHealthCheckNodePort, m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.Port)
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.AddrCluster.Addr())
	require.Equal(t, cmtypes.AddrClusterFrom(netip.MustParseAddr("192.0.2.0"), option.Config.ClusterID), m.svc.svcByHash[svc.healthcheckFrontendHash].backends[0].AddrCluster)

	// IPv6 NodePort Backend
	oldHealthHash = svc.healthcheckFrontendHash
	svc.frontend = *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("2001:db8:1::1"), 80, lb.ScopeExternal, 0)
	err = m.svc.upsertNodePortHealthService(svc, mockCollector)
	require.NoError(t, err)
	require.Equal(t, cmtypes.AddrClusterFrom(netip.MustParseAddr("2001:db8::1"), option.Config.ClusterID), m.svc.svcByHash[svc.healthcheckFrontendHash].backends[0].AddrCluster)
	require.Nil(t, m.svc.svcByHash[oldHealthHash])

	var ok bool
	// Delete
	ok, err = m.svc.DeleteService(m.svc.svcByHash[svc.healthcheckFrontendHash].frontend.L3n4Addr)
	require.True(t, ok)
	require.NoError(t, err)

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

	p1 := &lb.LegacySVC{
		Frontend:            frontend1,
		Backends:            backends1,
		Type:                lb.SVCTypeNodePort,
		ExtTrafficPolicy:    lb.SVCTrafficPolicyLocal,
		IntTrafficPolicy:    lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort: 32000,
		ProxyDelegation:     lb.SVCProxyDelegationNone,
	}
	_, id1, err := m.svc.UpsertService(p1)
	require.NoError(t, err)

	// Unset HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 0
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyCluster
	_, _, err = m.svc.UpsertService(p1)
	require.NoError(t, err)

	// Set HealthCheckNodePort for that service
	p1.HealthCheckNodePort = 32000
	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	_, _, err = m.svc.UpsertService(p1)
	require.NoError(t, err)

	// Delete service with active HealthCheckNodePort
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.NoError(t, err)
	require.True(t, found)
}

func TestGetServiceNameByAddr(t *testing.T) {
	m := setupManagerTestSuite(t)

	fe := frontend1.DeepCopy()
	name := "svc1"
	namespace := "ns1"
	hcport := uint16(3)
	p := &lb.LegacySVC{
		Frontend:              *fe,
		Backends:              backends1,
		Type:                  lb.SVCTypeNodePort,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		HealthCheckNodePort:   hcport,
		Name:                  lb.ServiceName{Name: name, Namespace: namespace},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	created, id1, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	fe.ID = id1
	gotNamespace, gotName, ok := m.svc.GetServiceNameByAddr(frontend1.L3n4Addr)
	require.Equal(t, namespace, gotNamespace)
	require.Equal(t, name, gotName)
	require.True(t, ok)
	_, _, ok = m.svc.GetServiceNameByAddr(frontend2.L3n4Addr)
	require.False(t, ok)
}

func TestLocalRedirectLocalBackendSelection(t *testing.T) {
	m := setupManagerTestSuite(t)

	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	localBackends := []*lb.LegacyBackend{localBackend}
	// Create two remote backends.
	remoteBackends := make([]*lb.LegacyBackend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.LegacyBackend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	// Create a service entry of type Local Redirect.
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              allBackends,
		Type:                  lb.SVCTypeLocalRedirect,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	// Insert the service entry of type Local Redirect.
	created, id, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.True(t, ok)
	require.Equal(t, "ns1", svc.svcName.Namespace)
	require.Equal(t, "svc1", svc.svcName.Name)
	// Only node-local backends are selected
	require.Len(t, svc.backends, len(localBackends))

	svcFromLbMap, ok := m.lbmap.ServiceByID[uint16(id)]
	require.True(t, ok)
	require.Len(t, svcFromLbMap.Backends, len(svc.backends))
}

// Local redirect service should be able to override a ClusterIP service with same
// frontend, but reverse should produce an error. Also, it should not override
// any other type besides itself or clusterIP type.
func TestLocalRedirectServiceOverride(t *testing.T) {
	m := setupManagerTestSuite(t)

	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	localBackends := []*lb.LegacyBackend{localBackend}
	// Create two remote backends.
	remoteBackends := make([]*lb.LegacyBackend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.LegacyBackend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              allBackends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	// Insert the service entry of type ClusterIP.
	created, id, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)

	// Insert the service entry of type Local Redirect.
	p1.Type = lb.SVCTypeLocalRedirect
	created, id, err = m.svc.UpsertService(p1)

	// Local redirect service should override the ClusterIP service with node-local backends.
	require.NoError(t, err)
	require.False(t, created)
	require.NotEqual(t, lb.ID(0), id)
	svc = m.svc.svcByID[id]
	// Only node-local backends are selected.
	require.Len(t, svc.backends, len(localBackends))

	// Insert the service entry of type ClusterIP.
	p1.Type = lb.SVCTypeClusterIP
	created, _, err = m.svc.UpsertService(p1)

	require.Error(t, err)
	require.False(t, created)

	p2 := &lb.LegacySVC{
		Frontend:              frontend2,
		Backends:              allBackends,
		Type:                  lb.SVCTypeNodePort,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc2", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	// Insert the service entry of type NodePort.
	created, id, err = m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)

	// Insert the service entry of type Local Redirect.
	p2.Type = lb.SVCTypeLocalRedirect
	created, _, err = m.svc.UpsertService(p2)

	// Local redirect service should not override the NodePort service.
	require.Error(t, err)
	require.False(t, created)
}

// Tests whether upsert service handles terminating backends, whereby terminating
// backends are not added to the service map, but are added to the backends and
// affinity maps.
func TestUpsertServiceWithTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends4, backends1...)
	p := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}

	created, id1, err := m.svc.UpsertService(p)

	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	p.Backends[0].State = lb.BackendStateTerminating

	_, _, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Equal(t, len(backends1), m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	// Sorted active backends by ID first followed by non-active
	require.Equal(t, lb.BackendID(2), m.lbmap.ServiceByID[uint16(id1)].Backends[0].ID)
	require.Equal(t, lb.BackendID(3), m.lbmap.ServiceByID[uint16(id1)].Backends[1].ID)
	require.Equal(t, lb.BackendID(1), m.lbmap.ServiceByID[uint16(id1)].Backends[2].ID)
	require.Len(t, m.lbmap.BackendByID, 3)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Len(t, m.lbmap.AffinityMatch[uint16(id1)], 3)
	for bID := range m.lbmap.BackendByID {
		require.Equal(t, struct{}{}, m.lbmap.AffinityMatch[uint16(id1)][bID])
	}
	require.Equal(t, len(backends1), m.lbmap.DummyMaglevTable[uint16(id1)])

	// Delete terminating backends.
	p.Backends = []*lb.LegacyBackend{}

	created, id1, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Empty(t, m.lbmap.ServiceByID[uint16(id1)].Backends)
	require.Empty(t, m.lbmap.BackendByID)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Empty(t, m.lbmap.AffinityMatch[uint16(id1)])
}

// TestUpsertServiceWithOnlyTerminatingBackends tests that a terminating backend is still
// used if there are not active backends.
func TestUpsertServiceWithOnlyTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := backends1 // There are 2 backends
	p := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}

	created, id1, err := m.svc.UpsertService(p)

	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Equal(t, 2, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)

	// The terminating backend should not be considered
	p.Backends[1].State = lb.BackendStateTerminating

	created, id1, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	// Delete terminating backends.
	p.Backends = p.Backends[:1]

	created, id1, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 1)
	require.Len(t, m.lbmap.BackendByID, 1)
	require.Len(t, m.lbmap.AffinityMatch[uint16(id1)], 1)

	// The terminating backend should be considered since there are no more active
	p.Backends[0].State = lb.BackendStateTerminating

	created, id1, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 1)
	require.Len(t, m.lbmap.BackendByID, 1)
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	// Delete terminating backends.
	p.Backends = []*lb.LegacyBackend{}

	created, id1, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.False(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Empty(t, m.lbmap.ServiceByID[uint16(id1)].Backends)
	require.Empty(t, m.lbmap.BackendByID)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Empty(t, m.lbmap.AffinityMatch[uint16(id1)])
}

// Tests whether upsert service provisions the Maglev LUT for ClusterIP,
// if ExternalClusterIP is true
func TestUpsertServiceWithExternalClusterIP(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	option.Config.ExternalClusterIP = true
	backends := make([]*lb.LegacyBackend, 0, len(backends1))
	for _, b := range backends1 {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	p := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	created, id1, err := m.svc.UpsertService(p)

	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, len(backends), m.lbmap.DummyMaglevTable[uint16(id1)])
}

// Tests whether upsert service doesn't provision the Maglev LUT for ClusterIP,
// if ExternalClusterIP is false
func TestUpsertServiceWithOutExternalClusterIP(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	p := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends1,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	created, id1, err := m.svc.UpsertService(p)

	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, "svc1", m.svc.svcByID[id1].svcName.Name)
	require.Equal(t, "ns1", m.svc.svcByID[id1].svcName.Namespace)
	require.Equal(t, 0, m.lbmap.DummyMaglevTable[uint16(id1)])
}

// Tests terminating backend entries are not removed after service restore.
func TestRestoreServiceWithTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	backends := append(backends4, backends1...)
	p := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name:                      lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}

	created, id1, err := m.svc.UpsertService(p)

	t.Log(m.lbmap.ServiceByID[0])
	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	p.Backends[0].State = lb.BackendStateTerminating

	_, _, err = m.svc.UpsertService(p)

	require.NoError(t, err)

	// Simulate agent restart.
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)

	ctx := t.Context()

	m.newServiceMock(ctx, lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	require.NoError(t, err)

	// Backends including terminating ones have been restored
	require.Len(t, m.svc.backendByHash, 3)
	for _, b := range backends1 {
		_, found := m.svc.backendByHash[b.Hash()]
		require.True(t, found)
	}

	// Affinity matches including terminating ones were restored
	matches, _ := m.lbmap.DumpAffinityMatches()
	require.Len(t, matches, 1)
	require.Len(t, matches[uint16(id1)], 3)
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
	remoteBackends := make([]*lb.LegacyBackend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.LegacyBackend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              allBackends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	// Insert the service entry of type ClusterIP.
	created, id, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// registering redirection with proxy port 0 should result in an error
	echoOtherNode := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	resource1 := L7LBResourceName{Name: "testOwner1", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource1, 0, nil)
	require.Error(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// Registering with redirection stores the proxy port.
	resource2 := L7LBResourceName{Name: "testOwner2", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource2, 9090, nil)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// registering redirection for a Service that already has a redirect registration
	// should result in an error.
	resource3 := L7LBResourceName{Name: "testOwner3", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource3, 10000, nil)
	require.Error(t, err)

	// Remove with an unregistered owner name does not remove
	resource4 := L7LBResourceName{Name: "testOwner4", Namespace: "cilium-test"}
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource4)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// Removing registration without redirection does not remove the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource1)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// removing the registration with redirection removes the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource2)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)
}

// l7 load balancer service with ports should only override the given frontend ports.
func TestL7LoadBalancerServiceOverrideWithPorts(t *testing.T) {
	m := setupManagerTestSuite(t)

	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	// Create two remote backends.
	remoteBackends := make([]*lb.LegacyBackend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.LegacyBackend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              allBackends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	// Insert the service entry of type ClusterIP.
	created, id, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id)

	svc, ok := m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	echoOtherNode := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	resource1 := L7LBResourceName{Name: "testOwner1", Namespace: "cilium-test"}

	// Registering with redirection stores the proxy port.
	resource2 := L7LBResourceName{Name: "testOwner2", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource2, 9090, []uint16{80})
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// removing the registration with redirection removes the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource2)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// Registering with non-matching port does not store the proxy port.
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource2, 9090, []uint16{8080})
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	// registering redirection for a Service that already has a redirect registration
	// should result in an error.
	resource3 := L7LBResourceName{Name: "testOwner3", Namespace: "cilium-test"}
	err = m.svc.RegisterL7LBServiceRedirect(echoOtherNode, resource3, 10000, nil)
	require.Error(t, err)

	// Adding a matching frontend gets proxy port

	p2 := &lb.LegacySVC{
		Frontend:              frontend1_8080,
		Backends:              allBackends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	// Insert the service entry of type ClusterIP.
	created, id2, err := m.svc.UpsertService(p2)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id2)

	svc, ok = m.svc.svcByID[id2]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// Remove with an unregistered owner name does not remove
	resource4 := L7LBResourceName{Name: "testOwner4", Namespace: "cilium-test"}
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource4)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id2]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// Removing registration without redirection does not remove the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource1)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id2]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(9090), svc.l7LBProxyPort)

	// removing the registration with redirection removes the proxy port
	err = m.svc.DeregisterL7LBServiceRedirect(echoOtherNode, resource2)
	require.NoError(t, err)

	svc, ok = m.svc.svcByID[id]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)

	svc, ok = m.svc.svcByID[id2]
	require.Len(t, svc.backends, len(allBackends))
	require.True(t, ok)
	require.Equal(t, uint16(0), svc.l7LBProxyPort)
}

// L7 LB proxies should be able to register callback based backend sync registration
func TestL7LoadBalancerServiceBackendSyncRegistration(t *testing.T) {
	m := setupManagerTestSuite(t)

	// Create a node-local backend.
	localBackend := backends1[0]
	localBackend.NodeName = nodeTypes.GetName()
	// Create two remote backends.
	remoteBackends := make([]*lb.LegacyBackend, 0, len(backends2))
	for _, backend := range backends2 {
		backend.NodeName = "not-" + nodeTypes.GetName()
		remoteBackends = append(remoteBackends, backend)
	}
	allBackends := make([]*lb.LegacyBackend, 0, 1+len(remoteBackends))
	allBackends = append(allBackends, localBackend)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              allBackends,
		Type:                  lb.SVCTypeClusterIP,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		Name:                  lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	// Insert the service entry of type ClusterIP.
	created, id, err := m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.True(t, created)
	require.NotEqual(t, lb.ID(0), id)

	// Registering L7LB backend sync should register backend sync and trigger an initial synchronization
	service := lb.ServiceName{Name: "echo-other-node", Namespace: "cilium-test"}
	backendSyncer := &FakeBackendSyncer{}
	err = m.svc.RegisterL7LBServiceBackendSync(service, backendSyncer)
	require.NoError(t, err)

	require.Len(t, m.svc.l7lbSvcs, 1)
	require.Len(t, m.svc.l7lbSvcs[service].backendSyncRegistrations, 1)
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 1, backendSyncer.nrOfSyncs)

	// Re-Registering L7LB backend sync should keep the existing registration and trigger an implicit re-synchronization
	err = m.svc.RegisterL7LBServiceBackendSync(service, backendSyncer)
	require.NoError(t, err)

	require.Len(t, m.svc.l7lbSvcs, 1)
	require.Len(t, m.svc.l7lbSvcs[service].backendSyncRegistrations, 1)
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 2, backendSyncer.nrOfSyncs)

	// Upserting a service should trigger a sync for the registered backend sync registrations
	allBackends = append(allBackends, backends4...)
	p1.Backends = allBackends
	created, id, err = m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.False(t, created)
	require.NotEqual(t, lb.ID(0), id)

	require.Len(t, m.svc.l7lbSvcs, 1)
	require.Len(t, m.svc.l7lbSvcs[service].backendSyncRegistrations, 1)
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 3, backendSyncer.nrOfSyncs)

	// De-registering a backend sync should delete the backend sync registration
	err = m.svc.DeregisterL7LBServiceBackendSync(service, backendSyncer)
	require.NoError(t, err)

	require.Empty(t, m.svc.l7lbSvcs)
	require.Equal(t, len(allBackends), backendSyncer.nrOfBackends)
	require.Equal(t, 3, backendSyncer.nrOfSyncs)
}

// Tests that services with the given backends are updated with the new backend
// state.
func TestUpdateBackendsState(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.LegacyBackend, 0, len(backends1))
	for _, b := range backends1 {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	p2 := &lb.LegacySVC{
		Frontend:              frontend2,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc2", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	_, id1, err1 := m.svc.UpsertService(p1)
	_, id2, err2 := m.svc.UpsertService(p2)

	require.NoError(t, err1)
	require.NoError(t, err2)
	require.Equal(t, lb.ID(1), id1)
	require.Equal(t, lb.ID(2), id2)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[1].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[1].State)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Len(t, m.lbmap.ServiceByID[uint16(id2)].Backends, len(backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id2)])
	require.Len(t, m.lbmap.BackendByID, len(backends))
	// Backend states are persisted in the map.
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[1].State)
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[2].State)

	// Update the state for one of the backends.
	updated := []*lb.LegacyBackend{backends[0]}
	updated[0].State = lb.BackendStateQuarantined

	svcs, err := m.svc.UpdateBackendsState(updated)

	require.NoError(t, err)
	// Both the services are updated with the update backend state.
	require.Equal(t, lb.BackendStateQuarantined, m.svc.svcByID[id1].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[1].State)
	require.Equal(t, lb.BackendStateQuarantined, m.svc.svcByID[id2].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[1].State)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Len(t, m.lbmap.ServiceByID[uint16(id2)].Backends, len(backends))
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id2)])
	require.Len(t, m.lbmap.BackendByID, len(backends))
	require.ElementsMatch(t, svcs, []lb.L3n4Addr{p1.Frontend.L3n4Addr, p2.Frontend.L3n4Addr})
	// Updated backend states are persisted in the map.
	require.Equal(t, lb.BackendStateQuarantined, m.lbmap.BackendByID[1].State)
	require.Equal(t, lb.BackendStateActive, m.lbmap.BackendByID[2].State)

	// Update the state again.
	updated = []*lb.LegacyBackend{backends[0]}
	updated[0].State = lb.BackendStateActive

	svcs, err = m.svc.UpdateBackendsState(updated)

	require.NoError(t, err)
	// Both the services are updated with the update backend state.
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[1].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id2].backends[1].State)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Len(t, m.lbmap.ServiceByID[uint16(id2)].Backends, len(backends))
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	require.Equal(t, len(backends), m.lbmap.SvcActiveBackendsCount[uint16(id2)])
	require.Len(t, m.lbmap.BackendByID, len(backends))
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
	backends := make([]*lb.LegacyBackend, 0, len(bs))
	for _, b := range bs {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	backends[2].State = lb.BackendStateActive

	p1 := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
	}
	created, id1, err := m.svc.UpsertService(p1)

	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Len(t, m.svc.backendByHash, len(backends))

	// Update backend states.
	var updates []*lb.LegacyBackend
	backends[0].State = lb.BackendStateQuarantined
	backends[1].State = lb.BackendStateMaintenance
	updates = append(updates, backends[0], backends[1])
	_, err = m.svc.UpdateBackendsState(updates)

	require.NoError(t, err)

	// Simulate agent restart.
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)

	ctx := t.Context()

	m.newServiceMock(ctx, lbmap)

	// Restore services from lbmap
	err = m.svc.RestoreServices()
	require.NoError(t, err)

	// Check that backends along with their states have been restored
	require.Len(t, m.svc.backendByHash, len(backends))
	statesMatched := 0
	for _, b := range backends {
		be, found := m.svc.backendByHash[b.Hash()]
		require.True(t, found)
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

	p := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
		Name: lb.ServiceName{
			Name:      "svc1",
			Namespace: "ns1",
		},
	}

	created, id1, err := m.svc.UpsertService(p)

	require.NoError(t, err)
	require.True(t, created)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 3)
	require.Len(t, m.lbmap.BackendByID, 3)
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

	require.NoError(t, err)
	require.False(t, created)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 3)
	require.Len(t, m.lbmap.BackendByID, 3)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByID[id1].backendByHash[hash2].State)
	require.Equal(t, 1, m.lbmap.DummyMaglevTable[uint16(id1)])

	// Delete backends with weight 0
	p.Backends = backends[:1]

	created, id1, err = m.svc.UpsertService(p)

	require.NoError(t, err)
	require.False(t, created)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 1)
	require.Len(t, m.lbmap.BackendByID, 1)
	require.Equal(t, 1, m.lbmap.DummyMaglevTable[uint16(id1)])
}

func TestUpdateBackendsStateWithBackendSharedAcrossServices(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.NodePortAlg = option.NodePortAlgMaglev
	be := append(backends1, backends4...)
	backends := make([]*lb.LegacyBackend, 0, len(be))
	for _, b := range be {
		backends = append(backends, b.DeepCopy())
	}
	backends[0].State = lb.BackendStateActive
	backends[1].State = lb.BackendStateActive
	backends[2].State = lb.BackendStateMaintenance
	hash0 := backends[0].L3n4Addr.Hash()
	hash1 := backends[1].L3n4Addr.Hash()
	hash2 := backends[2].L3n4Addr.Hash()

	p := &lb.LegacySVC{
		Frontend:                  frontend1,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
		Name: lb.ServiceName{
			Name:      "svc1",
			Namespace: "ns1",
		},
	}
	r := &lb.LegacySVC{
		Frontend:                  frontend2,
		Backends:                  backends,
		Type:                      lb.SVCTypeNodePort,
		ExtTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:          lb.SVCTrafficPolicyCluster,
		LoadBalancerAlgorithm:     lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:           lb.SVCProxyDelegationNone,
		SessionAffinity:           true,
		SessionAffinityTimeoutSec: 100,
		Name: lb.ServiceName{
			Name:      "svc2",
			Namespace: "ns1",
		},
	}
	svcHash2 := r.Frontend.Hash()

	_, _, err := m.svc.UpsertService(p)
	require.NoError(t, err)
	_, _, err = m.svc.UpsertService(r)
	require.NoError(t, err)
	_, id1, err := m.svc.UpsertService(r)

	// Assert expected backend states after consecutive upsert service calls that share the backends.
	require.NoError(t, err)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 3)
	require.Len(t, m.lbmap.BackendByID, 3)
	require.Equal(t, lb.BackendStateActive, m.svc.backendByHash[hash0].State)
	require.Equal(t, lb.BackendStateActive, m.svc.backendByHash[hash1].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.backendByHash[hash2].State)

	backends[1].State = lb.BackendStateMaintenance
	_, err = m.svc.UpdateBackendsState(backends)

	require.NoError(t, err)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.backendByHash[hash1].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByHash[svcHash2].backends[1].State)
	require.Equal(t, lb.BackendStateMaintenance, m.svc.svcByHash[svcHash2].backendByHash[hash1].State)
}

func TestSyncNodePortFrontends(t *testing.T) {
	m := setupManagerTestSuite(t)

	// Add a IPv4 surrogate frontend
	surrogate := &lb.LegacySVC{
		Frontend:              surrogateFE,
		Backends:              backends1,
		Type:                  lb.SVCTypeNodePort,
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, surrID, err := m.svc.UpsertService(surrogate)
	require.NoError(t, err)
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends1,
		Type:                  lb.SVCTypeNodePort,
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, _, err = m.svc.UpsertService(p1)
	require.NoError(t, err)
	require.Len(t, m.svc.svcByID, 2)

	// With no addresses all frontends (except surrogates) should be removed.
	err = m.svc.SyncNodePortFrontends(sets.New[netip.Addr]())
	require.NoError(t, err)

	require.Len(t, m.svc.svcByID, 1)
	_, ok := m.svc.svcByID[surrID]
	require.True(t, ok)

	// With a new frontend addresses services should be re-created.
	nodeAddrs := sets.New(
		frontend1.AddrCluster.Addr(),
		frontend2.AddrCluster.Addr(),
		// IPv6 address should be ignored initially without IPv6 surrogate
		frontend3.AddrCluster.Addr(),
	)
	m.svc.SyncNodePortFrontends(nodeAddrs)
	require.Len(t, m.svc.svcByID, 2+1)

	_, _, found := m.svc.GetServiceNameByAddr(frontend1.L3n4Addr)
	require.True(t, found)
	_, _, found = m.svc.GetServiceNameByAddr(frontend2.L3n4Addr)
	require.True(t, found)

	// Add an IPv6 surrogate
	surrogate = &lb.LegacySVC{
		Frontend:              surrogateFEv6,
		Backends:              backends3,
		Type:                  lb.SVCTypeNodePort,
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	_, _, err = m.svc.UpsertService(surrogate)
	require.NoError(t, err)

	err = m.svc.SyncNodePortFrontends(nodeAddrs)
	require.NoError(t, err)
	require.Len(t, m.svc.svcByID, 3+2)
}

func TestTrafficPolicy(t *testing.T) {
	m := setupManagerTestSuite(t)

	internalIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeInternal, 0)
	externalIP := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.1"), 80, lb.ScopeExternal, 0)

	localBackend1 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080)
	localBackend2 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080)
	localBackend1.NodeName = nodeTypes.GetName()
	localBackend2.NodeName = nodeTypes.GetName()
	localBackends := []*lb.LegacyBackend{localBackend1, localBackend2}

	remoteBackend1 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.3"), 8080)
	remoteBackend2 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.4"), 8080)
	remoteBackend3 := lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.5"), 8080)
	remoteBackend1.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend2.NodeName = "not-" + nodeTypes.GetName()
	remoteBackend3.NodeName = "not-" + nodeTypes.GetName()
	remoteBackends := []*lb.LegacyBackend{remoteBackend1, remoteBackend2, remoteBackend3}

	allBackends := make([]*lb.LegacyBackend, 0, len(remoteBackends)+len(remoteBackends))
	allBackends = append(allBackends, localBackends...)
	allBackends = append(allBackends, remoteBackends...)

	p1 := &lb.LegacySVC{
		Frontend:              internalIP,
		Backends:              allBackends,
		Type:                  lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyLocal,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	created, id1, err := m.svc.UpsertService(p1)
	require.True(t, created)
	require.NoError(t, err)

	p2 := &lb.LegacySVC{
		Frontend:              externalIP,
		Backends:              allBackends,
		Type:                  lb.SVCTypeLoadBalancer,
		ExtTrafficPolicy:      lb.SVCTrafficPolicyCluster,
		IntTrafficPolicy:      lb.SVCTrafficPolicyLocal,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	created, id2, err := m.svc.UpsertService(p2)
	require.True(t, created)
	require.NoError(t, err)

	svcFromLbMap1, ok := m.lbmap.ServiceByID[uint16(id1)]
	require.True(t, ok)
	require.Len(t, svcFromLbMap1.Backends, len(localBackends))

	svcFromLbMap2, ok := m.lbmap.ServiceByID[uint16(id2)]
	require.True(t, ok)
	require.Len(t, svcFromLbMap2.Backends, len(allBackends))

	p1.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p1.IntTrafficPolicy = lb.SVCTrafficPolicyCluster
	created, id3, err := m.svc.UpsertService(p1)
	require.False(t, created)
	require.NoError(t, err)
	require.Equal(t, id1, id3)

	svcFromLbMap3, ok := m.lbmap.ServiceByID[uint16(id1)]
	require.True(t, ok)
	require.Len(t, svcFromLbMap3.Backends, len(allBackends))

	p2.ExtTrafficPolicy = lb.SVCTrafficPolicyLocal
	p2.IntTrafficPolicy = lb.SVCTrafficPolicyCluster
	created, id4, err := m.svc.UpsertService(p2)
	require.False(t, created)
	require.NoError(t, err)
	require.Equal(t, id2, id4)

	svcFromLbMap4, ok := m.lbmap.ServiceByID[uint16(id2)]
	require.True(t, ok)
	require.Len(t, svcFromLbMap4.Backends, len(localBackends))

	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))
	require.NoError(t, err)
	require.True(t, found)
	found, err = m.svc.DeleteServiceByID(lb.ServiceID(id2))
	require.NoError(t, err)
	require.True(t, found)
}

// Tests whether delete service handles non-active backends.
func TestDeleteServiceWithTerminatingBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := backends5
	backends[0].State = lb.BackendStateTerminating
	p := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	created, id1, err := m.svc.UpsertService(p)

	require.NoError(t, err)
	require.True(t, created)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, 2)
	require.Len(t, m.lbmap.BackendByID, 2)
	require.Equal(t, lb.ServiceName{Name: "svc1", Namespace: "ns1"}, m.svc.svcByID[id1].svcName)

	// Delete service.
	found, err := m.svc.DeleteServiceByID(lb.ServiceID(id1))

	require.NoError(t, err)
	require.True(t, found)
	require.Empty(t, m.lbmap.ServiceByID)
	require.Empty(t, m.lbmap.BackendByID)
}

func TestRestoreServicesWithLeakedBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.LegacyBackend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	_, id1, err1 := m.svc.UpsertService(p1)

	require.NoError(t, err1)
	require.Equal(t, lb.ID(1), id1)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	require.Len(t, m.lbmap.BackendByID, len(backends))

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
	require.Len(t, m.lbmap.BackendByID, len(backends)+4)
	lbmap := m.svc.lbmap.(*mockmaps.LBMockMap)
	logger := hivetest.Logger(t)
	m.svc = newService(logger, &FakeMonitorAgent{}, lbmap, nil, nil, true, option.Config)

	// Restore services from lbmap
	err := m.svc.RestoreServices()
	require.NoError(t, err)
	require.Len(t, m.lbmap.ServiceByID[uint16(id1)].Backends, len(backends))
	// Leaked backends should be deleted.
	require.Len(t, m.lbmap.BackendByID, len(backends))
}

// Tests backend connections getting destroyed.
func TestUpsertServiceWithDeletedBackends(t *testing.T) {
	m := setupManagerTestSuite(t)

	option.Config.EnableSocketLB = true
	backends := []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.UDP, cmtypes.MustParseAddrCluster("10.0.0.1"), 8080),
		lb.NewLegacyBackend(0, lb.UDP, cmtypes.MustParseAddrCluster("10.0.0.2"), 8080),
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
	svc := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	key1 := *lbmap.NewSockRevNat4Key(1234, s1.SockID.Destination, s1.SockID.DestinationPort)
	key2 := *lbmap.NewSockRevNat4Key(1235, s2.SockID.Destination, s2.SockID.DestinationPort)
	m.lbmap.SockRevNat4[key1] = lbmap.SockRevNat4Value{}
	m.lbmap.SockRevNat4[key2] = lbmap.SockRevNat4Value{}
	sockets := []*testsockets.MockSocket{&s1, &s2}
	m.svc.backendConnectionHandler = testsockets.NewMockSockets(sockets)

	created, _, err := m.svc.UpsertService(svc)

	require.NoError(t, err)
	require.True(t, created)

	// Delete one of the backends.
	svc = &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              []*lb.LegacyBackend{backends[1]},
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	created, _, err = m.svc.UpsertService(svc)

	require.NoError(t, err)
	require.False(t, created)

	// Only the sockets connected to the deleted backend are destroyed.
	for _, socket := range sockets {
		if socket.Equal(sockets[0]) {
			require.True(t, socket.Destroyed)
		} else {
			require.False(t, socket.Destroyed)
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

func (r *FakeBackendSyncer) Sync(svc *lb.LegacySVC) error {
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

func (f *FakeMonitorAgent) SendEvent(typ int, event any) error {
	return nil
}

func (f *FakeMonitorAgent) State() *models.MonitorStatus {
	return nil
}

func TestHealthCheckCB(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.LegacyBackend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	_, id1, err1 := m.svc.UpsertService(p1)

	require.NoError(t, err1)
	require.Equal(t, id1, lb.ID(1))
	require.Len(t, backends, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Len(t, backends, len(m.lbmap.BackendByID))
	require.Equal(t, lb.BackendStateActive, m.svc.svcByID[id1].backends[0].State)

	be := backends[0]
	m.svc.healthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend1.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateQuarantined,
		})

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Len(ct, backends, len(m.lbmap.BackendByID))
		assert.Equal(ct, lb.BackendStateQuarantined, m.svc.svcByID[id1].backends[0].State)
		assert.Equal(ct, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	}, 3*time.Second, 100*time.Millisecond)
}

func TestHealthCheckInitialSync(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.LegacyBackend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}

	_, _, err := m.svc.UpsertService(p1)
	require.NoError(t, err)

	// Test the Subscribe call replays the current state
	receivedServices := make([]lb.ServiceName, 0)

	// Upsert the service before subscription
	m.svc.UpsertService(p1)

	ctx := t.Context()

	m.svc.Subscribe(ctx, func(svcInfo HealthUpdateSvcInfo) {
		receivedServices = append(receivedServices, svcInfo.Name)
	})

	require.Len(t, receivedServices, 1, "Unexpected number of events received")
	require.Equal(t, receivedServices[0], p1.Name, "Received an unexpected service")
}

func TestNotifyHealthCheckUpdatesSubscriber(t *testing.T) {
	m := setupManagerTestSuite(t)

	backends := make([]*lb.LegacyBackend, len(backends1))
	backends[0] = backends1[0].DeepCopy()
	backends[1] = backends1[1].DeepCopy()
	// Add two services with common backend.
	p1 := &lb.LegacySVC{
		Frontend:              frontend1,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc1", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	p2 := &lb.LegacySVC{
		Frontend:              frontend2,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc2", Namespace: "ns2"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	cbCh1 := make(chan struct{})
	cbCh2 := make(chan struct{})
	wg := sync.WaitGroup{}
	wg.Add(2)
	// Ensure that callbacks are received for all the services.
	cb := func(svcInfo HealthUpdateSvcInfo) {
		require.Len(t, svcInfo.ActiveBackends, 1)
		require.Equal(t, svcInfo.ActiveBackends[0].L3n4Addr, backends[1].L3n4Addr)
		require.Equal(t, lb.BackendStateActive, svcInfo.ActiveBackends[0].State)
		if svcInfo.Name == p1.Name {
			require.Equal(t, svcInfo.Addr, frontend1.L3n4Addr)
			require.Equal(t, lb.SVCTypeClusterIP, svcInfo.SvcType)
			// No duplicate updates
			close(cbCh1)
		} else if svcInfo.Name == p2.Name {
			require.Equal(t, svcInfo.Addr, frontend2.L3n4Addr)
			require.Equal(t, lb.SVCTypeClusterIP, svcInfo.SvcType)
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
	require.Len(t, backends, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Len(t, backends, len(m.lbmap.BackendByID))
	require.Equal(t, 2, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	_, id2, err2 := m.svc.UpsertService(p2)

	require.NoError(t, err2)
	require.Equal(t, id2, lb.ID(2))
	require.Len(t, backends, len(m.lbmap.ServiceByID[uint16(id2)].Backends))
	require.Len(t, backends, len(m.lbmap.BackendByID))
	require.Equal(t, 2, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

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
	m.svc.healthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend1.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateQuarantined,
		})
	m.svc.healthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend2.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateQuarantined,
		})

	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Equal(ct, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	}, time.Second*3, time.Millisecond*100)

	wg.Wait()

	// Subscriber stops callbacks.
	cancel()
	ctx.Done()

	be = backends[0]
	m.svc.healthCheckCallback(HealthCheckCBBackendEvent,
		HealthCheckCBBackendEventData{
			SvcAddr: frontend1.L3n4Addr,
			BeAddr:  be.L3n4Addr,
			BeState: lb.BackendStateActive,
		})
	require.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Equal(ct, 2, m.lbmap.SvcActiveBackendsCount[uint16(id1)])
	}, time.Second*3, time.Millisecond*100)

	// Subscriber callback is not executed.

	// Test HealthCheckCBSvcEvent.
	// Add a service with a quarantined backend.
	backends = []*lb.LegacyBackend{
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.20"), 8080),
		lb.NewLegacyBackend(0, lb.TCP, cmtypes.MustParseAddrCluster("10.0.0.21"), 8080),
	}
	backends[0].State = lb.BackendStateQuarantined
	frontendFoo := *lb.NewL3n4AddrID(lb.TCP, cmtypes.MustParseAddrCluster("1.1.1.11"), 80, lb.ScopeExternal, 0)
	p1 = &lb.LegacySVC{
		Frontend:              frontendFoo,
		Backends:              backends,
		Type:                  lb.SVCTypeClusterIP,
		Name:                  lb.ServiceName{Name: "svc10", Namespace: "ns1"},
		LoadBalancerAlgorithm: lb.SVCLoadBalancingAlgorithmMaglev,
		ProxyDelegation:       lb.SVCProxyDelegationNone,
	}
	cbCh1 = make(chan struct{})
	cb = func(svcInfo HealthUpdateSvcInfo) {
		if svcInfo.Name == p1.Name {
			require.Equal(t, svcInfo.Addr, frontendFoo.L3n4Addr)
			require.Equal(t, lb.SVCTypeClusterIP, svcInfo.SvcType)
			require.Len(t, svcInfo.ActiveBackends, 1)
			require.Equal(t, svcInfo.ActiveBackends[0].L3n4Addr, backends[1].L3n4Addr)
			require.Equal(t, lb.BackendStateActive, svcInfo.ActiveBackends[0].State)
			// No duplicate updates
			close(cbCh1)
		}
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	m.svc.Subscribe(ctx, cb)

	_, id1, err1 = m.svc.UpsertService(p1)

	require.NoError(t, err1)
	require.Equal(t, id1, lb.ID(3))
	require.Len(t, backends, len(m.lbmap.ServiceByID[uint16(id1)].Backends))
	require.Equal(t, 1, m.lbmap.SvcActiveBackendsCount[uint16(id1)])

	// Send a CB service event
	m.svc.healthCheckCallback(HealthCheckCBSvcEvent,
		HealthCheckCBSvcEventData{
			SvcAddr: p1.Frontend.L3n4Addr,
		})

	// The subscriber callback function asserts expected callbacks, and also
	// closes the channel.
	<-cbCh1
}

func initializeNetns(t *testing.T, ns *netns.NetNS, addr string) net.Conn {
	var conn net.Conn
	assert.NoError(t, ns.Do(func() error {
		ls, err := netlink.LinkList()
		assert.NoError(t, err)
		for _, l := range ls {
			// Netns should be default created with loopback dev
			// we assign a localhost address to it to allow us to
			// bind sockets.
			if l.Attrs().Name == "lo" {
				netlink.AddrAdd(l, &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   net.ParseIP("127.0.0.1"),
						Mask: net.IPv4Mask(0xff, 0xff, 0xff, 0xff),
					},
				})
			}
			_, err := netlink.AddrList(l, unix.AF_INET)
			assert.NoError(t, err)
		}
		conn, err = net.Dial("udp", addr)
		assert.NoError(t, err)
		conn.Write([]byte("ping"))
		return err
	}))
	return conn
}

func TestTerminateUDPConnectionsToBackend(t *testing.T) {
	testutils.PrivilegedTest(t)

	ns1, err := netns.New()
	require.NoError(t, err)
	// ns2 has a connection that should not be matched due
	// to a different port.
	ns2, err := netns.New()
	require.NoError(t, err)
	// ns3 will match revnat, but with a different cookie value
	// so we expect to avoid a socket close (i.e. this is
	// the case where we have matching tuple values, but
	// in an unexpected socket cookie value).
	ns3, err := netns.New()
	require.NoError(t, err)

	var conn1, conn2, conn3 net.Conn
	conn1 = initializeNetns(t, ns1, "127.0.0.1:30000")
	defer conn1.Close()

	conn2 = initializeNetns(t, ns2, "127.0.0.1:30002")
	defer conn2.Close()

	conn3 = initializeNetns(t, ns3, "127.0.0.1:30001")
	defer conn3.Close()

	getCookie := func(ns *netns.NetNS, port uint16) uint32 {
		if ns == nil {
			var err error
			ns, err = netns.Current()
			require.NoError(t, err)
		}
		out := uint32(0)
		ns.Do(func() error {
			sock, err := netlink.SocketDiagUDP(unix.AF_INET)
			assert.NoError(t, err)
			for _, s := range sock {
				if s.ID.DestinationPort == port {
					out = s.ID.Cookie[0]
					break
				}
			}
			return nil
		})
		return out
	}

	cookie := getCookie(ns1, 30000)

	lbmap := mockmaps.NewLBMockMap()

	lbmap.AddSockRevNat(uint64(cookie), net.IP{127, 0, 0, 1}, 30000)

	logger := hivetest.Logger(t)
	s := Service{
		logger: logger,
		config: &option.DaemonConfig{
			EnableSocketLB:                         true,
			EnableSocketLBPodConnectionTermination: true,
			BPFSocketLBHostnsOnly:                  false,
		},

		backendConnectionHandler: &backendConnectionHandler{},

		// Don't need to pin ns's for the purpose of the test.
		nsIterator: func() (iter.Seq2[string, *netns.NetNS], <-chan error) {
			ch := make(chan error)
			return func(yield func(string, *netns.NetNS) bool) {
				yield("cni-0000", ns1)
				yield("cni-0001", ns2)
				yield("cni-0002", ns3)
				close(ch)
			}, ch
		},

		lbmap: lbmap,
	}
	ip, err := netip.ParseAddr("127.0.0.1")
	require.NoError(t, err)
	l4a := lb.NewL3n4Addr(lb.UDP, cmtypes.AddrClusterFrom(ip, 0), 30000, 0)

	assertForceClose := func(closed bool, c net.Conn) {
		if closed {
			c.SetDeadline(time.Now().Add(time.Millisecond * 250))
			_, err = c.Read([]byte{0})
			assert.ErrorIs(t, err, unix.ECONNABORTED, "first sock connection should have been aborted")
		} else {
			c.SetDeadline(time.Now().Add(time.Millisecond * 250))
			_, err = c.Read([]byte{0})
			//nolint:errorlint
			assert.True(t, err.(net.Error).Timeout(),
				"other connection should not be prematurely closed, thus read cmd on the sock should simply be allowed to timeout")
		}
	}

	// 1. First, we have conn1 in ns1 which has:
	// 	* Is tracked in the l3nl4addr map.
	// 	* Real socket cookie.
	// 	* BPFSocketLBHostnsOnly is disabled
	// Therefore we expect a socket close.
	assert.NoError(t, s.TerminateUDPConnectionsToBackend(l4a))

	assertForceClose(true, conn1)
	assertForceClose(false, conn2)

	l4a = lb.NewL3n4Addr(lb.UDP, cmtypes.AddrClusterFrom(ip, 0), 30001, 0)
	assert.NoError(t, s.TerminateUDPConnectionsToBackend(l4a))
	assertForceClose(false, conn3)

	// 2. Will otherwise close, but we have lb host ns only enabled so we expect
	// 	connection to *not* close.
	assert.NoError(t, ns3.Do(func() error {
		conn3, err = net.Dial("udp", "127.0.0.1:30001")
		assert.NoError(t, err)
		return nil
	}))
	cookie3 := getCookie(ns3, 30001)
	lbmap.AddSockRevNat(uint64(cookie3), net.IP{127, 0, 0, 1}, 30001)
	l4a = lb.NewL3n4Addr(lb.UDP, cmtypes.AddrClusterFrom(ip, 0), 30001, 0)
	s.config.BPFSocketLBHostnsOnly = true
	assert.NoError(t, s.TerminateUDPConnectionsToBackend(l4a))
	assertForceClose(false, conn3)

	// 3. Now we try a similar test, but with a connection in host ns
	// 	so this one should close.
	conn3, err = net.Dial("udp", "127.0.0.1:30004")
	assert.NoError(t, err)
	lbmap.AddSockRevNat(uint64(getCookie(nil, 30004)), net.IP{127, 0, 0, 1}, 30004)
	l4a = lb.NewL3n4Addr(lb.UDP, cmtypes.AddrClusterFrom(ip, 0), 30004, 0)
	assert.NoError(t, s.TerminateUDPConnectionsToBackend(l4a))
	assertForceClose(true, conn3)

	// 4. Now we try one in ns3 again, but we turn off lb host ns only so we expect a connection
	// 	to be closed.
	assert.NoError(t, ns3.Do(func() error {
		conn3, err = net.Dial("udp", "127.0.0.1:30003")
		assert.NoError(t, err)
		return nil
	}))
	cookie3 = getCookie(ns3, 30003)
	lbmap.AddSockRevNat(uint64(cookie3), net.IP{127, 0, 0, 1}, 30003)
	l4a = lb.NewL3n4Addr(lb.UDP, cmtypes.AddrClusterFrom(ip, 0), 30003, 0)
	s.config.BPFSocketLBHostnsOnly = false
	assert.NoError(t, s.TerminateUDPConnectionsToBackend(l4a))
	assertForceClose(true, conn3)
}
