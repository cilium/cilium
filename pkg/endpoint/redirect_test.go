// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	monitorAPI "github.com/cilium/cilium/pkg/monitor/api"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
	"github.com/cilium/cilium/pkg/u8proto"
)

type RedirectSuite struct {
	oldPolicyEnable string
	mgr             *cache.CachingIdentityAllocator
	do              *DummyOwner
	rsp             *RedirectSuiteProxy
	stats           *regenerationStatistics
}

func setupRedirectSuite(tb testing.TB) *RedirectSuite {
	testutils.IntegrationTest(tb)

	s := &RedirectSuite{
		do: &DummyOwner{},
	}
	s.oldPolicyEnable = policy.GetPolicyEnabled()
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	// Setup dependencies for endpoint.
	kvstore.SetupDummy(tb, "etcd")

	s.mgr = cache.NewCachingIdentityAllocator(s.do)
	<-s.mgr.InitIdentityAllocator(nil)

	identityCache := identity.IdentityMap{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}

	s.do.idmgr = identitymanager.NewIdentityManager()
	s.do.repo = policy.NewPolicyRepository(identityCache, nil, nil, s.do.idmgr)
	s.do.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())

	s.rsp = &RedirectSuiteProxy{
		parserProxyPortMap: map[string]uint16{
			policy.ParserTypeHTTP.String():  httpPort,
			policy.ParserTypeDNS.String():   dnsPort,
			policy.ParserTypeKafka.String(): kafkaPort,
			"crd/cec1/listener1":            crd1Port,
			"crd/cec2/listener2":            crd2Port,
		},
		redirectPortUserMap: make(map[uint16][]string),
	}

	s.stats = new(regenerationStatistics)

	tb.Cleanup(func() {
		s.do.idmgr.RemoveAll()
		s.mgr.Close()
		policy.SetPolicyEnabled(s.oldPolicyEnable)
	})

	return s
}

// RedirectSuiteProxy implements EndpointProxy. It is used for testing the
// functions related to generating proxy redirects for a given Endpoint.
type RedirectSuiteProxy struct {
	parserProxyPortMap  map[string]uint16
	redirectPortUserMap map[uint16][]string
}

// CreateOrUpdateRedirect returns the proxy port for the given L7Parser from the
// ProxyPolicy parameter.
func (r *RedirectSuiteProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, localEndpoint endpoint.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	pp := r.parserProxyPortMap[l4.GetL7Parser().String()+l4.GetListener()]
	return pp, nil, func() { log.Infof("FINALIZER CALLED") }, nil
}

// RemoveRedirect does nothing.
func (r *RedirectSuiteProxy) RemoveRedirect(id string, wg *completion.WaitGroup) (error, revert.FinalizeFunc, revert.RevertFunc) {
	return nil, nil, nil
}

// UpdateNetworkPolicy does nothing.
func (r *RedirectSuiteProxy) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, vis *policy.VisibilityPolicy, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
	return nil, nil
}

// RemoveNetworkPolicy does nothing.
func (r *RedirectSuiteProxy) RemoveNetworkPolicy(ep endpoint.EndpointInfoSource) {}

// DummyIdentityAllocatorOwner implements
// pkg/identity/cache/IdentityAllocatorOwner. It is used for unit testing.
type DummyIdentityAllocatorOwner struct{}

// UpdateIdentities does nothing.
func (d *DummyIdentityAllocatorOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
}

// GetNodeSuffix does nothing.
func (d *DummyIdentityAllocatorOwner) GetNodeSuffix() string {
	return ""
}

// DummyOwner implements pkg/endpoint/regeneration/Owner. Used for unit testing.
type DummyOwner struct {
	repo  *policy.Repository
	idmgr *identitymanager.IdentityManager
}

// GetPolicyRepository returns the policy repository of the owner.
func (d *DummyOwner) GetPolicyRepository() *policy.Repository {
	return d.repo
}

// QueueEndpointBuild does nothing.
func (d *DummyOwner) QueueEndpointBuild(ctx context.Context, epID uint64) (func(), error) {
	return nil, nil
}

// GetCompilationLock does nothing.
func (d *DummyOwner) GetCompilationLock() datapath.CompilationLock {
	return nil
}

// GetCIDRPrefixLengths does nothing.
func (d *DummyOwner) GetCIDRPrefixLengths() (s6, s4 []int) {
	return nil, nil
}

// SendNotification does nothing.
func (d *DummyOwner) SendNotification(msg monitorAPI.AgentNotifyMessage) error {
	return nil
}

// Datapath returns a nil datapath.
func (d *DummyOwner) Datapath() datapath.Datapath {
	return nil
}

func (s *DummyOwner) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *DummyOwner) RemoveRestoredDNSRules(epID uint16) {}

func (s *DummyOwner) AddIdentity(id *identity.Identity)    { s.idmgr.Add(id) }
func (s *DummyOwner) RemoveIdentity(id *identity.Identity) { s.idmgr.Remove(id) }
func (s *DummyOwner) RemoveOldAddNewIdentity(old, new *identity.Identity) {
	s.idmgr.RemoveOldAddNew(old, new)
}

// GetNodeSuffix does nothing.
func (d *DummyOwner) GetNodeSuffix() string {
	return ""
}

func (d *DummyOwner) UpdateIdentities(added, deleted identity.IdentityMap) {
	wg := &sync.WaitGroup{}
	d.repo.GetSelectorCache().UpdateIdentities(added, deleted, wg)
	wg.Wait()
}

const (
	httpPort  = uint16(19001)
	dnsPort   = uint16(19002)
	kafkaPort = uint16(19003)
	crd1Port  = uint16(19004)
	crd2Port  = uint16(19005)
)

func (s *RedirectSuite) NewTestEndpoint(t *testing.T) *Endpoint {
	ep := NewTestEndpointWithState(t, s.do, s.do, testipcache.NewMockIPCache(), s.rsp, s.mgr, 12345, StateRegenerating)
	ep.SetPropertyValue(PropertyFakeEndpoint, false)

	epIdentity, _, err := s.mgr.AllocateIdentity(context.Background(), labelsBar.Labels(), true, identity.NumericIdentity(identityBar))
	require.Nil(t, err)
	ep.SetIdentity(epIdentity, true)

	return ep
}

func (s *RedirectSuite) AddRules(rules api.Rules) {
	s.do.repo.MustAddList(rules)
}

func (s *RedirectSuite) TearDownTest(t *testing.T) {
	s.do.idmgr.RemoveAll()
	s.mgr.Close()
	policy.SetPolicyEnabled(s.oldPolicyEnable)
}

func TestAddVisibilityRedirects(t *testing.T) {
	s := setupRedirectSuite(t)
	ep := s.NewTestEndpoint(t)

	firstAnno := "<Ingress/80/TCP/HTTP>"
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return firstAnno, nil
	})
	res, err := ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	_, err, _, _ = ep.addNewRedirects(cmp)
	require.Nil(t, err)
	v, ok := ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	require.Equal(t, true, ok)
	require.Equal(t, httpPort, v.ProxyPort)

	secondAnno := "<Ingress/80/TCP/Kafka>"

	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return secondAnno, nil
	})
	res, err = ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	d, err, _, _ := ep.addNewRedirects(cmp)
	require.Nil(t, err)
	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	require.Equal(t, true, ok)
	// Check that proxyport was updated accordingly.
	require.Equal(t, kafkaPort, v.ProxyPort)

	thirdAnno := "<Ingress/80/TCP/Kafka>,<Egress/80/TCP/HTTP>"

	// Check that multiple values in annotation are handled correctly.
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return thirdAnno, nil
	})
	res, err = ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	realizedRedirects := ep.GetRealizedRedirects()
	d2, err, _, _ := ep.addNewRedirects(cmp)
	require.Nil(t, err)
	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	require.Equal(t, true, ok)
	require.Equal(t, kafkaPort, v.ProxyPort)

	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	require.Equal(t, true, ok)
	require.Equal(t, kafkaPort, v.ProxyPort)

	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Egress.Uint8(),
	})
	require.Equal(t, true, ok)
	require.Equal(t, httpPort, v.ProxyPort)
	pID := policy.ProxyID(ep.ID, false, u8proto.TCP.String(), uint16(80), "")
	p, ok := d2[pID]
	require.Equal(t, true, ok)
	require.Equal(t, httpPort, p)

	// Check that the egress redirect is removed when the redirects have been
	// updated.
	ep.removeOldRedirects(d, realizedRedirects, cmp)
	// Egress redirect should not exist in desired redirects
	_, ok = d[pID]
	require.Equal(t, false, ok)

	// Check that all redirects are removed when no visibility policy applies.
	noAnno := ""
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return noAnno, nil
	})
	res, err = ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	realizedRedirects = ep.GetRealizedRedirects()
	d, err, _, _ = ep.addNewRedirects(cmp)
	require.Nil(t, err)
	ep.removeOldRedirects(d, realizedRedirects, cmp)
	require.Equal(t, 0, len(d))
}

var (
	// Identity, labels, selectors for an endpoint named "foo"
	identityFoo = uint32(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "red")
	selectFoo_  = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	selectRed_  = api.NewESFromLabels(labels.ParseSelectLabel("red"))
	denyFooL3__ = selectFoo_

	identityBar = uint32(200)

	labelsBar  = labels.ParseSelectLabelArray("bar", "blue")
	selectBar_ = api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	denyAllL4_ []api.PortDenyRule

	allowPort80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
	}}
	allowHTTPRoot = &api.L7Rules{
		HTTP: []api.PortRuleHTTP{
			{Method: "GET", Path: "/"},
		},
	}

	lblsL3DenyFoo = labels.ParseLabelArray("l3-deny")
	ruleL3DenyFoo = api.NewRule().
			WithLabels(lblsL3DenyFoo).
			WithIngressDenyRules([]api.IngressDenyRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{denyFooL3__},
			},
			ToPorts: denyAllL4_,
		}})
	lblsL4L7Allow = labels.ParseLabelArray("l4l7-allow")
	ruleL4L7Allow = api.NewRule().
			WithLabels(lblsL4L7Allow).
			WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{},
			ToPorts:           combineL4L7(allowPort80, allowHTTPRoot),
		}})

	AllowAnyEgressLabels = labels.LabelArray{labels.NewLabel(policy.LabelKeyPolicyDerivedFrom,
		policy.LabelAllowAnyEgress,
		labels.LabelSourceReserved)}

	dirIngress      = trafficdirection.Ingress.Uint8()
	dirEgress       = trafficdirection.Egress.Uint8()
	mapKeyAllL7     = policy.Key{Identity: 0, DestPort: 80, Nexthdr: 6, TrafficDirection: dirIngress}
	mapKeyFoo       = policy.Key{Identity: identityFoo, DestPort: 0, InvertedPortMask: 0xffff, Nexthdr: 0, TrafficDirection: dirIngress}
	mapKeyFooL7     = policy.Key{Identity: identityFoo, DestPort: 80, Nexthdr: 6, TrafficDirection: dirIngress}
	mapKeyAllowAllE = policy.Key{Identity: 0, DestPort: 0, Nexthdr: 0, InvertedPortMask: 0xffff, TrafficDirection: dirEgress}
)

// combineL4L7 returns a new PortRule that refers to the specified l4 ports and
// l7 rules.
func combineL4L7(l4 []api.PortRule, l7 *api.L7Rules) []api.PortRule {
	result := make([]api.PortRule, 0, len(l4))
	for _, pr := range l4 {
		result = append(result, api.PortRule{
			Ports: pr.Ports,
			Rules: l7,
		})
	}
	return result
}

func (s *RedirectSuite) testMapState(initMap map[policy.Key]policy.MapStateEntry) policy.MapState {
	return policy.NewMapState().WithState(initMap, s.do.repo.GetSelectorCache())
}

func TestRedirectWithDeny(t *testing.T) {
	s := setupRedirectSuite(t)
	ep := s.NewTestEndpoint(t)

	// Policy denies anything to "foo"
	s.AddRules(api.Rules{
		ruleL3DenyFoo.WithEndpointSelector(selectBar_),
		ruleL4L7Allow.WithEndpointSelector(selectBar_),
	})

	res, err := ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	expected := s.testMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyFoo: {
			IsDeny:           true,
			DerivedFromRules: labels.LabelArrayList{lblsL3DenyFoo},
		},
	})
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	realizedRedirects := ep.GetRealizedRedirects()
	desiredRedirects, err, finalizeFunc, revertFunc := ep.addNewRedirects(cmp)
	require.Nil(t, err)
	finalizeFunc()

	// Redirect is still created, even if all MapState entries may have been overridden by a
	// deny entry.  A new FQDN redirect may have no MapState entries as the associated CIDR
	// identities may match no numeric IDs yet, so we can not count the number of added MapState
	// entries and make any conclusions from it.
	require.Equal(t, 1, len(desiredRedirects))

	expected2 := s.testMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyAllL7: {
			IsDeny:           false,
			ProxyPort:        httpPort,
			DerivedFromRules: labels.LabelArrayList{lblsL4L7Allow},
		},
		mapKeyFoo: {
			IsDeny:           true,
			DerivedFromRules: labels.LabelArrayList{lblsL3DenyFoo},
		},
		mapKeyFooL7: {
			IsDeny:           true,
			DerivedFromRules: labels.LabelArrayList{lblsL3DenyFoo},
		},
	})

	// Redirect for the HTTP port should have been added, but there should be a deny for Foo on
	// that port, as it is shadowed by the deny rule
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected2) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected2))
	}

	// Keep only desired redirects
	ep.removeOldRedirects(desiredRedirects, realizedRedirects, cmp)

	// Check that the redirect is still realized
	require.Equal(t, 1, len(desiredRedirects))
	require.Equal(t, 4, ep.desiredPolicy.GetPolicyMap().Len())

	// Pretend that something failed and revert the changes
	revertFunc()

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}
	require.Equal(t, 2, ep.desiredPolicy.GetPolicyMap().Len())
}

var (
	allowListener1Port80 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
		Listener: &api.Listener{
			EnvoyConfig: &api.EnvoyConfig{
				Name: "cec1",
			},
			Name: "listener1",
		},
	}}
	allowListener2Port80Priority1 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
		Listener: &api.Listener{
			EnvoyConfig: &api.EnvoyConfig{
				Name: "cec2",
			},
			Name:     "listener2",
			Priority: 1,
		},
	}}
	allowListener1Port80Priority1 = []api.PortRule{{
		Ports: []api.PortProtocol{
			{Port: "80", Protocol: api.ProtoTCP},
		},
		Listener: &api.Listener{
			EnvoyConfig: &api.EnvoyConfig{
				Name: "cec1",
			},
			Name:     "listener1",
			Priority: 1,
		},
	}}
	lblsL4AllowListener1 = labels.ParseLabelArray("foo-l4l7-allow-listener1")
	ruleL4AllowListener1 = api.NewRule().
				WithLabels(lblsL4AllowListener1).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{selectFoo_},
			},
			ToPorts: allowListener1Port80,
		}})
	lblsL4L7AllowListener1Priority1 = labels.ParseLabelArray("foo-l4l7-allow-listener1-priority1")
	ruleL4L7AllowListener1Priority1 = api.NewRule().
					WithLabels(lblsL4L7AllowListener1Priority1).
					WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{selectFoo_},
			},
			ToPorts: allowListener1Port80Priority1,
		}})
	lblsL4AllowPort80 = labels.ParseLabelArray("l4-allow-port80")
	ruleL4AllowPort80 = api.NewRule().
				WithLabels(lblsL4AllowPort80).
				WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{},
			ToPorts:           allowPort80,
		}})
	lblsL4L7AllowListener2Priority1 = labels.ParseLabelArray("red-l4l7-allow-listener2-priority1")
	ruleL4L7AllowListener2Priority1 = api.NewRule().
					WithLabels(lblsL4L7AllowListener2Priority1).
					WithIngressRules([]api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{selectRed_},
			},
			ToPorts: allowListener2Port80Priority1,
		}})
)

func TestRedirectWithPriority(t *testing.T) {
	s := setupRedirectSuite(t)

	ep := s.NewTestEndpoint(t)
	api.TestAllowIngressListener = true
	defer func() { api.TestAllowIngressListener = false }()

	s.AddRules(api.Rules{
		ruleL4AllowListener1.WithEndpointSelector(selectBar_),
		ruleL4AllowPort80.WithEndpointSelector(selectBar_),
		ruleL4L7AllowListener2Priority1.WithEndpointSelector(selectBar_),
	})

	res, err := ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	expected := s.testMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyAllL7: {
			DerivedFromRules: labels.LabelArrayList{lblsL4AllowListener1, lblsL4AllowPort80, lblsL4L7AllowListener2Priority1},
		},
	})
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	realizedRedirects := ep.GetRealizedRedirects()
	desiredRedirects, err, finalizeFunc, revertFunc := ep.addNewRedirects(cmp)
	require.Nil(t, err)
	finalizeFunc()

	// Check that all redirects have been created.
	require.Equal(t, crd2Port, desiredRedirects["12345:ingress:TCP:80:/cec2/listener2"])
	require.Equal(t, crd1Port, desiredRedirects["12345:ingress:TCP:80:/cec1/listener1"])
	require.Equal(t, 2, len(desiredRedirects))

	expected2 := s.testMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyFooL7: {
			ProxyPort:        crd2Port,
			Listener:         "/cec2/listener2",
			DerivedFromRules: labels.LabelArrayList{lblsL4AllowListener1, lblsL4AllowPort80, lblsL4L7AllowListener2Priority1},
		},
		mapKeyAllL7: {
			DerivedFromRules: labels.LabelArrayList{lblsL4AllowListener1, lblsL4AllowPort80, lblsL4L7AllowListener2Priority1},
		},
	})
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected2) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected2))
	}

	// Keep only desired redirects
	ep.removeOldRedirects(desiredRedirects, realizedRedirects, cmp)

	// Check that the redirect is still realized
	require.Equal(t, 2, len(desiredRedirects))
	require.Equal(t, 3, ep.desiredPolicy.GetPolicyMap().Len())

	// Pretend that something failed and revert the changes
	revertFunc()

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}
	require.Equal(t, 2, ep.desiredPolicy.GetPolicyMap().Len())
}

func TestRedirectWithEqualPriority(t *testing.T) {
	s := setupRedirectSuite(t)

	ep := s.NewTestEndpoint(t)

	api.TestAllowIngressListener = true
	defer func() { api.TestAllowIngressListener = false }()
	s.AddRules(api.Rules{
		ruleL4L7AllowListener1Priority1.WithEndpointSelector(selectBar_),
		ruleL4AllowPort80.WithEndpointSelector(selectBar_),
		ruleL4L7AllowListener2Priority1.WithEndpointSelector(selectBar_),
	})

	res, err := ep.regeneratePolicy(s.stats)
	require.Nil(t, err)
	err = ep.setDesiredPolicy(res)
	require.Nil(t, err)

	expected := s.testMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyAllL7: {
			DerivedFromRules: labels.LabelArrayList{lblsL4L7AllowListener1Priority1, lblsL4AllowPort80, lblsL4L7AllowListener2Priority1},
		},
	})
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	realizedRedirects := ep.GetRealizedRedirects()
	desiredRedirects, err, finalizeFunc, revertFunc := ep.addNewRedirects(cmp)
	require.Nil(t, err)
	finalizeFunc()

	// Check that all redirects have been created.
	require.Equal(t, crd2Port, desiredRedirects["12345:ingress:TCP:80:/cec2/listener2"])
	require.Equal(t, crd1Port, desiredRedirects["12345:ingress:TCP:80:/cec1/listener1"])
	require.Equal(t, 2, len(desiredRedirects))

	expected2 := s.testMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyFooL7: {
			ProxyPort:        crd1Port,
			Listener:         "/cec1/listener1",
			DerivedFromRules: labels.LabelArrayList{lblsL4L7AllowListener1Priority1, lblsL4AllowPort80, lblsL4L7AllowListener2Priority1},
		},
		mapKeyAllL7: {
			DerivedFromRules: labels.LabelArrayList{lblsL4L7AllowListener1Priority1, lblsL4AllowPort80, lblsL4L7AllowListener2Priority1},
		},
	})
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected2) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected2))
	}

	// Keep only desired redirects
	ep.removeOldRedirects(desiredRedirects, realizedRedirects, cmp)

	// Check that the redirect is still realized
	require.Equal(t, 2, len(desiredRedirects))
	require.Equal(t, 3, ep.desiredPolicy.GetPolicyMap().Len())

	// Pretend that something failed and revert the changes
	revertFunc()

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}
	require.Equal(t, 2, ep.desiredPolicy.GetPolicyMap().Len())
}
