// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package endpoint

import (
	"context"

	check "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/completion"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/fqdn/restore"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
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

type RedirectSuite struct{}

// suite can be used by testing.T benchmarks or tests as a mock regeneration.Owner
var redirectSuite = RedirectSuite{}
var _ = check.Suite(&redirectSuite)

func (s *RedirectSuite) SetUpSuite(c *check.C) {
	testutils.IntegrationTest(c)
}

// RedirectSuiteProxy implements EndpointProxy. It is used for testing the
// functions related to generating proxy redirects for a given Endpoint.
type RedirectSuiteProxy struct {
	parserProxyPortMap  map[policy.L7ParserType]uint16
	redirectPortUserMap map[uint16][]string
}

// CreateOrUpdateRedirect returns the proxy port for the given L7Parser from the
// ProxyPolicy parameter.
func (r *RedirectSuiteProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, localEndpoint endpoint.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	pp := r.parserProxyPortMap[l4.GetL7Parser()]
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
func (d *DummyIdentityAllocatorOwner) UpdateIdentities(added, deleted cache.IdentityCache) {
}

// GetNodeSuffix does nothing.
func (d *DummyIdentityAllocatorOwner) GetNodeSuffix() string {
	return ""
}

// DummyOwner implements pkg/endpoint/regeneration/Owner. Used for unit testing.
type DummyOwner struct {
	repo *policy.Repository
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
func (d *DummyOwner) GetCompilationLock() *lock.RWMutex {
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

func (s *DummyOwner) RemoveRestoredDNSRules(epID uint16) {
}

// GetNodeSuffix does nothing.
func (d *DummyOwner) GetNodeSuffix() string {
	return ""
}

// UpdateIdentities does nothing.
func (d *DummyOwner) UpdateIdentities(added, deleted cache.IdentityCache) {}

func (s *RedirectSuite) TestAddVisibilityRedirects(c *check.C) {
	// Setup dependencies for endpoint.
	kvstore.SetupDummy(c, "etcd")

	idAllocatorOwner := &DummyIdentityAllocatorOwner{}

	mgr := cache.NewCachingIdentityAllocator(idAllocatorOwner)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()

	do := &DummyOwner{
		repo: policy.NewPolicyRepository(nil, nil, nil, nil),
	}
	do.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	identitymanager.Subscribe(do.repo)
	defer identitymanager.RemoveAll()

	lblQA := labels.ParseLabel("QA")
	lblBar := labels.ParseLabel("bar")

	httpPort := uint16(19001)
	dnsPort := uint16(19002)
	kafkaPort := uint16(19003)

	rsp := &RedirectSuiteProxy{
		parserProxyPortMap: map[policy.L7ParserType]uint16{
			policy.ParserTypeHTTP:  httpPort,
			policy.ParserTypeDNS:   dnsPort,
			policy.ParserTypeKafka: kafkaPort,
		},
		redirectPortUserMap: make(map[uint16][]string),
	}

	ep := NewEndpointWithState(do, do, testipcache.NewMockIPCache(), rsp, mgr, 12345, StateRegenerating)

	qaBarLbls := labels.Labels{lblBar.Key: lblBar, lblQA.Key: lblQA}
	epIdentity, _, err := mgr.AllocateIdentity(context.Background(), qaBarLbls, true, identity.InvalidIdentity)
	c.Assert(err, check.IsNil)
	ep.SetIdentity(epIdentity, true)

	firstAnno := "<Ingress/80/TCP/HTTP>"
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return firstAnno, nil
	})
	res, err := ep.regeneratePolicy()
	c.Assert(err, check.IsNil)
	err = ep.setDesiredPolicy(res)
	c.Assert(err, check.IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	_, err, _, _ = ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	v, ok := ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, httpPort)

	secondAnno := "<Ingress/80/TCP/Kafka>"

	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return secondAnno, nil
	})
	res, err = ep.regeneratePolicy()
	c.Assert(err, check.IsNil)
	err = ep.setDesiredPolicy(res)
	c.Assert(err, check.IsNil)

	d, err, _, _ := ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	c.Assert(ok, check.Equals, true)
	// Check that proxyport was updated accordingly.
	c.Assert(v.ProxyPort, check.Equals, kafkaPort)

	thirdAnno := "<Ingress/80/TCP/Kafka>,<Egress/80/TCP/HTTP>"

	// Check that multiple values in annotation are handled correctly.
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return thirdAnno, nil
	})
	res, err = ep.regeneratePolicy()
	c.Assert(err, check.IsNil)
	err = ep.setDesiredPolicy(res)
	c.Assert(err, check.IsNil)

	_, err, _, _ = ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, kafkaPort)

	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Ingress.Uint8(),
	})
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, kafkaPort)

	v, ok = ep.desiredPolicy.GetPolicyMap().Get(policy.Key{
		Identity:         0,
		DestPort:         uint16(80),
		Nexthdr:          uint8(u8proto.TCP),
		TrafficDirection: trafficdirection.Egress.Uint8(),
	})
	c.Assert(ok, check.Equals, true)
	c.Assert(v.ProxyPort, check.Equals, httpPort)
	pID := policy.ProxyID(ep.ID, false, u8proto.TCP.String(), uint16(80))
	p, ok := ep.realizedRedirects[pID]
	c.Assert(ok, check.Equals, true)
	c.Assert(p, check.Equals, httpPort)

	// Check that the egress redirect is removed when the redirects have been
	// updated.
	ep.removeOldRedirects(d, cmp)
	// Egress redirect should be removed.
	_, ok = ep.realizedRedirects[pID]
	c.Assert(ok, check.Equals, false)

	// Check that all redirects are removed when no visibility policy applies.
	noAnno := ""
	ep.UpdateVisibilityPolicy(func(_, _ string) (proxyVisibility string, err error) {
		return noAnno, nil
	})
	res, err = ep.regeneratePolicy()
	c.Assert(err, check.IsNil)
	err = ep.setDesiredPolicy(res)
	c.Assert(err, check.IsNil)

	d, err, _, _ = ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	ep.removeOldRedirects(d, cmp)
	c.Assert(len(ep.realizedRedirects), check.Equals, 0)
}

var (
	// Identity, labels, selectors for an endpoint named "foo"
	identityFoo = uint32(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "red")
	selectFoo_  = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
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
		L7Proto: policy.ParserTypeHTTP.String(),
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
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{},
			},
			ToPorts: combineL4L7(allowPort80, allowHTTPRoot),
		}})

	AllowAnyEgressLabels = labels.LabelArray{labels.NewLabel(policy.LabelKeyPolicyDerivedFrom,
		policy.LabelAllowAnyEgress,
		labels.LabelSourceReserved)}

	dirIngress      = trafficdirection.Ingress.Uint8()
	dirEgress       = trafficdirection.Egress.Uint8()
	mapKeyAllL7     = policy.Key{Identity: 0, DestPort: 80, Nexthdr: 6, TrafficDirection: dirIngress}
	mapKeyFoo       = policy.Key{Identity: identityFoo, DestPort: 0, Nexthdr: 0, TrafficDirection: dirIngress}
	mapKeyFooL7     = policy.Key{Identity: identityFoo, DestPort: 80, Nexthdr: 6, TrafficDirection: dirIngress}
	mapKeyAllowAllE = policy.Key{Identity: 0, DestPort: 0, Nexthdr: 0, TrafficDirection: dirEgress}
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

func (s *RedirectSuite) TestRedirectWithDeny(c *check.C) {
	// Setup dependencies for endpoint.
	kvstore.SetupDummy(c, "etcd")

	oldPolicyEnable := policy.GetPolicyEnabled()
	defer policy.SetPolicyEnabled(oldPolicyEnable)
	policy.SetPolicyEnabled(option.DefaultEnforcement)

	idAllocatorOwner := &DummyIdentityAllocatorOwner{}

	mgr := cache.NewCachingIdentityAllocator(idAllocatorOwner)
	<-mgr.InitIdentityAllocator(nil)
	defer mgr.Close()

	identityCache := cache.IdentityCache{
		identity.NumericIdentity(identityFoo): labelsFoo,
		identity.NumericIdentity(identityBar): labelsBar,
	}

	do := &DummyOwner{
		repo: policy.NewPolicyRepository(mgr, identityCache, nil, nil),
	}
	do.repo.GetSelectorCache().SetLocalIdentityNotifier(testidentity.NewDummyIdentityNotifier())
	identitymanager.Subscribe(do.repo)
	defer identitymanager.RemoveAll()

	httpPort := uint16(19001)
	dnsPort := uint16(19002)
	kafkaPort := uint16(19003)

	rsp := &RedirectSuiteProxy{
		parserProxyPortMap: map[policy.L7ParserType]uint16{
			policy.ParserTypeHTTP:  httpPort,
			policy.ParserTypeDNS:   dnsPort,
			policy.ParserTypeKafka: kafkaPort,
		},
		redirectPortUserMap: make(map[uint16][]string),
	}

	ep := NewEndpointWithState(do, do, testipcache.NewMockIPCache(), rsp, mgr, 12345, StateRegenerating)

	epIdentity, _, err := mgr.AllocateIdentity(context.Background(), labelsBar.Labels(),
		true, identity.NumericIdentity(identityBar))
	c.Assert(err, check.IsNil)
	ep.SetIdentity(epIdentity, true)

	// Policy denies anything to "foo"
	rules := api.Rules{
		ruleL3DenyFoo.WithEndpointSelector(selectBar_),
		ruleL4L7Allow.WithEndpointSelector(selectBar_),
	}
	do.repo.AddList(rules)

	res, err := ep.regeneratePolicy()
	c.Assert(err, check.IsNil)
	err = ep.setDesiredPolicy(res)
	c.Assert(err, check.IsNil)

	expected := policy.NewMapState(map[policy.Key]policy.MapStateEntry{
		mapKeyAllowAllE: {
			DerivedFromRules: labels.LabelArrayList{AllowAnyEgressLabels},
		},
		mapKeyFoo: {
			IsDeny:           true,
			DerivedFromRules: labels.LabelArrayList{lblsL3DenyFoo},
		},
	})
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		c.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)

	desiredRedirects, err, finalizeFunc, revertFunc := ep.addNewRedirects(cmp)
	c.Assert(err, check.IsNil)
	finalizeFunc()

	// Redirect is still created, even if all MapState entries may have been overridden by a
	// deny entry.  A new FQDN redirect may have no MapState entries as the associated CIDR
	// identities may match no numeric IDs yet, so we can not count the number of added MapState
	// entries and make any conclusions from it.
	c.Assert(len(desiredRedirects), check.Equals, 1)

	expected2 := policy.NewMapState(map[policy.Key]policy.MapStateEntry{
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
		c.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected2))
	}

	// Keep only desired redirects
	ep.removeOldRedirects(desiredRedirects, cmp)

	// Check that the redirect is still realized
	c.Assert(len(ep.realizedRedirects), check.Equals, 1)
	c.Assert(ep.desiredPolicy.GetPolicyMap().Len(), check.Equals, 4)

	// Pretend that something failed and revert the changes
	revertFunc()

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.GetPolicyMap().Equals(expected) {
		c.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.GetPolicyMap().Diff(expected))
	}
	c.Assert(len(ep.realizedRedirects), check.Equals, 0)
	c.Assert(ep.desiredPolicy.GetPolicyMap().Len(), check.Equals, 2)
}
