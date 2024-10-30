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
	"github.com/cilium/cilium/pkg/proxy/endpoint"
	"github.com/cilium/cilium/pkg/revert"
	"github.com/cilium/cilium/pkg/testutils"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
	testipcache "github.com/cilium/cilium/pkg/testutils/ipcache"
)

type RedirectSuite struct {
	oldPolicyEnable   string
	mgr               *cache.CachingIdentityAllocator
	do                *DummyOwner
	rsp               *RedirectSuiteProxy
	stats             *regenerationStatistics
	datapathRegenCtxt *datapathRegenerationContext
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

	s.mgr = cache.NewCachingIdentityAllocator(s.do, cache.AllocatorConfig{})
	<-s.mgr.InitIdentityAllocator(nil)

	identityCache := identity.IdentityMap{
		identityFoo: labelsFoo,
		identityBar: labelsBar,
	}

	s.do.idmgr = identitymanager.NewIDManager()
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
		redirects: make(map[string]uint16),
	}

	s.stats = new(regenerationStatistics)
	s.datapathRegenCtxt = new(datapathRegenerationContext)

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
	parserProxyPortMap map[string]uint16
	redirects          map[string]uint16
}

// CreateOrUpdateRedirect returns the proxy port for the given L7Parser from the
// ProxyPolicy parameter.
func (r *RedirectSuiteProxy) CreateOrUpdateRedirect(ctx context.Context, l4 policy.ProxyPolicy, id string, localEndpoint endpoint.EndpointUpdater, wg *completion.WaitGroup) (proxyPort uint16, err error, finalizeFunc revert.FinalizeFunc, revertFunc revert.RevertFunc) {
	pp := r.parserProxyPortMap[l4.GetL7Parser().String()+l4.GetListener()]
	return pp, nil, func() { r.redirects[id] = pp }, nil
}

// RemoveRedirect removes a redirect from the map
func (r *RedirectSuiteProxy) RemoveRedirect(id string) {
	delete(r.redirects, id)
}

// UseCurrentNetworkPolicy does nothing.
func (f *RedirectSuiteProxy) UseCurrentNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, wg *completion.WaitGroup) {
}

// UpdateNetworkPolicy does nothing.
func (r *RedirectSuiteProxy) UpdateNetworkPolicy(ep endpoint.EndpointUpdater, policy *policy.L4Policy, ingressPolicyEnforced, egressPolicyEnforced bool, wg *completion.WaitGroup) (error, func() error) {
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
	repo  policy.PolicyRepository
	idmgr identitymanager.IDManager
}

// GetPolicyRepository returns the policy repository of the owner.
func (d *DummyOwner) GetPolicyRepository() policy.PolicyRepository {
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
func (d *DummyOwner) Loader() datapath.Loader {
	return nil
}

func (d *DummyOwner) Orchestrator() datapath.Orchestrator {
	return nil
}

func (d *DummyOwner) BandwidthManager() datapath.BandwidthManager {
	return nil
}

func (d *DummyOwner) IPTablesManager() datapath.IptablesManager {
	return nil
}

func (s *DummyOwner) GetDNSRules(epID uint16) restore.DNSRules {
	return nil
}

func (s *DummyOwner) RemoveRestoredDNSRules(epID uint16) {}

func (s *DummyOwner) AddIdentity(id *identity.Identity) { s.idmgr.Add(id) }

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
	ep := NewTestEndpointWithState(s.do, s.do, testipcache.NewMockIPCache(), s.rsp, s.mgr, 12345, StateRegenerating)
	ep.SetPropertyValue(PropertyFakeEndpoint, false)

	epIdentity, _, err := s.mgr.AllocateIdentity(context.Background(), labelsBar.Labels(), true, identityBar)
	require.NoError(t, err)
	ep.SetIdentity(epIdentity, true)

	return ep
}

func (s *RedirectSuite) AddRules(rules api.Rules) {
	repo := s.do.repo.(*policy.Repository)
	repo.MustAddList(rules)
}

func (s *RedirectSuite) TearDownTest(t *testing.T) {
	s.do.idmgr.RemoveAll()
	s.mgr.Close()
	policy.SetPolicyEnabled(s.oldPolicyEnable)
}

var (
	// Identity, labels, selectors for an endpoint named "foo"
	identityFoo = identity.NumericIdentity(100)
	labelsFoo   = labels.ParseSelectLabelArray("foo", "red")
	selectFoo_  = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	selectRed_  = api.NewESFromLabels(labels.ParseSelectLabel("red"))
	denyFooL3__ = selectFoo_

	identityBar = identity.NumericIdentity(200)

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

	mapKeyAllL7     = policy.IngressKey().WithTCPPort(80)
	mapKeyFoo       = policy.IngressKey().WithIdentity(identityFoo)
	mapKeyFooL7     = policy.IngressKey().WithIdentity(identityFoo).WithTCPPort(80)
	mapKeyAllowAllE = policy.EgressKey()
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

func (s *RedirectSuite) computePolicyForTest(t *testing.T, ep *Endpoint, cmp *completion.WaitGroup) {
	res, err := ep.regeneratePolicy(s.stats, s.datapathRegenCtxt)
	require.NoError(t, err)

	oldDesiredPolicy := ep.desiredPolicy
	s.datapathRegenCtxt.revertStack.Push(func() error {
		ep.desiredPolicy = oldDesiredPolicy
		return nil
	})
	ep.setDesiredPolicy(res, s.datapathRegenCtxt)

	// This will also remove old redirects
	s.datapathRegenCtxt.finalizeList.Finalize()
}

type LabelArrayListMap map[policy.Key]labels.LabelArrayList

func (obtained LabelArrayListMap) Equals(expected LabelArrayListMap) bool {
	if len(obtained) != len(expected) {
		return false
	}
	for kO, vO := range obtained {
		if vE, ok := expected[kO]; !ok || !vO.Equals(vE) {
			return false
		}
	}
	return true
}

func (e *Endpoint) GetDesiredPolicyRuleLabels() LabelArrayListMap {
	desiredLabels := make(LabelArrayListMap)
	for k := range e.desiredPolicy.Entries() {
		desiredLabels[k], _ = e.desiredPolicy.GetRuleLabels(k)
	}
	return desiredLabels
}

func (e *Endpoint) ValidateRuleLabels(t *testing.T, expectedLabels LabelArrayListMap) {
	t.Helper()

	desiredLabels := e.GetDesiredPolicyRuleLabels()

	if !desiredLabels.Equals(expectedLabels) {
		t.Fatal("desired policy labels do not equal expected labels:\n",
			desiredLabels.Diff(expectedLabels))
	}
}

// Diff returns the string of differences between 'obtained' and 'expected' prefixed with
// '+ ' or '- ' for obtaining something unexpected, or not obtaining the expected, respectively.
// For use in debugging.
func (obtained LabelArrayListMap) Diff(expected LabelArrayListMap) (res string) {
	res += "Missing (-), Unexpected (+), Different (!):\n"
	for kE, vE := range expected {
		if vO, ok := obtained[kE]; ok {
			if !vO.Equals(vE) {
				res += "! " + kE.String() + ": " + vO.Diff(vE) + "\n"
			}
		} else {
			res += "- " + kE.String() + ": " + vE.String() + "\n"
		}
	}
	for kO, vO := range obtained {
		if _, ok := expected[kO]; !ok {
			res += "+ " + kO.String() + ": " + vO.String() + "\n"
		}
	}
	return res
}

func TestRedirectWithDeny(t *testing.T) {
	s := setupRedirectSuite(t)
	ep := s.NewTestEndpoint(t)

	// Policy denies anything to "foo"
	s.AddRules(api.Rules{
		ruleL3DenyFoo.WithEndpointSelector(selectBar_),
		ruleL4L7Allow.WithEndpointSelector(selectBar_),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)
	s.computePolicyForTest(t, ep, cmp)

	// Redirect is still created, even if all MapState entries may have been overridden by a
	// deny entry.  A new FQDN redirect may have no MapState entries as the associated CIDR
	// identities may match no numeric IDs yet, so we can not count the number of added MapState
	// entries and make any conclusions from it.
	require.Len(t, ep.desiredPolicy.Redirects, 1)

	expected := policy.MapStateMap{
		mapKeyAllowAllE: {},
		mapKeyAllL7: {
			ProxyPort: httpPort,
		},
		mapKeyFoo: {
			IsDeny: true,
		},
		mapKeyFooL7: {
			IsDeny: true,
		},
	}

	ep.ValidateRuleLabels(t, LabelArrayListMap{
		mapKeyAllowAllE: labels.LabelArrayList{AllowAnyEgressLabels},
		mapKeyAllL7:     labels.LabelArrayList{lblsL4L7Allow},
		mapKeyFoo:       labels.LabelArrayList{lblsL3DenyFoo},
		mapKeyFooL7:     labels.LabelArrayList{lblsL3DenyFoo},
	})

	// Redirect for the HTTP port should have been added, but there should be a deny for Foo on
	// that port, as it is shadowed by the deny rule
	if !ep.desiredPolicy.Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.Diff(expected))
	}

	// Check that the redirect is realized
	require.Len(t, ep.desiredPolicy.Redirects, 1)
	require.Equal(t, 4, ep.desiredPolicy.Len())

	// Pretend that something failed and revert the changes
	s.datapathRegenCtxt.revertStack.Revert()
	require.Empty(t, ep.desiredPolicy.Redirects)

	expected = policy.MapStateMap{}

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.Diff(expected))
	}
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)
	s.computePolicyForTest(t, ep, cmp)

	// Check that all redirects have been created.
	require.Equal(t, crd2Port, ep.desiredPolicy.Redirects["12345:ingress:TCP:80:/cec2/listener2"])
	require.Equal(t, crd1Port, ep.desiredPolicy.Redirects["12345:ingress:TCP:80:/cec1/listener1"])
	require.Len(t, ep.desiredPolicy.Redirects, 2)

	expected := policy.MapStateMap{
		mapKeyAllowAllE: {},
		mapKeyFooL7:     {ProxyPort: crd2Port},
		mapKeyAllL7:     {},
	}
	ep.ValidateRuleLabels(t, LabelArrayListMap{
		mapKeyAllowAllE: labels.LabelArrayList{AllowAnyEgressLabels},
		mapKeyFooL7:     labels.LabelArrayList{lblsL4AllowListener1, lblsL4L7AllowListener2Priority1}, // lblsL4AllowPort80
		mapKeyAllL7:     labels.LabelArrayList{lblsL4AllowPort80},                                     // lblsL4AllowListener1, lblsL4L7AllowListener2Priority1
	})
	if !ep.desiredPolicy.Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.Diff(expected))
	}

	// Check that the redirect is realized
	require.Len(t, ep.desiredPolicy.Redirects, 2)
	require.Equal(t, 3, ep.desiredPolicy.Len())

	// Pretend that something failed and revert the changes
	s.datapathRegenCtxt.revertStack.Revert()
	require.Empty(t, ep.desiredPolicy.Redirects)

	expected = policy.MapStateMap{}

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.Diff(expected))
	}
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmp := completion.NewWaitGroup(ctx)
	s.computePolicyForTest(t, ep, cmp)

	// Check that all redirects have been created.
	require.Equal(t, crd2Port, ep.desiredPolicy.Redirects["12345:ingress:TCP:80:/cec2/listener2"])
	require.Equal(t, crd1Port, ep.desiredPolicy.Redirects["12345:ingress:TCP:80:/cec1/listener1"])
	require.Len(t, ep.desiredPolicy.Redirects, 2)

	expected := policy.MapStateMap{
		mapKeyAllowAllE: {},
		mapKeyFooL7:     {ProxyPort: crd1Port},
		mapKeyAllL7:     {},
	}
	ep.ValidateRuleLabels(t, LabelArrayListMap{
		mapKeyAllowAllE: labels.LabelArrayList{AllowAnyEgressLabels},
		mapKeyFooL7:     labels.LabelArrayList{lblsL4L7AllowListener1Priority1, lblsL4L7AllowListener2Priority1}, // lblsL4AllowPort80
		mapKeyAllL7:     labels.LabelArrayList{lblsL4AllowPort80},                                                // lblsL4L7AllowListener1Priority1, lblsL4L7AllowListener2Priority1
	})
	if !ep.desiredPolicy.Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.Diff(expected))
	}

	// Check that the redirect is realized
	require.Len(t, ep.desiredPolicy.Redirects, 2)
	require.Equal(t, 3, ep.desiredPolicy.Len())

	// Pretend that something failed and revert the changes
	s.datapathRegenCtxt.revertStack.Revert()
	require.Empty(t, ep.desiredPolicy.Redirects)

	expected = policy.MapStateMap{}

	// Check that the state before addRedirects is restored
	if !ep.desiredPolicy.Equals(expected) {
		t.Fatal("desired policy map does not equal expected map:\n",
			ep.desiredPolicy.Diff(expected))
	}
}
