// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"sync"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
	testidentity "github.com/cilium/cilium/pkg/testutils/identity"
)

var (
	fooLabel = labels.NewLabel("k8s:foo", "", "")
	lbls     = labels.Labels{
		"foo": fooLabel,
	}
	lblsArray   = lbls.LabelArray()
	fooIdentity = &identity.Identity{
		ID:         303,
		Labels:     lbls,
		LabelArray: lbls.LabelArray(),
	}
	identityCache = cache.IdentityCache{303: lblsArray}
)

type dummyEndpoint struct {
	ID               uint16
	SecurityIdentity *identity.Identity
	Endpoint         // Implement methods of the interface that need to mock out real behavior.
}

func (d *dummyEndpoint) GetID16() uint16 {
	return d.ID
}

func (d *dummyEndpoint) IsHost() bool {
	return false
}

func (d *dummyEndpoint) GetSecurityIdentity() (*identity.Identity, error) {
	return d.SecurityIdentity, nil
}

func GenerateNumIdentities(numIdentities int) {
	for i := 0; i < numIdentities; i++ {

		identityLabel := labels.NewLabel(fmt.Sprintf("k8s:foo%d", i), "", "")
		clusterLabel := labels.NewLabel("io.cilium.k8s.policy.cluster=default", "", labels.LabelSourceK8s)
		serviceAccountLabel := labels.NewLabel("io.cilium.k8s.policy.serviceaccount=default", "", labels.LabelSourceK8s)
		namespaceLabel := labels.NewLabel("io.kubernetes.pod.namespace=monitoring", "", labels.LabelSourceK8s)
		funLabel := labels.NewLabel("app=analytics-erneh", "", labels.LabelSourceK8s)

		identityLabels := labels.Labels{
			fmt.Sprintf("foo%d", i):                           identityLabel,
			"k8s:io.cilium.k8s.policy.cluster=default":        clusterLabel,
			"k8s:io.cilium.k8s.policy.serviceaccount=default": serviceAccountLabel,
			"k8s:io.kubernetes.pod.namespace=monitoring":      namespaceLabel,
			"k8s:app=analytics-erneh":                         funLabel,
		}

		bumpedIdentity := i + 1000
		numericIdentity := identity.NumericIdentity(bumpedIdentity)

		identityCache[numericIdentity] = identityLabels.LabelArray()
	}
}

func GenerateL3IngressRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	ingRule := api.IngressRule{
		IngressCommonRule: api.IngressCommonRule{
			FromEndpoints: []api.EndpointSelector{barSelector},
		},
	}

	var rules api.Rules
	uuid := k8stypes.UID("11bba160-ddca-13e8-b697-0800273b04ff")
	for i := 1; i <= numRules; i++ {
		rule := api.Rule{
			EndpointSelector: fooSelector,
			Ingress:          []api.IngressRule{ingRule},
			Labels:           utils.GetPolicyLabels("default", "l3-ingress", uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

func GenerateL3EgressRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	egRule := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{barSelector},
		},
	}

	var rules api.Rules
	uuid := k8stypes.UID("13bba160-ddca-13e8-b697-0800273b04ff")
	for i := 1; i <= numRules; i++ {
		rule := api.Rule{
			EndpointSelector: fooSelector,
			Egress:           []api.EgressRule{egRule},
			Labels:           utils.GetPolicyLabels("default", "l3-egress", uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

func GenerateCIDRRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	//barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	egRule := api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: []api.CIDR{api.CIDR("10.2.3.0/24"), api.CIDR("ff02::/64")},
		},
		/*ToRequires:  []api.EndpointSelector{barSelector},
		ToPorts: []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     "8080",
						Protocol: api.ProtoTCP,
					},
				},
			},
		},*/
	}

	var rules api.Rules
	uuid := k8stypes.UID("12bba160-ddca-13e8-b697-0800273b04ff")
	for i := 1; i <= numRules; i++ {
		rule := api.Rule{
			EndpointSelector: fooSelector,
			Egress:           []api.EgressRule{egRule},
			Labels:           utils.GetPolicyLabels("default", "cidr", uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

type DummyOwner struct{}

func (d DummyOwner) LookupRedirectPortLocked(bool, string, uint16) uint16 {
	return 4242
}

func (d DummyOwner) HasBPFPolicyMap() bool {
	return true
}

func (d DummyOwner) GetNamedPort(ingress bool, name string, proto uint8) uint16 {
	return 80
}

func (d DummyOwner) GetNamedPortLocked(ingress bool, name string, proto uint8) uint16 {
	return 80
}

func (d DummyOwner) GetID() uint64 {
	return 1234
}

func (d DummyOwner) PolicyDebug(fields logrus.Fields, msg string) {
	log.WithFields(fields).Info(msg)
}

func bootstrapRepo(ruleGenFunc func(int) api.Rules, numRules int, tb testing.TB) *Repository {
	mgr := cache.NewCachingIdentityAllocator(&testidentity.IdentityAllocatorOwnerMock{})
	ids := mgr.GetIdentityCache()
	fakeAllocator := testidentity.NewMockIdentityAllocator(ids)
	testRepo := NewPolicyRepository(fakeAllocator, ids, nil, nil)

	SetPolicyEnabled(option.DefaultEnforcement)
	GenerateNumIdentities(3000)
	wg := &sync.WaitGroup{}
	testSelectorCache.UpdateIdentities(identityCache, nil, wg)
	wg.Wait()
	testRepo.selectorCache = testSelectorCache
	rulez, _ := testRepo.AddList(ruleGenFunc(numRules))

	epSet := NewEndpointSet(map[Endpoint]struct{}{
		&dummyEndpoint{
			ID:               9001,
			SecurityIdentity: fooIdentity,
		}: {},
	})

	epsToRegen := NewEndpointSet(nil)
	wg = &sync.WaitGroup{}
	rulez.UpdateRulesEndpointsCaches(epSet, epsToRegen, wg)
	wg.Wait()

	require.Equal(tb, 0, epSet.Len())
	require.Equal(tb, 1, epsToRegen.Len())

	return testRepo
}

func BenchmarkRegenerateCIDRPolicyRules(b *testing.B) {
	testRepo := bootstrapRepo(GenerateCIDRRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := testRepo.resolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, false)
		ip.Detach()
	}
}

func BenchmarkRegenerateL3IngressPolicyRules(b *testing.B) {
	testRepo := bootstrapRepo(GenerateL3IngressRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := testRepo.resolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, false)
		ip.Detach()
	}
}

func BenchmarkRegenerateL3EgressPolicyRules(b *testing.B) {
	testRepo := bootstrapRepo(GenerateL3EgressRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := testRepo.resolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, false)
		ip.Detach()
	}
}

func (ds *PolicyTestSuite) TestL7WithIngressWildcard(c *C) {
	repo := bootstrapRepo(GenerateL3IngressRules, 1000, c)

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/good"},
						},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	c.Assert(selPolicy.L4Policy.redirectTypes, Equals, redirectTypeEnvoy)

	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: wildcardCachedSelector,
						L7Parser: ParserTypeHTTP,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							wildcardCachedSelector: &PerSelectorPolicy{
								L7Rules: api.L7Rules{
									HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
								},
								CanShortCircuit: true,
								isRedirect:      true,
							},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {nil}},
					},
				}},
				Egress:        newL4DirectionPolicy(),
				redirectTypes: redirectTypeEnvoy,
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		// inherit this from the result as it is outside of the scope
		// of this test
		policyMapState: policy.policyMapState,
	}

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestL7WithLocalHostWildcardd(c *C) {
	repo := bootstrapRepo(GenerateL3IngressRules, 1000, c)

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}

	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	// Emulate Kubernetes mode with allow from localhost
	oldLocalhostOpt := option.Config.AllowLocalhost
	option.Config.AllowLocalhost = option.AllowLocalhostAlways
	defer func() { option.Config.AllowLocalhost = oldLocalhostOpt }()

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/good"},
						},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	cachedSelectorHost := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameHost])
	c.Assert(cachedSelectorHost, Not(IsNil))

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: wildcardCachedSelector,
						L7Parser: ParserTypeHTTP,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							wildcardCachedSelector: &PerSelectorPolicy{
								L7Rules: api.L7Rules{
									HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
								},
								CanShortCircuit: true,
								isRedirect:      true,
							},
							cachedSelectorHost: nil,
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {nil}},
					},
				}},
				Egress:        newL4DirectionPolicy(),
				redirectTypes: redirectTypeEnvoy,
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		// inherit this from the result as it is outside of the scope
		// of this test
		policyMapState: policy.policyMapState,
	}

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestMapStateWithIngressWildcard(c *C) {
	repo := bootstrapRepo(GenerateL3IngressRules, 1000, c)

	ruleLabel := labels.ParseLabelArray("rule-foo-allow-port-80")
	ruleLabelAllowAnyEgress := labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
	}

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Labels:           ruleLabel,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	rule1MapStateEntry := NewMapStateEntry(wildcardCachedSelector, labels.LabelArrayList{ruleLabel}, false, false, DefaultAuthType, AuthTypeDisabled)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, false, false, ExplicitAuthType, AuthTypeDisabled)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							wildcardCachedSelector: nil,
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {ruleLabel}},
					},
				}},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: newMapState(map[Key]MapStateEntry{
			{TrafficDirection: trafficdirection.Egress.Uint8()}: allowEgressMapStateEntry,
			{DestPort: 80, Nexthdr: 6}:                          rule1MapStateEntry,
		}),
	}

	// Add new identity to test accumulation of MapChanges
	added1 := cache.IdentityCache{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1"),
	}
	wg := &sync.WaitGroup{}
	testSelectorCache.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	c.Assert(policy.policyMapChanges.changes, HasLen, 0)

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	c.Assert(policy, checker.Equals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestMapStateWithIngress(c *C) {
	repo := bootstrapRepo(GenerateL3IngressRules, 1000, c)

	ruleLabel := labels.ParseLabelArray("rule-world-allow-port-80")
	ruleLabelAllowAnyEgress := labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
	}

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	lblTest := labels.ParseLabel("id=resolve_test_1")

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Labels:           ruleLabel,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: []api.Entity{api.EntityWorld},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{},
				}},
			},
			{
				Authentication: &api.Authentication{
					Mode: api.AuthenticationModeDisabled,
				},
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblTest),
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	// Add new identity to test accumulation of MapChanges
	added1 := cache.IdentityCache{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1", "num=1"),
		identity.NumericIdentity(193): labels.ParseSelectLabelArray("id=resolve_test_1", "num=2"),
		identity.NumericIdentity(194): labels.ParseSelectLabelArray("id=resolve_test_1", "num=3"),
	}
	wg := &sync.WaitGroup{}
	testSelectorCache.UpdateIdentities(added1, nil, wg)
	// Cleanup the identities from the testSelectorCache
	defer testSelectorCache.UpdateIdentities(nil, added1, wg)
	wg.Wait()
	c.Assert(policy.policyMapChanges.changes, HasLen, 3)

	deleted1 := cache.IdentityCache{
		identity.NumericIdentity(193): labels.ParseSelectLabelArray("id=resolve_test_1", "num=2"),
	}
	wg = &sync.WaitGroup{}
	testSelectorCache.UpdateIdentities(nil, deleted1, wg)
	wg.Wait()
	c.Assert(policy.policyMapChanges.changes, HasLen, 4)

	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorld])
	c.Assert(cachedSelectorWorld, Not(IsNil))

	cachedSelectorTest := testSelectorCache.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	c.Assert(cachedSelectorTest, Not(IsNil))

	rule1MapStateEntry := NewMapStateEntry(cachedSelectorTest, labels.LabelArrayList{ruleLabel}, false, false, DefaultAuthType, AuthTypeDisabled)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, false, false, ExplicitAuthType, AuthTypeDisabled)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							cachedSelectorWorld: nil,
							cachedSelectorTest: &PerSelectorPolicy{
								Authentication: &api.Authentication{
									Mode: api.AuthenticationModeDisabled,
								},
								CanShortCircuit: true,
							},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld: {ruleLabel},
							cachedSelectorTest:  {ruleLabel},
						},
					},
				},
					features: authRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: newMapState(map[Key]MapStateEntry{
			{TrafficDirection: trafficdirection.Egress.Uint8()}:                              allowEgressMapStateEntry,
			{Identity: uint32(identity.ReservedIdentityWorld), DestPort: 80, Nexthdr: 6}:     rule1MapStateEntry.WithOwners(cachedSelectorWorld),
			{Identity: uint32(identity.ReservedIdentityWorldIPv4), DestPort: 80, Nexthdr: 6}: rule1MapStateEntry.WithOwners(cachedSelectorWorld),
			{Identity: uint32(identity.ReservedIdentityWorldIPv6), DestPort: 80, Nexthdr: 6}: rule1MapStateEntry.WithOwners(cachedSelectorWorld),
			{Identity: 192, DestPort: 80, Nexthdr: 6}:                                        rule1MapStateEntry.WithAuthType(AuthTypeDisabled),
			{Identity: 194, DestPort: 80, Nexthdr: 6}:                                        rule1MapStateEntry.WithAuthType(AuthTypeDisabled),
		}),
	}

	// Have to remove circular reference before testing for Equality to avoid an infinite loop
	policy.selectorPolicy.Detach()
	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	cachedSelectorTest = testSelectorCache.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	c.Assert(cachedSelectorTest, IsNil)

	adds, deletes := policy.ConsumeMapChanges()
	// maps on the policy got cleared
	c.Assert(policy.policyMapChanges.changes, IsNil)

	c.Assert(adds, checker.Equals, Keys{
		{Identity: 192, DestPort: 80, Nexthdr: 6}: {},
		{Identity: 194, DestPort: 80, Nexthdr: 6}: {},
	})
	c.Assert(deletes, checker.Equals, Keys{
		{Identity: 193, DestPort: 80, Nexthdr: 6}: {},
	})

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	policy.policyMapChanges.mutex = lock.Mutex{}
	c.Assert(policy, checker.Equals, &expectedEndpointPolicy)
}

func TestEndpointPolicy_AllowsIdentity(t *testing.T) {
	type fields struct {
		selectorPolicy *selectorPolicy
		PolicyMapState *mapState
	}
	type args struct {
		identity identity.NumericIdentity
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantIngress bool
		wantEgress  bool
	}{
		{
			name: "policy disabled",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: false,
					EgressPolicyEnabled:  false,
				},
				PolicyMapState: newMapState(nil),
			},
			args: args{
				identity: 0,
			},
			wantIngress: true,
			wantEgress:  true,
		},
		{
			name: "policy enabled",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: true,
					EgressPolicyEnabled:  true,
				},
				PolicyMapState: newMapState(nil),
			},
			args: args{
				identity: 0,
			},
			wantIngress: false,
			wantEgress:  false,
		},
		{
			name: "policy enabled for ingress",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: true,
					EgressPolicyEnabled:  true,
				},
				PolicyMapState: newMapState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Ingress.Uint8(),
					}: {},
				}),
			},
			args: args{
				identity: 0,
			},
			wantIngress: true,
			wantEgress:  false,
		},
		{
			name: "policy enabled for egress",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: true,
					EgressPolicyEnabled:  true,
				},
				PolicyMapState: newMapState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Egress.Uint8(),
					}: {},
				}),
			},
			args: args{
				identity: 0,
			},
			wantIngress: false,
			wantEgress:  true,
		},
		{
			name: "policy enabled for ingress with deny policy",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: true,
					EgressPolicyEnabled:  true,
				},
				PolicyMapState: newMapState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Ingress.Uint8(),
					}: {IsDeny: true},
				}),
			},
			args: args{
				identity: 0,
			},
			wantIngress: false,
			wantEgress:  false,
		},
		{
			name: "policy disabled for ingress with deny policy",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: false,
					EgressPolicyEnabled:  true,
				},
				PolicyMapState: newMapState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Ingress.Uint8(),
					}: {IsDeny: true},
				}),
			},
			args: args{
				identity: 0,
			},
			wantIngress: true,
			wantEgress:  false,
		},
		{
			name: "policy enabled for egress with deny policy",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: true,
					EgressPolicyEnabled:  true,
				},
				PolicyMapState: newMapState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Egress.Uint8(),
					}: {IsDeny: true},
				}),
			},
			args: args{
				identity: 0,
			},
			wantIngress: false,
			wantEgress:  false,
		},
		{
			name: "policy disabled for egress with deny policy",
			fields: fields{
				selectorPolicy: &selectorPolicy{
					IngressPolicyEnabled: true,
					EgressPolicyEnabled:  false,
				},
				PolicyMapState: newMapState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Egress.Uint8(),
					}: {IsDeny: true},
				}),
			},
			args: args{
				identity: 0,
			},
			wantIngress: false,
			wantEgress:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EndpointPolicy{
				selectorPolicy: tt.fields.selectorPolicy,
				policyMapState: tt.fields.PolicyMapState,
			}
			gotIngress, gotEgress := p.AllowsIdentity(tt.args.identity)
			if gotIngress != tt.wantIngress {
				t.Errorf("AllowsIdentity() gotIngress = %v, want %v", gotIngress, tt.wantIngress)
			}
			if gotEgress != tt.wantEgress {
				t.Errorf("AllowsIdentity() gotEgress = %v, want %v", gotEgress, tt.wantEgress)
			}
		})
	}
}
