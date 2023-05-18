// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/cache"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

func GenerateL3IngressDenyRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	ingDenyRule := api.IngressDenyRule{
		IngressCommonRule: api.IngressCommonRule{
			FromEndpoints: []api.EndpointSelector{barSelector},
		},
	}

	rules := make(api.Rules, 0, numRules)
	for i := 1; i <= numRules; i++ {
		rule := api.Rule{
			EndpointSelector: fooSelector,
			IngressDeny:      []api.IngressDenyRule{ingDenyRule},
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

func GenerateL3EgressDenyRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	egDenyRule := api.EgressDenyRule{
		EgressCommonRule: api.EgressCommonRule{
			ToEndpoints: []api.EndpointSelector{barSelector},
		},
	}

	rules := make(api.Rules, 0, numRules)
	for i := 1; i <= numRules; i++ {
		rule := api.Rule{
			EndpointSelector: fooSelector,
			EgressDeny:       []api.EgressDenyRule{egDenyRule},
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

func GenerateCIDRDenyRules(numRules int) api.Rules {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)
	//barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

	// Change ingRule and rule in the for-loop below to change what type of rules
	// are added into the policy repository.
	egDenyRule := api.EgressDenyRule{
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
	for i := 1; i <= numRules; i++ {

		rule := api.Rule{
			EndpointSelector: fooSelector,
			EgressDeny:       []api.EgressDenyRule{egDenyRule},
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules
}

func (ds *PolicyTestSuite) TestL3WithIngressDenyWildcard(c *C) {
	repo := bootstrapRepo(GenerateL3IngressDenyRules, 1000, c)

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		IngressDeny: []api.IngressDenyRule{
			{
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: &L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {nil}},
					},
				},
				Egress: L4PolicyMap{},
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{},
		// inherit this from the result as it is outside of the scope
		// of this test
		PolicyMapState: policy.PolicyMapState,
	}

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestL3WithLocalHostWildcardd(c *C) {
	repo := bootstrapRepo(GenerateL3IngressDenyRules, 1000, c)

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
		IngressDeny: []api.IngressDenyRule{
			{
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1, []Endpoint{})
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
			L4Policy: &L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {nil}},
					},
				},
				Egress: L4PolicyMap{},
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{},
		// inherit this from the result as it is outside of the scope
		// of this test
		PolicyMapState: policy.PolicyMapState,
	}

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestMapStateWithIngressDenyWildcard(c *C) {
	repo := bootstrapRepo(GenerateL3IngressDenyRules, 1000, c)

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
		IngressDeny: []api.IngressDenyRule{
			{
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	c.Assert(err, IsNil)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	rule1MapStateEntry := NewMapStateEntry(wildcardCachedSelector, labels.LabelArrayList{ruleLabel}, false, true, AuthTypeNone)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, false, false, AuthTypeNone)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: &L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {ruleLabel}},
					},
				},
				Egress: L4PolicyMap{},
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{},
		PolicyMapState: MapState{
			// Although we have calculated deny policies, the overall policy
			// will still allow egress to world.
			{TrafficDirection: trafficdirection.Egress.Uint8()}: allowEgressMapStateEntry,
			{DestPort: 80, Nexthdr: 6}:                          rule1MapStateEntry,
		},
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
	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}

func (ds *PolicyTestSuite) TestMapStateWithIngressDeny(c *C) {
	repo := bootstrapRepo(GenerateL3IngressDenyRules, 1000, c)

	ruleLabel := labels.ParseLabelArray("rule-deny-port-80-world-and-test")
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
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: []api.Entity{api.EntityWorld},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(lblTest),
					},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	rule1.Sanitize()
	_, _, err := repo.Add(rule1, []Endpoint{})
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

	rule1MapStateEntry := NewMapStateEntry(cachedSelectorTest, labels.LabelArrayList{ruleLabel}, false, true, AuthTypeNone)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, false, false, AuthTypeNone)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: &L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4PolicyMap{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							cachedSelectorWorld: &PerSelectorPolicy{IsDeny: true},
							cachedSelectorTest:  &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld: {ruleLabel},
							cachedSelectorTest:  {ruleLabel},
						},
					},
				},
				Egress: L4PolicyMap{},
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{},
		PolicyMapState: MapState{
			// Although we have calculated deny policies, the overall policy
			// will still allow egress to world.
			{TrafficDirection: trafficdirection.Egress.Uint8()}:                          allowEgressMapStateEntry,
			{Identity: uint32(identity.ReservedIdentityWorld), DestPort: 80, Nexthdr: 6}: rule1MapStateEntry.WithOwners(cachedSelectorWorld),
			{Identity: 192, DestPort: 80, Nexthdr: 6}:                                    rule1MapStateEntry,
			{Identity: 194, DestPort: 80, Nexthdr: 6}:                                    rule1MapStateEntry,
		},
	}

	adds, deletes := policy.ConsumeMapChanges()
	// maps on the policy got cleared

	c.Assert(adds, checker.Equals, Keys{
		{Identity: 192, DestPort: 80, Nexthdr: 6}: {},
		{Identity: 194, DestPort: 80, Nexthdr: 6}: {},
	})
	c.Assert(deletes, checker.Equals, Keys{
		{Identity: 193, DestPort: 80, Nexthdr: 6}: {},
	})

	// Have to remove circular reference before testing for Equality to avoid an infinite loop
	policy.selectorPolicy.Detach()
	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	cachedSelectorTest = testSelectorCache.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	c.Assert(cachedSelectorTest, IsNil)

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	policy.policyMapChanges.mutex = lock.Mutex{}
	c.Assert(policy, checker.DeepEquals, &expectedEndpointPolicy)
}
