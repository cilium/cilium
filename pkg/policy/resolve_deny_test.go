// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/identity"
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

func TestL3WithIngressDenyWildcard(t *testing.T) {
	td := newTestData()
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressDenyRules, 1000, t)

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)
	td.addIdentity(fooIdentity)

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
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
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
						wildcard: td.wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
					},
				},
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
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
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(nil, expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}

func TestL3WithLocalHostWildcardd(t *testing.T) {
	td := newTestData()
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressDenyRules, 1000, t)

	idFooSelectLabelArray := labels.ParseSelectLabelArray("id=foo")
	idFooSelectLabels := labels.Labels{}
	for _, lbl := range idFooSelectLabelArray {
		idFooSelectLabels[lbl.Key] = lbl
	}

	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)
	td.addIdentity(fooIdentity)

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
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	cachedSelectorHost := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameHost])
	require.NotNil(t, cachedSelectorHost)

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
						wildcard: td.wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
					},
				},
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
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
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(nil, expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}

func TestMapStateWithIngressDenyWildcard(t *testing.T) {
	td := newTestData()
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressDenyRules, 1000, t)

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
	td.addIdentity(fooIdentity)

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
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	rule1MapStateEntry := NewMapStateEntry(td.wildcardCachedSelector, labels.LabelArrayList{ruleLabel}, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled)

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
						wildcard: td.wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {ruleLabel}},
					},
				},
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: newMapState(map[Key]MapStateEntry{
			// Although we have calculated deny policies, the overall policy
			// will still allow egress to world.
			{TrafficDirection: trafficdirection.Egress.Uint8(), InvertedPortMask: 0xffff /* This is a wildcard */}: allowEgressMapStateEntry,
			{DestPort: 80, Nexthdr: 6}: rule1MapStateEntry,
		}),
	}

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	// Cleanup the identities from the testSelectorCache
	defer td.sc.UpdateIdentities(nil, added1, wg)
	wg.Wait()
	require.Equal(t, 0, len(policy.policyMapChanges.changes))

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(nil, expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}

func TestMapStateWithIngressDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressDenyRules, 1000, t)

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
	td.addIdentity(fooIdentity)

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
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1", "num=1"),
		identity.NumericIdentity(193): labels.ParseSelectLabelArray("id=resolve_test_1", "num=2"),
		identity.NumericIdentity(194): labels.ParseSelectLabelArray("id=resolve_test_1", "num=3"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	require.Len(t, policy.policyMapChanges.changes, 3)

	deleted1 := identity.IdentityMap{
		identity.NumericIdentity(193): labels.ParseSelectLabelArray("id=resolve_test_1", "num=2"),
	}
	wg = &sync.WaitGroup{}
	td.sc.UpdateIdentities(nil, deleted1, wg)
	wg.Wait()
	require.Len(t, policy.policyMapChanges.changes, 4)

	cachedSelectorWorld := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorld])
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

	cachedSelectorTest := td.sc.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.NotNil(t, cachedSelectorTest)

	rule1MapStateEntry := NewMapStateEntry(cachedSelectorTest, labels.LabelArrayList{ruleLabel}, 0, "", 0, true, DefaultAuthType, AuthTypeDisabled)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled)

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
							cachedSelectorWorld:   &PerSelectorPolicy{IsDeny: true},
							cachedSelectorWorldV4: &PerSelectorPolicy{IsDeny: true},
							cachedSelectorWorldV6: &PerSelectorPolicy{IsDeny: true},
							cachedSelectorTest:    &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld:   {ruleLabel},
							cachedSelectorWorldV4: {ruleLabel},
							cachedSelectorWorldV6: {ruleLabel},
							cachedSelectorTest:    {ruleLabel},
						},
					},
				},
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: newMapState(map[Key]MapStateEntry{
			// Although we have calculated deny policies, the overall policy
			// will still allow egress to world.
			{TrafficDirection: trafficdirection.Egress.Uint8(), InvertedPortMask: 0xffff /* This is a wildcard */}: allowEgressMapStateEntry,
			{Identity: uint32(identity.ReservedIdentityWorld), DestPort: 80, Nexthdr: 6}:                           rule1MapStateEntry.WithOwners(cachedSelectorWorld),
			{Identity: uint32(identity.ReservedIdentityWorldIPv4), DestPort: 80, Nexthdr: 6}:                       rule1MapStateEntry.WithOwners(cachedSelectorWorldV4, cachedSelectorWorld),
			{Identity: uint32(identity.ReservedIdentityWorldIPv6), DestPort: 80, Nexthdr: 6}:                       rule1MapStateEntry.WithOwners(cachedSelectorWorldV6, cachedSelectorWorld),
			{Identity: 192, DestPort: 80, Nexthdr: 6}:                                                              rule1MapStateEntry,
			{Identity: 194, DestPort: 80, Nexthdr: 6}:                                                              rule1MapStateEntry,
		}),
	}

	adds, deletes := policy.ConsumeMapChanges()
	// maps on the policy got cleared

	require.Equal(t, Keys{
		{Identity: 192, DestPort: 80, Nexthdr: 6}: {},
		{Identity: 194, DestPort: 80, Nexthdr: 6}: {},
	}, adds)
	require.Equal(t, Keys{
		{Identity: 193, DestPort: 80, Nexthdr: 6}: {},
	}, deletes)

	// Have to remove circular reference before testing for Equality to avoid an infinite loop
	policy.selectorPolicy.Detach()
	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	cachedSelectorTest = td.sc.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.Nil(t, cachedSelectorTest)

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	policy.policyMapChanges.mutex = lock.Mutex{}
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(nil, expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}
