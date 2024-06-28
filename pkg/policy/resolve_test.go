// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/trafficdirection"
)

var (
	fooLabel = labels.NewLabel("k8s:foo", "", "")
	lbls     = labels.Labels{
		"foo": fooLabel,
	}
	fooIdentity = &identity.Identity{
		ID:         303,
		Labels:     lbls,
		LabelArray: lbls.LabelArray(),
	}
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

func generateNumIdentities(numIdentities int) identity.IdentityMap {
	c := make(identity.IdentityMap, numIdentities)
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

		c[numericIdentity] = identityLabels.LabelArray()
	}
	return c
}

func GenerateL3IngressRules(numRules int) (api.Rules, identity.IdentityMap) {
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
	return rules, generateNumIdentities(3000)
}

func GenerateL3EgressRules(numRules int) (api.Rules, identity.IdentityMap) {
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
	return rules, generateNumIdentities(3000)
}

func GenerateCIDRRules(numRules int) (api.Rules, identity.IdentityMap) {
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
	return rules, generateNumIdentities(3000)
}

type DummyOwner struct{}

func (d DummyOwner) LookupRedirectPort(bool, string, uint16, string) (uint16, error) {
	return 1, nil
}

func (d DummyOwner) GetRealizedRedirects() map[string]uint16 {
	return map[string]uint16{
		// This is the only proxy ID currently used in this test suite
		"1234:ingress:TCP:80:": 1,
	}
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

func (td *testData) bootstrapRepo(ruleGenFunc func(int) (api.Rules, identity.IdentityMap), numRules int, tb testing.TB) {
	SetPolicyEnabled(option.DefaultEnforcement)
	wg := &sync.WaitGroup{}
	// load in standard reserved identities
	c := identity.IdentityMap{
		fooIdentity.ID: fooIdentity.LabelArray,
	}
	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		c[ni] = id.Labels.LabelArray()
	})
	td.sc.UpdateIdentities(c, nil, wg)

	apiRules, ids := ruleGenFunc(numRules)
	td.sc.UpdateIdentities(ids, nil, wg)
	wg.Wait()
	rulez, _ := td.repo.MustAddList(apiRules)

	epSet := NewEndpointSet(map[Endpoint]struct{}{
		&dummyEndpoint{
			ID:               9001,
			SecurityIdentity: fooIdentity,
		}: {},
	})

	epsToRegen := NewEndpointSet(nil)
	wg = &sync.WaitGroup{}
	rulez.FindSelectedEndpoints(epSet, epsToRegen, wg)
	wg.Wait()

	require.Equal(tb, 0, epSet.Len())
	require.Equal(tb, 1, epsToRegen.Len())
}

func BenchmarkRegenerateCIDRPolicyRules(b *testing.B) {
	td := newTestData()
	td.bootstrapRepo(GenerateCIDRRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, false)
		ip.Detach()
	}
}

func BenchmarkRegenerateL3IngressPolicyRules(b *testing.B) {
	td := newTestData()
	td.bootstrapRepo(GenerateL3IngressRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, false)
		ip.Detach()
	}
}

func BenchmarkRegenerateL3EgressPolicyRules(b *testing.B) {
	td := newTestData()
	td.bootstrapRepo(GenerateL3EgressRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		_ = ip.DistillPolicy(DummyOwner{}, false)
		ip.Detach()
	}
}

func TestL7WithIngressWildcard(t *testing.T) {

	td := newTestData()
	repo := td.repo

	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

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
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	require.Equal(t, redirectTypeEnvoy, selPolicy.L4Policy.redirectTypes)

	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: td.wildcardCachedSelector,
						L7Parser: ParserTypeHTTP,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{
								L7Rules: api.L7Rules{
									HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
								},
								CanShortCircuit: true,
								isRedirect:      true,
							},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
					},
				})},
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
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}

func TestL7WithLocalHostWildcard(t *testing.T) {

	td := newTestData()
	repo := td.repo

	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

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
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: td.wildcardCachedSelector,
						L7Parser: ParserTypeHTTP,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{
								L7Rules: api.L7Rules{
									HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
								},
								CanShortCircuit: true,
								isRedirect:      true,
							},
							cachedSelectorHost: nil,
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
					},
				})},
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
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}

func TestMapStateWithIngressWildcard(t *testing.T) {

	td := newTestData()
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

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
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	policy := selPolicy.DistillPolicy(DummyOwner{}, false)

	rule1MapStateEntry := NewMapStateEntry(td.wildcardCachedSelector, labels.LabelArrayList{ruleLabel}, 0, "", 0, false, DefaultAuthType, AuthTypeDisabled)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						wildcard: td.wildcardCachedSelector,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: nil,
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {ruleLabel}},
					},
				})},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: newMapState().withState(map[Key]MapStateEntry{
			{TrafficDirection: trafficdirection.Egress.Uint8(), InvertedPortMask: 0xffff}: allowEgressMapStateEntry,
			{DestPort: 80, Nexthdr: 6}: rule1MapStateEntry,
		}, td.sc),
	}

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	require.Equal(t, 0, len(policy.policyMapChanges.changes))

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.Equal(t, policy, &expectedEndpointPolicy)
}

func TestMapStateWithIngress(t *testing.T) {

	td := newTestData()
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

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
	td.addIdentity(fooIdentity)

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

	rule1MapStateEntry := NewMapStateEntry(cachedSelectorTest, labels.LabelArrayList{ruleLabel}, 0, "", 0, false, DefaultAuthType, AuthTypeDisabled)
	allowEgressMapStateEntry := NewMapStateEntry(nil, labels.LabelArrayList{ruleLabelAllowAnyEgress}, 0, "", 0, false, ExplicitAuthType, AuthTypeDisabled)

	expectedEndpointPolicy := EndpointPolicy{
		selectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						L7Parser: ParserTypeNone,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							cachedSelectorWorld:   nil,
							cachedSelectorWorldV4: nil,
							cachedSelectorWorldV6: nil,
							cachedSelectorTest: &PerSelectorPolicy{
								Authentication: &api.Authentication{
									Mode: api.AuthenticationModeDisabled,
								},
								CanShortCircuit: true,
							},
						},
						RuleOrigin: map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld:   {ruleLabel},
							cachedSelectorWorldV4: {ruleLabel},
							cachedSelectorWorldV6: {ruleLabel},
							cachedSelectorTest:    {ruleLabel},
						},
					},
				}),
					features: authRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: newMapState().withState(map[Key]MapStateEntry{
			{TrafficDirection: trafficdirection.Egress.Uint8(), InvertedPortMask: 0xffff /*This is a wildcard*/}: allowEgressMapStateEntry,
			{Identity: uint32(identity.ReservedIdentityWorld), DestPort: 80, Nexthdr: 6}:                         rule1MapStateEntry.WithOwners(cachedSelectorWorld),
			{Identity: uint32(identity.ReservedIdentityWorldIPv4), DestPort: 80, Nexthdr: 6}:                     rule1MapStateEntry.WithOwners(cachedSelectorWorld, cachedSelectorWorldV4),
			{Identity: uint32(identity.ReservedIdentityWorldIPv6), DestPort: 80, Nexthdr: 6}:                     rule1MapStateEntry.WithOwners(cachedSelectorWorld, cachedSelectorWorldV6),
			{Identity: 192, DestPort: 80, Nexthdr: 6}:                                                            rule1MapStateEntry.WithAuthType(AuthTypeDisabled),
			{Identity: 194, DestPort: 80, Nexthdr: 6}:                                                            rule1MapStateEntry.WithAuthType(AuthTypeDisabled),
		}, td.sc),
	}

	// Have to remove circular reference before testing for Equality to avoid an infinite loop
	policy.selectorPolicy.Detach()
	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	cachedSelectorTest = td.sc.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.Nil(t, cachedSelectorTest)

	adds, deletes := policy.ConsumeMapChanges()
	// maps on the policy got cleared
	require.Nil(t, policy.policyMapChanges.changes)

	require.Equal(t, Keys{
		{Identity: 192, DestPort: 80, Nexthdr: 6}: {},
		{Identity: 194, DestPort: 80, Nexthdr: 6}: {},
	}, adds)
	require.Equal(t, Keys{
		{Identity: 193, DestPort: 80, Nexthdr: 6}: {},
	}, deletes)

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	policy.policyMapChanges.mutex = lock.Mutex{}
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equals(expectedEndpointPolicy.policyMapState),
		policy.policyMapState.Diff(expectedEndpointPolicy.policyMapState))
	policy.policyMapState = nil
	expectedEndpointPolicy.policyMapState = nil
	require.EqualExportedValues(t, &expectedEndpointPolicy, policy)
}

// allowsIdentity returns whether the specified policy allows
// ingress and egress traffic for the specified numeric security identity.
// If the 'secID' is zero, it will check if all traffic is allowed.
//
// Returning true for either return value indicates all traffic is allowed.
func (p *EndpointPolicy) allowsIdentity(identity identity.NumericIdentity) (ingress, egress bool) {
	key := Key{
		Identity:         uint32(identity),
		InvertedPortMask: 0xffff, // wildcard port
	}

	if !p.IngressPolicyEnabled {
		ingress = true
	} else {
		key.TrafficDirection = trafficdirection.Ingress.Uint8()
		if v, exists := p.policyMapState.Get(key); exists && !v.IsDeny {
			ingress = true
		}
	}

	if !p.EgressPolicyEnabled {
		egress = true
	} else {
		key.TrafficDirection = trafficdirection.Egress.Uint8()
		if v, exists := p.policyMapState.Get(key); exists && !v.IsDeny {
			egress = true
		}
	}

	return ingress, egress
}

func TestEndpointPolicy_AllowsIdentity(t *testing.T) {
	td := newTestData()

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
				PolicyMapState: newMapState(),
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
				PolicyMapState: newMapState(),
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
				PolicyMapState: newMapState().withState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						InvertedPortMask: 0xffff, // This is a wildcard.
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Ingress.Uint8(),
					}: {},
				}, td.sc),
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
				PolicyMapState: newMapState().withState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						InvertedPortMask: 0xffff, // This is a wildcard.
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Egress.Uint8(),
					}: {},
				}, td.sc),
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
				PolicyMapState: newMapState().withState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						InvertedPortMask: 0xffff, // This is a wildcard.
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Ingress.Uint8(),
					}: {IsDeny: true},
				}, td.sc),
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
				PolicyMapState: newMapState().withState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						InvertedPortMask: 0xffff, // This is a wildcard.
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Ingress.Uint8(),
					}: {IsDeny: true},
				}, td.sc),
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
				PolicyMapState: newMapState().withState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						InvertedPortMask: 0xffff, // This a wildcard.
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Egress.Uint8(),
					}: {IsDeny: true},
				}, td.sc),
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
				PolicyMapState: newMapState().withState(map[Key]MapStateEntry{
					{
						Identity:         0,
						DestPort:         0,
						InvertedPortMask: 0xffff, // This is a wildcard.
						Nexthdr:          0,
						TrafficDirection: trafficdirection.Egress.Uint8(),
					}: {IsDeny: true},
				}, td.sc),
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
			gotIngress, gotEgress := p.allowsIdentity(tt.args.identity)
			if gotIngress != tt.wantIngress {
				t.Errorf("allowsIdentity() gotIngress = %v, want %v", gotIngress, tt.wantIngress)
			}
			if gotEgress != tt.wantEgress {
				t.Errorf("allowsIdentity() gotEgress = %v, want %v", gotEgress, tt.wantEgress)
			}
		})
	}
}
