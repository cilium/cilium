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
	"github.com/cilium/cilium/pkg/u8proto"
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

var testRedirects = map[string]uint16{
	"1234:ingress:TCP:80:": 1,
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

	var rules api.Rules
	uuid := k8stypes.UID("12bba160-ddca-13e8-b697-0800273b04ff")
	for i := 1; i <= numRules; i++ {
		rule := api.Rule{
			EndpointSelector: fooSelector,
			Egress:           []api.EgressRule{generateCIDREgressRule(i)},
			Labels:           utils.GetPolicyLabels("default", "cidr", uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules, generateCIDRIdentities(rules)
}

type DummyOwner struct {
	mapStateSize int
}

func (d DummyOwner) CreateRedirects(*L4Filter) {
}

func (d DummyOwner) GetNamedPort(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 80
}

func (d DummyOwner) GetNamedPortLocked(ingress bool, name string, proto u8proto.U8proto) uint16 {
	return 80
}

func (d DummyOwner) GetID() uint64 {
	return 1234
}

func (d DummyOwner) IsHost() bool {
	return false
}

func (d DummyOwner) MapStateSize() int {
	return d.mapStateSize
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
	td.repo.MustAddList(apiRules)
}

func BenchmarkRegenerateCIDRPolicyRules(b *testing.B) {
	td := newTestData()
	td.bootstrapRepo(GenerateCIDRRules, 1000, b)
	ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
	owner := DummyOwner{}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		epPolicy := ip.DistillPolicy(owner, nil)
		owner.mapStateSize = epPolicy.policyMapState.Len()
		epPolicy.Ready()
	}
	ip.Detach()
	b.Logf("Number of MapState entries: %d\n", owner.mapStateSize)
}

func BenchmarkRegenerateL3IngressPolicyRules(b *testing.B) {
	td := newTestData()
	td.bootstrapRepo(GenerateL3IngressRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		policy := ip.DistillPolicy(DummyOwner{}, nil)
		policy.Ready()
		ip.Detach()
	}
}

func BenchmarkRegenerateL3EgressPolicyRules(b *testing.B) {
	td := newTestData()
	td.bootstrapRepo(GenerateL3EgressRules, 1000, b)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		policy := ip.DistillPolicy(DummyOwner{}, nil)
		policy.Ready()
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	require.Equal(t, redirectTypeEnvoy, selPolicy.L4Policy.redirectTypes)

	policy := selPolicy.DistillPolicy(DummyOwner{}, testRedirects)
	policy.Ready()

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
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
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
					},
				}),
					features: redirectRules,
				},
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
	policy.policyMapChanges.mutex = lock.Mutex{}
	policy.policyMapChanges.firstVersion = 0
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equal(&expectedEndpointPolicy.policyMapState), policy.policyMapState.diff(&expectedEndpointPolicy.policyMapState))
	policy.policyMapState = mapState{}
	expectedEndpointPolicy.policyMapState = mapState{}
	require.Equal(t, &expectedEndpointPolicy, policy)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)

	policy := selPolicy.DistillPolicy(DummyOwner{}, testRedirects)
	policy.Ready()

	cachedSelectorHost := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameHost])
	require.NotNil(t, cachedSelectorHost)

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
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
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
					},
				}),
					features: redirectRules,
				},
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
	policy.policyMapChanges.mutex = lock.Mutex{}
	policy.policyMapChanges.firstVersion = 0
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equal(&expectedEndpointPolicy.policyMapState), policy.policyMapState.diff(&expectedEndpointPolicy.policyMapState))
	policy.policyMapState = mapState{}
	expectedEndpointPolicy.policyMapState = mapState{}
	require.Equal(t, &expectedEndpointPolicy, policy)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)

	policy := selPolicy.DistillPolicy(DummyOwner{}, testRedirects)
	policy.Ready()

	rule1MapStateEntry := newAllowEntryWithLabels(ruleLabel)
	allowEgressMapStateEntry := newAllowEntryWithLabels(ruleLabelAllowAnyEgress)

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
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
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {ruleLabel}}),
					},
				})},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{},
		policyMapState: emptyMapState().withState(mapStateMap{
			EgressKey():                  allowEgressMapStateEntry,
			IngressKey().WithTCPPort(80): rule1MapStateEntry,
		}),
	}

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	require.Empty(t, policy.policyMapChanges.synced) // XXX why 0?

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.Detach()

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	policy.policyMapChanges.mutex = lock.Mutex{}
	policy.policyMapChanges.firstVersion = 0
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equal(&expectedEndpointPolicy.policyMapState), policy.policyMapState.diff(&expectedEndpointPolicy.policyMapState))
	policy.policyMapState = mapState{}
	expectedEndpointPolicy.policyMapState = mapState{}
	require.Equal(t, &expectedEndpointPolicy, policy)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)

	policy := selPolicy.DistillPolicy(DummyOwner{}, testRedirects)
	policy.Ready()

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabelArray("id=resolve_test_1", "num=1"),
		identity.NumericIdentity(193): labels.ParseSelectLabelArray("id=resolve_test_1", "num=2"),
		identity.NumericIdentity(194): labels.ParseSelectLabelArray("id=resolve_test_1", "num=3"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	require.Len(t, policy.policyMapChanges.synced, 3)

	deleted1 := identity.IdentityMap{
		identity.NumericIdentity(193): labels.ParseSelectLabelArray("id=resolve_test_1", "num=2"),
	}
	wg = &sync.WaitGroup{}
	td.sc.UpdateIdentities(nil, deleted1, wg)
	wg.Wait()
	require.Len(t, policy.policyMapChanges.synced, 4)

	cachedSelectorWorld := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorld])
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

	cachedSelectorTest := td.sc.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.NotNil(t, cachedSelectorTest)

	rule1MapStateEntry := newAllowEntryWithLabels(ruleLabel)
	allowEgressMapStateEntry := newAllowEntryWithLabels(ruleLabelAllowAnyEgress)

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
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
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld:   {ruleLabel},
							cachedSelectorWorldV4: {ruleLabel},
							cachedSelectorWorldV6: {ruleLabel},
							cachedSelectorTest:    {ruleLabel},
						}),
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
		policyMapState: emptyMapState().withState(mapStateMap{
			EgressKey(): allowEgressMapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorld).WithTCPPort(80):     rule1MapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorldIPv4).WithTCPPort(80): rule1MapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorldIPv6).WithTCPPort(80): rule1MapStateEntry,
			IngressKey().WithIdentity(192).WithTCPPort(80):                                rule1MapStateEntry.withExplicitAuth(AuthTypeDisabled),
			IngressKey().WithIdentity(194).WithTCPPort(80):                                rule1MapStateEntry.withExplicitAuth(AuthTypeDisabled),
		}),
	}

	// Have to remove circular reference before testing for Equality to avoid an infinite loop
	policy.selectorPolicy.Detach()
	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	cachedSelectorTest = td.sc.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.Nil(t, cachedSelectorTest)

	closer, changes := policy.ConsumeMapChanges()
	closer()

	// maps on the policy got cleared
	require.Nil(t, policy.policyMapChanges.synced)

	require.Equal(t, Keys{
		ingressKey(192, 6, 80, 0): {},
		ingressKey(194, 6, 80, 0): {},
	}, changes.Adds)
	require.Equal(t, Keys{
		ingressKey(193, 6, 80, 0): {},
	}, changes.Deletes)

	// Assign an empty mutex so that checker.Equal does not complain about the
	// difference of the internal time.Time from the lock_debug.go.
	policy.selectorPolicy.L4Policy.mutex = lock.RWMutex{}
	policy.policyMapChanges.mutex = lock.Mutex{}
	policy.policyMapChanges.firstVersion = 0
	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equal(&expectedEndpointPolicy.policyMapState), policy.policyMapState.diff(&expectedEndpointPolicy.policyMapState))
	require.EqualExportedValues(t, &expectedEndpointPolicy, policy)
}

// allowsIdentity returns whether the specified policy allows
// ingress and egress traffic for the specified numeric security identity.
// If the 'secID' is zero, it will check if all traffic is allowed.
//
// Returning true for either return value indicates all traffic is allowed.
func (p *EndpointPolicy) allowsIdentity(identity identity.NumericIdentity) (ingress, egress bool) {
	if !p.IngressPolicyEnabled {
		ingress = true
	} else {
		key := IngressKey().WithIdentity(identity)
		if v, exists := p.policyMapState.Get(key); exists && !v.IsDeny() {
			ingress = true
		}
	}

	if !p.EgressPolicyEnabled {
		egress = true
	} else {
		key := EgressKey().WithIdentity(identity)
		if v, exists := p.policyMapState.Get(key); exists && !v.IsDeny() {
			egress = true
		}
	}

	return ingress, egress
}

func TestEndpointPolicy_AllowsIdentity(t *testing.T) {
	type fields struct {
		selectorPolicy *selectorPolicy
		PolicyMapState mapState
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
				PolicyMapState: emptyMapState(),
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
				PolicyMapState: emptyMapState(),
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
				PolicyMapState: emptyMapState().withState(mapStateMap{
					IngressKey(): {},
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
				PolicyMapState: emptyMapState().withState(mapStateMap{
					EgressKey(): {},
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
				PolicyMapState: emptyMapState().withState(mapStateMap{
					IngressKey(): NewMapStateEntry(DenyEntry),
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
				PolicyMapState: emptyMapState().withState(mapStateMap{
					IngressKey(): NewMapStateEntry(DenyEntry),
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
				PolicyMapState: emptyMapState().withState(mapStateMap{
					EgressKey(): NewMapStateEntry(DenyEntry),
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
				PolicyMapState: emptyMapState().withState(mapStateMap{
					EgressKey(): NewMapStateEntry(DenyEntry),
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
