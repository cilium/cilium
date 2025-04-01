// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"net/netip"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func GenerateL3IngressDenyRules(numRules int) (api.Rules, identity.IdentityMap) {
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

	return rules, generateNumIdentities(3000)
}

// generate a CIDR identity for each unique CIDR rule in 'rules'
func generateCIDRIdentities(rules api.Rules) identity.IdentityMap {
	c := make(identity.IdentityMap, len(rules))
	prefixes := make(map[string]identity.NumericIdentity)
	id := identity.IdentityScopeLocal
	addPrefix := func(prefix string) {
		if _, exists := prefixes[prefix]; !exists {
			lbls := labels.GetCIDRLabels(netip.MustParsePrefix(prefix))
			id++
			c[id] = lbls.LabelArray()
			prefixes[prefix] = id
		}
	}
	for _, rule := range rules {
		for _, egress := range rule.Egress {
			for _, toCIDR := range egress.ToCIDR {
				addPrefix(string(toCIDR))
			}
		}
		for _, egress := range rule.EgressDeny {
			for _, toCIDR := range egress.ToCIDR {
				addPrefix(string(toCIDR))
			}
		}
		for _, egress := range rule.Ingress {
			for _, toCIDR := range egress.FromCIDR {
				addPrefix(string(toCIDR))
			}
		}
		for _, egress := range rule.IngressDeny {
			for _, toCIDR := range egress.FromCIDR {
				addPrefix(string(toCIDR))
			}
		}
	}
	return c
}

func generateCIDREgressRule(i int) api.EgressRule {
	port := fmt.Sprintf("%d", 80+i%97)
	prefix := []string{"8", "16", "24", "28", "32"}[i%5]
	var net string
	switch prefix {
	case "8":
		net = []string{"10.0.0.0", "192.0.0.0", "244.0.0.0"}[i%3]
	case "16":
		pat := []string{"10.%d.0.0", "192.%d.0.0", "244.%d.0.0"}[i%3]
		net = fmt.Sprintf(pat, i%17)
	case "24":
		pat := []string{"10.%d.%d.0", "192.%d.%d.0", "244.%d.%d.0"}[i%3]
		net = fmt.Sprintf(pat, i%17, i%121)
	case "28":
		pat := []string{"10.%d.%d.%d", "192.%d.%d.%d", "244.%d.%d.%d"}[i%3]
		net = fmt.Sprintf(pat, i%17, i%121, i%16<<4)
	case "32":
		pat := []string{"10.%d.%d.%d", "192.%d.%d.%d", "244.%d.%d.%d"}[i%3]
		net = fmt.Sprintf(pat, i%17, i%121, i%255)
	}
	cidr := net + "/" + prefix
	return api.EgressRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: []api.CIDR{api.CIDR(cidr)},
		},
		ToPorts: []api.PortRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     port,
						Protocol: api.ProtoTCP,
					},
				},
			},
		},
	}
}

func generateCIDREgressDenyRule(i int) api.EgressDenyRule {
	port := fmt.Sprintf("%d", 80+i%131)
	prefix := []string{"8", "16", "24", "28", "32"}[(i+21)%5]
	var net string
	switch prefix {
	case "8":
		net = []string{"10.0.0.0", "192.0.0.0", "244.0.0.0"}[i%3]
	case "16":
		pat := []string{"10.%d.0.0", "192.%d.0.0", "244.%d.0.0"}[i%3]
		net = fmt.Sprintf(pat, i%23)
	case "24":
		pat := []string{"10.%d.%d.0", "192.%d.%d.0", "244.%d.%d.0"}[i%3]
		net = fmt.Sprintf(pat, i%23, i%119)
	case "28":
		pat := []string{"10.%d.%d.%d", "192.%d.%d.%d", "244.%d.%d.%d"}[i%3]
		net = fmt.Sprintf(pat, i%23, i%119, i%15<<4)
	case "32":
		pat := []string{"10.%d.%d.%d", "192.%d.%d.%d", "244.%d.%d.%d"}[i%3]
		net = fmt.Sprintf(pat, i%23, i%119, i%253)
	}
	cidr := net + "/" + prefix
	return api.EgressDenyRule{
		EgressCommonRule: api.EgressCommonRule{
			ToCIDR: []api.CIDR{api.CIDR(cidr)},
		},
		ToPorts: []api.PortDenyRule{
			{
				Ports: []api.PortProtocol{
					{
						Port:     port,
						Protocol: api.ProtoTCP,
					},
				},
			},
		},
	}
}

func GenerateCIDRDenyRules(numRules int) (api.Rules, identity.IdentityMap) {
	parseFooLabel := labels.ParseSelectLabel("k8s:foo")
	fooSelector := api.NewESFromLabels(parseFooLabel)

	var rules api.Rules
	for i := 1; i <= numRules; i++ {
		uuid := k8stypes.UID(fmt.Sprintf("12bba160-ddca-13e8-%04x-0800273b04ff", i))
		rule := api.Rule{
			EndpointSelector: fooSelector,
			Egress:           []api.EgressRule{generateCIDREgressRule(i)},
			EgressDeny:       []api.EgressDenyRule{generateCIDREgressDenyRule(i + 773)},
			Labels:           utils.GetPolicyLabels("default", fmt.Sprintf("cidr-%d", i), uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules, generateCIDRIdentities(rules)
}

func BenchmarkRegenerateCIDRDenyPolicyRules(b *testing.B) {
	logger := hivetest.Logger(b)
	td := newTestData(logger)
	td.bootstrapRepo(GenerateCIDRDenyRules, 1000, b)
	ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
	owner := DummyOwner{logger: logger}
	b.ReportAllocs()

	for b.Loop() {
		epPolicy := ip.DistillPolicy(logger, owner, nil)
		owner.mapStateSize = epPolicy.policyMapState.Len()
		epPolicy.Ready()
	}
	ip.detach(true, 0)
	b.Logf("Number of MapState entries: %d\n", owner.mapStateSize)
}

func TestRegenerateCIDRDenyPolicyRules(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(logger)
	td.bootstrapRepo(GenerateCIDRDenyRules, 10, t)
	ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
	epPolicy := ip.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
	n := epPolicy.policyMapState.Len()
	epPolicy.Ready()
	ip.detach(true, 0)
	assert.Positive(t, n)
}

func TestL3WithIngressDenyWildcard(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(logger)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	policy := selPolicy.DistillPolicy(hivetest.Logger(t), DummyOwner{logger: hivetest.Logger(t)}, nil)
	policy.Ready()

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
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
					},
				}),
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{logger: hivetest.Logger(t)},
		// inherit this from the result as it is outside of the scope
		// of this test
		policyMapState:   policy.policyMapState,
		policyMapChanges: MapChanges{logger: logger},
	}

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.detach(true, 0)

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

func TestL3WithLocalHostWildcardd(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(logger)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)
	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
	policy.Ready()

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
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
					},
				}),
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{logger: logger},
		// inherit this from the result as it is outside of the scope
		// of this test
		policyMapState:   policy.policyMapState,
		policyMapChanges: MapChanges{logger: logger},
	}

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.detach(true, 0)

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

func TestMapStateWithIngressDenyWildcard(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(logger)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
	policy.Ready()

	rule1MapStateEntry := denyEntry().withLabels(labels.LabelArrayList{ruleLabel})
	allowEgressMapStateEntry := newAllowEntryWithLabels(ruleLabelAllowAnyEgress)

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
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {ruleLabel}}),
					},
				}),
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{logger: logger},
		policyMapState: emptyMapState(logger).withState(mapStateMap{
			// Although we have calculated deny policies, the overall policy
			// will still allow egress to world.
			EgressKey():                  allowEgressMapStateEntry,
			IngressKey().WithTCPPort(80): rule1MapStateEntry,
		}),
		policyMapChanges: MapChanges{logger: logger},
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
	require.Empty(t, policy.policyMapChanges.synced)

	// Have to remove circular reference before testing to avoid an infinite loop
	policy.selectorPolicy.detach(true, 0)

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

func TestMapStateWithIngressDeny(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(logger)
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

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()
	selPolicy, err := repo.resolvePolicyLocked(fooIdentity)
	require.NoError(t, err)

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
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

	rule1MapStateEntry := denyEntry().withLabels(labels.LabelArrayList{ruleLabel})
	allowEgressMapStateEntry := newAllowEntryWithLabels(ruleLabelAllowAnyEgress)

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
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							cachedSelectorWorld:   &PerSelectorPolicy{IsDeny: true},
							cachedSelectorWorldV4: &PerSelectorPolicy{IsDeny: true},
							cachedSelectorWorldV6: &PerSelectorPolicy{IsDeny: true},
							cachedSelectorTest:    &PerSelectorPolicy{IsDeny: true},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld:   {ruleLabel},
							cachedSelectorWorldV4: {ruleLabel},
							cachedSelectorWorldV6: {ruleLabel},
							cachedSelectorTest:    {ruleLabel},
						}),
					},
				}),
					features: denyRules,
				},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
		},
		PolicyOwner: DummyOwner{logger: logger},
		policyMapState: emptyMapState(logger).withState(mapStateMap{
			// Although we have calculated deny policies, the overall policy
			// will still allow egress to world.
			EgressKey(): allowEgressMapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorld).WithTCPPort(80):     rule1MapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorldIPv4).WithTCPPort(80): rule1MapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorldIPv6).WithTCPPort(80): rule1MapStateEntry,
			IngressKey().WithIdentity(192).WithTCPPort(80):                                rule1MapStateEntry,
			IngressKey().WithIdentity(194).WithTCPPort(80):                                rule1MapStateEntry,
		}),
		policyMapChanges: MapChanges{logger: logger},
	}

	closer, changes := policy.ConsumeMapChanges()
	closer()
	// maps on the policy got cleared

	require.Equal(t, Keys{
		ingressKey(192, 6, 80, 0): {},
		ingressKey(194, 6, 80, 0): {},
	}, changes.Adds)
	require.Equal(t, Keys{}, changes.Deletes)

	// Have to remove circular reference before testing for Equality to avoid an infinite loop
	policy.selectorPolicy.detach(true, 0)
	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	cachedSelectorTest = td.sc.FindCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.Nil(t, cachedSelectorTest)

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
