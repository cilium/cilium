// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strconv"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	k8stypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/endpoint/regeneration"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/utils"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	pkgTypes "github.com/cilium/cilium/pkg/types"
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
	for i := range numIdentities {
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

		c[numericIdentity] = identityLabels
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
	// barSelector := api.NewESFromLabels(labels.ParseSelectLabel("bar"))

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

func GenerateUniqueRules(numRules int) (api.Rules, identity.IdentityMap) {
	var rules api.Rules
	uuid := k8stypes.UID("12bba160-ddca-13e8-b697-0800273b04ff")
	for i := 1; i <= numRules; i++ {
		uniqSelector := api.NewESFromLabels(labels.NewLabel("k8s", "value", strconv.FormatInt(int64(i), 10)))
		rule := api.Rule{
			EndpointSelector: uniqSelector,
			Egress:           []api.EgressRule{generateCIDREgressRule(i)},
			Labels:           utils.GetPolicyLabels("default", "cidr", uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules, generateCIDRIdentities(rules)
}

func GenerateMatchAllRules(numRules int) (api.Rules, identity.IdentityMap) {
	var rules api.Rules
	uuid := k8stypes.UID("12bba160-ddca-13e8-b697-0800273b04ff")
	for i := 1; i <= numRules; i++ {
		matchAll := api.NewESFromMatchRequirements(nil, []slim_metav1.LabelSelectorRequirement{{Key: "key", Operator: slim_metav1.LabelSelectorOpDoesNotExist}})
		rule := api.Rule{
			EndpointSelector: matchAll,
			Egress:           []api.EgressRule{generateCIDREgressRule(i)},
			Labels:           utils.GetPolicyLabels("default", "cidr", uuid, utils.ResourceTypeCiliumNetworkPolicy),
		}
		rule.Sanitize()
		rules = append(rules, &rule)
	}
	return rules, generateCIDRIdentities(rules)
}

type DummyOwner struct {
	logger      *slog.Logger
	previousMap *mapState
}

func (d DummyOwner) CreateRedirects(*L4Filter) {
}

func (d DummyOwner) GetIngressNamedPort(name string, proto u8proto.U8proto) uint16 {
	return 80
}

func (d DummyOwner) GetID() uint64 {
	return 1234
}

func (d DummyOwner) IsHost() bool {
	return false
}

func (d DummyOwner) PreviousMapState() *MapState {
	return d.previousMap
}

func (_ DummyOwner) RegenerateIfAlive(_ *regeneration.ExternalRegenerationMetadata) <-chan bool {
	ch := make(chan bool)
	close(ch)
	return ch
}

func (d DummyOwner) PolicyDebug(msg string, attrs ...any) {
	d.logger.Debug(msg, attrs...)
}

func (td *testData) bootstrapRepo(ruleGenFunc func(int) (api.Rules, identity.IdentityMap), numRules int, _ testing.TB) {
	SetPolicyEnabled(option.DefaultEnforcement)
	wg := &sync.WaitGroup{}
	// load in standard reserved identities
	c := identity.IdentityMap{
		fooIdentity.ID: fooIdentity.Labels,
	}
	identity.IterateReservedIdentities(func(ni identity.NumericIdentity, id *identity.Identity) {
		c[ni] = id.Labels
	})
	td.sc.UpdateIdentities(c, nil, wg)
	td.subjectSc.UpdateIdentities(c, nil, wg)

	if ruleGenFunc != nil {
		apiRules, ids := ruleGenFunc(numRules)
		td.sc.UpdateIdentities(ids, nil, wg)
		td.subjectSc.UpdateIdentities(ids, nil, wg)
		wg.Wait()
		td.repo.MustAddList(apiRules)
	}
}

func BenchmarkResolveCIDRPolicyRules(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateCIDRRules, 1000, b)

	b.ReportAllocs()
	for b.Loop() {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		ip.Detach()
	}
}

func BenchmarkResolveNoMatchingRules(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateUniqueRules, 20000, b)

	b.ReportAllocs()
	for b.Loop() {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		ip.Detach()
	}
}

func BenchmarkRegenerateCIDRPolicyRules(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateCIDRRules, 1000, b)
	ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
	owner := DummyOwner{logger: hivetest.Logger(b)}
	b.ReportAllocs()

	for b.Loop() {
		epPolicy := ip.DistillPolicy(hivetest.Logger(b), owner, nil)
		owner.previousMap = epPolicy.GetMapState()
		epPolicy.Ready()
	}
	ip.Detach()
	assert.Equal(b, 44596, owner.previousMap.Len())
}

func BenchmarkResolveL3IngressPolicyRules(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateL3IngressRules, 1000, b)

	b.ReportAllocs()
	for b.Loop() {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		ip.Detach()
	}
}

func BenchmarkRegenerateL3IngressPolicyRules(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateL3IngressRules, 1000, b)

	for b.Loop() {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		policy := ip.DistillPolicy(hivetest.Logger(b), DummyOwner{logger: hivetest.Logger(b)}, nil)
		policy.Ready()
		ip.Detach()
	}
}

func BenchmarkRegenerateL3EgressPolicyRules(b *testing.B) {
	td := newTestData(b, hivetest.Logger(b))
	td.bootstrapRepo(GenerateL3EgressRules, 1000, b)

	for b.Loop() {
		ip, _ := td.repo.resolvePolicyLocked(fooIdentity)
		policy := ip.DistillPolicy(hivetest.Logger(b), DummyOwner{logger: hivetest.Logger(b)}, nil)
		policy.Ready()
		ip.Detach()
	}
}

func TestEgressCIDRTCPPort(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)
	repo := td.repo

	td.bootstrapRepo(nil, 1, t)

	idFooSelectLabels := labels.ParseSelectLabelArray("id=foo").Labels()
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)
	td.addIdentity(fooIdentity)

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"10.1.1.1"},
				},
				ToPorts: []api.PortRule{{
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
	require.Equal(t, redirectTypeNone, selPolicy.L4Policy.redirectTypes)

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, testRedirects)
	policy.Ready()

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
		SelectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Egress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Tier:     types.Normal,
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						Ingress:  false,
						PerSelectorPolicies: L7DataMap{
							td.cachedSelectorCIDR: nil,
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorCIDR: {nil}}),
					},
				})},
				Ingress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: false,
			EgressPolicyEnabled:  true,
		},
		PolicyOwner: DummyOwner{logger: logger},
	}

	mdl := repo.GetRulesList()
	require.Contains(t, mdl.Policy, "10.1.1.1")

	td.assertEqualPolicies(t, &expectedEndpointPolicy, policy)
}

type testNamedPortsGetter struct {
	npm pkgTypes.NamedPortMultiMap
}

func (g testNamedPortsGetter) GetNamedPorts() pkgTypes.NamedPortMultiMap {
	return g.npm
}

func TestGetEgressNamedPorts(t *testing.T) {
	namedPorts := pkgTypes.NewNamedPortMultiMap()
	nid1 := identity.NumericIdentity(101)
	nid2 := identity.NumericIdentity(102)
	require.True(t, namedPorts.Update(nid1, nil, pkgTypes.NamedPortMap{
		"http": pkgTypes.PortProto{Port: 8080, Proto: u8proto.TCP},
	}))
	require.True(t, namedPorts.Update(nid1, nil, pkgTypes.NamedPortMap{
		"http": pkgTypes.PortProto{Port: 9090, Proto: u8proto.TCP},
	}))
	require.True(t, namedPorts.Update(nid2, nil, pkgTypes.NamedPortMap{
		"http": pkgTypes.PortProto{Port: 9090, Proto: u8proto.TCP},
	}))

	sp := newSelectorPolicy(testNewSelectorCache(t, hivetest.Logger(t), nil))
	sp.namedPortsGetter = testNamedPortsGetter{npm: namedPorts}

	portsByNID := map[identity.NumericIdentity]uint16{}
	for destID, port := range sp.GetEgressNamedPorts("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{nid1, nid2, 103})) {
		require.NotContains(t, portsByNID, destID)
		portsByNID[destID] = port
	}
	require.Equal(t, map[identity.NumericIdentity]uint16{
		nid2: 9090,
	}, portsByNID)

	portsByNID = map[identity.NumericIdentity]uint16{}
	for destID, port := range sp.GetEgressNamedPorts("http", u8proto.UDP, slices.Values([]identity.NumericIdentity{nid1, nid2})) {
		require.NotContains(t, portsByNID, destID)
		portsByNID[destID] = port
	}
	require.Empty(t, portsByNID)

	portsByNID = map[identity.NumericIdentity]uint16{}
	for destID, port := range sp.GetEgressNamedPorts("http", u8proto.TCP, slices.Values([]identity.NumericIdentity{103})) {
		require.NotContains(t, portsByNID, destID)
		portsByNID[destID] = port
	}
	require.Empty(t, portsByNID)
}

func TestEgressWildcardCIDRMatchesWorld(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger).withIDs(ruleTestIDs, identity.ListReservedIdentities())
	repo := td.repo

	td.bootstrapRepo(nil, 1, t)

	idFooLabels := labels.ParseLabelArray("id=foo").Labels()
	fooIdentity := identity.NewIdentity(12345, idFooLabels)
	td.addIdentity(fooIdentity)

	cidr1111Labels := labels.GetCIDRLabels(netip.MustParsePrefix("1.1.1.1/32"))
	cidr1111Identity := identity.NewIdentity(identity.IdentityScopeLocal, cidr1111Labels)
	td.addIdentity(cidr1111Identity)

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	rule1 := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{"0.0.0.0/0"},
				},
				ToPorts: []api.PortRule{{
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
	require.Equal(t, redirectTypeNone, selPolicy.L4Policy.redirectTypes)

	mdl := repo.GetRulesList()
	require.Contains(t, mdl.Policy, "0.0.0.0")

	expectedPolicy := &selectorPolicy{
		Revision:      repo.GetRevision(),
		SelectorCache: repo.GetSelectorCache(),
		L4Policy: L4Policy{
			Revision: repo.GetRevision(),
			Egress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
				"80/TCP": {
					Tier:     types.Normal,
					Port:     80,
					Protocol: api.ProtoTCP,
					U8Proto:  0x6,
					Ingress:  false,
					PerSelectorPolicies: L7DataMap{
						td.cachedSelectorCIDR0: nil,
					},
					RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorCIDR0: {nil}}),
				},
			})},
			Ingress: newL4DirectionPolicy(),
		},
		IngressPolicyEnabled: false,
		EgressPolicyEnabled:  true,
	}

	td.assertEqualPolicies(t, expectedPolicy, selPolicy)

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, testRedirects)
	policy.Ready()

	// test that policy matches world-ipv4 due to the wildcard CIDR
	entry, found := policy.policyMapState.Get(HttpEgressKey(identity.ReservedIdentityWorldIPv4))
	require.True(t, found)
	require.False(t, entry.IsDeny())

	// test that policy matches CIDR 1.1.1.1 due to the wildcard CIDR
	entry, found = policy.policyMapState.Get(HttpEgressKey(cidr1111Identity.ID))
	require.True(t, found)
	require.False(t, entry.IsDeny())
}

func TestL7WithIngressWildcard(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)
	repo := td.repo

	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

	idFooSelectLabels := labels.ParseSelectLabelArray("id=foo").Labels()
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

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, testRedirects)
	policy.Ready()

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
		SelectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Tier:     types.Normal,
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{
								Verdict:          types.Allow,
								L7Parser:         ParserTypeHTTP,
								ListenerPriority: ListenerPriorityHTTP,
								L7Rules: api.L7Rules{
									HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
								},
							},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
					},
				})},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{logger: logger},
	}

	td.assertEqualPolicies(t, &expectedEndpointPolicy, policy)
}

func TestL7WithLocalHostWildcard(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)
	repo := td.repo

	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

	idFooSelectLabels := labels.ParseSelectLabelArray("id=foo").Labels()
	fooIdentity := identity.NewIdentity(12345, idFooSelectLabels)
	td.addIdentity(fooIdentity)

	// Emulate Kubernetes mode with allow from localhost
	oldLocalhostOpt := option.Config.UnsafeDaemonConfigOption.AllowLocalhost
	option.Config.UnsafeDaemonConfigOption.AllowLocalhost = option.AllowLocalhostAlways
	defer func() { option.Config.UnsafeDaemonConfigOption.AllowLocalhost = oldLocalhostOpt }()

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

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, testRedirects)
	policy.Ready()

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
		SelectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					api.PortProtocolAny: {
						Tier:     types.DefaultPolicy,
						Protocol: api.ProtoAny,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.cachedSelectorHost: &PerSelectorPolicy{
								Verdict:  types.Allow,
								Priority: 10,
							},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorHost: {nil}}),
					},
					"80/TCP": {
						Tier:     types.Normal,
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							td.wildcardCachedSelector: &PerSelectorPolicy{
								Verdict:          types.Allow,
								L7Parser:         ParserTypeHTTP,
								ListenerPriority: ListenerPriorityHTTP,
								L7Rules: api.L7Rules{
									HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/good"}},
								},
							},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
					},
				})},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{logger: logger},
	}

	td.assertEqualPolicies(t, &expectedEndpointPolicy, policy)
}

func TestMapStateWithIngressWildcard(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

	ruleLabel := labels.ParseLabelArray("rule-foo-allow-port-80")
	ruleLabelAllowAnyEgress := labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
	}

	idFooSelectLabels := labels.ParseSelectLabelArray("id=foo").Labels()
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

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, testRedirects)
	policy.Ready()

	rule1MapStateEntry := newAllowEntryWithLabels(ruleLabel)
	allowEgressMapStateEntry := newAllowEntryWithLabels(ruleLabelAllowAnyEgress)

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
		SelectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Tier:     types.Normal,
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
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
		PolicyOwner: DummyOwner{logger: logger},
		policyMapState: emptyMapState(logger).withState(mapStateMap{
			EgressKey():                  allowEgressMapStateEntry,
			IngressKey().WithTCPPort(80): rule1MapStateEntry,
		}),
	}

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabels("id=resolve_test_1"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	require.Empty(t, policy.policyMapChanges.synced)

	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equal(&expectedEndpointPolicy.policyMapState), policy.policyMapState.diff(&expectedEndpointPolicy.policyMapState))

	td.assertEqualPolicies(t, &expectedEndpointPolicy, policy)
}

func TestMapStateWithIngress(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)
	repo := td.repo
	td.bootstrapRepo(GenerateL3IngressRules, 1000, t)

	ruleLabel := labels.ParseLabelArray("rule-world-allow-port-80")
	ruleLabelAllowAnyEgress := labels.LabelArray{
		labels.NewLabel(LabelKeyPolicyDerivedFrom, LabelAllowAnyEgress, labels.LabelSourceReserved),
	}

	idFooSelectLabels := labels.ParseSelectLabelArray("id=foo").Labels()
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

	policy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, testRedirects)
	policy.Ready()

	// Add new identity to test accumulation of MapChanges
	added1 := identity.IdentityMap{
		identity.NumericIdentity(192): labels.ParseSelectLabels("id=resolve_test_1", "num=1"),
		identity.NumericIdentity(193): labels.ParseSelectLabels("id=resolve_test_1", "num=2"),
		identity.NumericIdentity(194): labels.ParseSelectLabels("id=resolve_test_1", "num=3"),
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(added1, nil, wg)
	wg.Wait()
	require.Len(t, policy.policyMapChanges.synced, 3)

	deleted1 := identity.IdentityMap{
		identity.NumericIdentity(193): labels.ParseSelectLabels("id=resolve_test_1", "num=2"),
	}
	wg = &sync.WaitGroup{}
	td.sc.UpdateIdentities(nil, deleted1, wg)
	wg.Wait()
	require.Len(t, policy.policyMapChanges.synced, 4)

	cachedSelectorWorld := td.sc.findCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorld])
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := td.sc.findCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := td.sc.findCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

	cachedSelectorTest := td.sc.findCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.NotNil(t, cachedSelectorTest)

	rule1MapStateEntry := newAllowEntryWithLabels(ruleLabel)
	allowEgressMapStateEntry := newAllowEntryWithLabels(ruleLabelAllowAnyEgress)

	expectedEndpointPolicy := EndpointPolicy{
		Redirects: testRedirects,
		SelectorPolicy: &selectorPolicy{
			Revision:      repo.GetRevision(),
			SelectorCache: repo.GetSelectorCache(),
			L4Policy: L4Policy{
				Revision: repo.GetRevision(),
				Ingress: L4DirectionPolicy{PortRules: NewL4PolicyMapWithValues(map[string]*L4Filter{
					"80/TCP": {
						Tier:     types.Normal,
						Port:     80,
						Protocol: api.ProtoTCP,
						U8Proto:  0x6,
						Ingress:  true,
						PerSelectorPolicies: L7DataMap{
							cachedSelectorWorld:   nil,
							cachedSelectorWorldV4: nil,
							cachedSelectorWorldV6: nil,
							cachedSelectorTest: &PerSelectorPolicy{
								Verdict: types.Allow,
								Authentication: &api.Authentication{
									Mode: api.AuthenticationModeDisabled,
								},
							},
						},
						RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
							cachedSelectorWorld:   {ruleLabel},
							cachedSelectorWorldV4: {ruleLabel},
							cachedSelectorWorldV6: {ruleLabel},
							cachedSelectorTest:    {ruleLabel},
						}),
					},
				})},
				Egress: newL4DirectionPolicy(),
			},
			IngressPolicyEnabled: true,
			EgressPolicyEnabled:  false,
		},
		PolicyOwner: DummyOwner{logger: logger},
		policyMapState: emptyMapState(logger).withState(mapStateMap{
			EgressKey(): allowEgressMapStateEntry,
			IngressKey().WithIdentity(identity.ReservedIdentityWorld).WithTCPPort(80): rule1MapStateEntry,
			IngressKey().WithIdentity(192).WithTCPPort(80):                            rule1MapStateEntry.withExplicitAuth(AuthTypeDisabled),
			IngressKey().WithIdentity(194).WithTCPPort(80):                            rule1MapStateEntry.withExplicitAuth(AuthTypeDisabled),
		}),
	}

	// Verify that cached selector is not found after Detach().
	// Note that this depends on the other tests NOT using the same selector concurrently!
	policy.SelectorPolicy.Detach()
	cachedSelectorTest = td.sc.findCachedIdentitySelector(api.NewESFromLabels(lblTest))
	require.Nil(t, cachedSelectorTest)

	closer, changes := policy.ConsumeMapChanges()
	closer()

	// maps on the policy got cleared
	require.Nil(t, policy.policyMapChanges.synced)

	require.Equal(t, Keys{
		ingressKey(192, 6, 80, 0): {},
		ingressKey(194, 6, 80, 0): {},
	}, changes.Adds)
	require.Equal(t, Keys{}, changes.Deletes)

	// policyMapState cannot be compared via DeepEqual
	require.Truef(t, policy.policyMapState.Equal(&expectedEndpointPolicy.policyMapState), policy.policyMapState.diff(&expectedEndpointPolicy.policyMapState))

	td.assertEqualPolicies(t, &expectedEndpointPolicy, policy)
}

// allowsIdentity returns whether the specified policy allows
// ingress and egress traffic for the specified numeric security identity.
// If the 'secID' is zero, it will check if all traffic is allowed.
//
// Returning true for either return value indicates all traffic is allowed.
func (p *EndpointPolicy) allowsIdentity(identity identity.NumericIdentity) (ingress, egress bool) {
	if !p.SelectorPolicy.IngressPolicyEnabled {
		ingress = true
	} else {
		key := IngressKey().WithIdentity(identity)
		if v, exists := p.policyMapState.Get(key); exists && !v.IsDeny() {
			ingress = true
		}
	}

	if !p.SelectorPolicy.EgressPolicyEnabled {
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
	logger := hivetest.Logger(t)
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
				PolicyMapState: emptyMapState(logger),
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
				PolicyMapState: emptyMapState(logger),
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
				PolicyMapState: emptyMapState(logger).withState(mapStateMap{
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
				PolicyMapState: emptyMapState(logger).withState(mapStateMap{
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
				PolicyMapState: emptyMapState(logger).withState(mapStateMap{
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
				PolicyMapState: emptyMapState(logger).withState(mapStateMap{
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
				PolicyMapState: emptyMapState(logger).withState(mapStateMap{
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
				PolicyMapState: emptyMapState(logger).withState(mapStateMap{
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
				SelectorPolicy: tt.fields.selectorPolicy,
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

func TestEndpointPolicy_GetRuleMeta(t *testing.T) {
	log := hivetest.Logger(t)

	key1 := ingressKey(192, 6, 80, 0)
	key2 := ingressKey(193, 6, 80, 0)

	lbls := labels.ParseLabelArray("k8s:k=v")
	lblss := labels.LabelArrayList{lbls}
	logstr := "log"
	logstrs := []string{logstr}

	// test empty map state
	p := &EndpointPolicy{
		policyMapState: emptyMapState(log),
	}
	_, err := p.GetRuleMeta(key1)
	require.Error(t, err)

	// test non-empty mapstate
	p.policyMapState = emptyMapState(log).withState(mapStateMap{
		key1: newMapStateEntry(0, types.HighestPriority, types.LowestPriority, makeSingleRuleOrigin(lbls, logstr), 0, 0, types.Allow, NoAuthRequirement),
	})

	rm, err := p.GetRuleMeta(key1)
	require.NoError(t, err)
	require.Equal(t, rm.LabelArray(), lblss)
	require.Equal(t, rm.Log(), logstrs)

	_, err = p.GetRuleMeta(key2)
	require.Error(t, err)

	// test mapstate from dump
	msDump := MapStateMap{
		key1: types.NewMapStateEntry(0, false, 0, 0, NoAuthRequirement),
	}

	p = &EndpointPolicy{
		policyMapState: emptyMapState(log),
	}

	p.CopyMapStateFrom(msDump)
	rm, err = p.GetRuleMeta(key1)
	require.NoError(t, err)
	require.Equal(t, NilRuleOrigin.Value(), rm)
}

func TestEndpointPolicy_Lookup_PortRange(t *testing.T) {
	log := hivetest.Logger(t)

	rangeEntry := ingressKey(192, 6, 64, 10)
	flowKey := ingressKey(192, 6, 80, 16)

	lbls := labels.ParseLabelArray("k8s:io.cilium.k8s.policy.name=allow-egress-port-range")
	lblss := labels.LabelArrayList{lbls}

	p := &EndpointPolicy{
		policyMapState: emptyMapState(log).withState(mapStateMap{
			rangeEntry: newMapStateEntry(0, types.HighestPriority, types.LowestPriority, makeSingleRuleOrigin(lbls, "log"), 0, 0, types.Allow, NoAuthRequirement),
		}),
	}

	_, rm, found := p.Lookup(flowKey)
	require.True(t, found, "Lookup for a port inside a stored range should succeed")
	require.Equal(t, lblss, rm.LabelArray(),
		"rule meta should come from the covering port-range entry")

	outOfRangeKey := ingressKey(192, 6, 200, 16)
	_, _, found = p.Lookup(outOfRangeKey)
	require.False(t, found, "Lookup for a port outside the stored range should miss")
}

// TestEndpointPolicy_Lookup_PortRange_L4Only covers the L4-only side of the
// L3-vs-L4 precedence in mapState.lookup: when the stored entry has identity
// zero and a port range, a flow keyed by a specific port inside that range
// must still resolve to it.
func TestEndpointPolicy_Lookup_PortRange_L4Only(t *testing.T) {
	log := hivetest.Logger(t)

	// L4-only range entry: identity == 0, port 64-127, TCP.
	rangeEntry := ingressKey(0, 6, 64, 10)
	flowKey := ingressKey(0, 6, 80, 16)

	lbls := labels.ParseLabelArray("k8s:io.cilium.k8s.policy.name=allow-l4only-port-range")
	lblss := labels.LabelArrayList{lbls}

	p := &EndpointPolicy{
		policyMapState: emptyMapState(log).withState(mapStateMap{
			rangeEntry: newMapStateEntry(0, types.HighestPriority, types.LowestPriority, makeSingleRuleOrigin(lbls, "log"), 0, 0, types.Allow, NoAuthRequirement),
		}),
	}

	_, rm, found := p.Lookup(flowKey)
	require.True(t, found, "L4Only Lookup for a port inside a stored range should succeed")
	require.Equal(t, lblss, rm.LabelArray(),
		"rule meta should come from the covering port-range entry")
}
