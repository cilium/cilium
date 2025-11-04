// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"
	k8sTypes "k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/container/set"
	"github.com/cilium/cilium/pkg/crypto/certificatemanager"
	envoypolicy "github.com/cilium/cilium/pkg/envoy/policy"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/policy/utils"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

var (
	hostSelector = api.ReservedEndpointSelectors[labels.IDNameHost]

	dummySelectorCacheUser = &testpolicy.DummySelectorCacheUser{}
	fooSelector            = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	bazSelector            = api.NewESFromLabels(labels.ParseSelectLabel("baz"))

	selBar1 = api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 = api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	falseValue = false
)

type testData struct {
	sc              *SelectorCache
	subjectSc       *SelectorCache
	repo            *Repository
	identityManager identitymanager.IDManager

	idSet set.Set[identity.NumericIdentity]

	testPolicyContext *testPolicyContextType

	cachedSelectorA        CachedSelector
	cachedSelectorB        CachedSelector
	cachedSelectorC        CachedSelector
	cachedSelectorHost     CachedSelector
	wildcardCachedSelector CachedSelector
	cachedSelectorCIDR     CachedSelector
	cachedSelectorCIDR0    CachedSelector

	cachedFooSelector CachedSelector
	cachedBazSelector CachedSelector

	cachedSelectorBar1 CachedSelector
	cachedSelectorBar2 CachedSelector

	cachedSelectorWorld   CachedSelector
	cachedSelectorWorldV4 CachedSelector
	cachedSelectorWorldV6 CachedSelector
}

func newTestData(tb testing.TB, logger *slog.Logger) *testData {
	idMgr := identitymanager.NewIDManager(logger)
	td := &testData{
		identityManager:   idMgr,
		sc:                testNewSelectorCache(tb, logger, nil),
		subjectSc:         testNewSelectorCache(tb, logger, nil),
		repo:              NewPolicyRepository(logger, nil, &fakeCertificateManager{}, envoypolicy.NewEnvoyL7RulesTranslator(logger, certificatemanager.NewMockSecretManagerInline()), idMgr, testpolicy.NewPolicyMetricsNoop()),
		idSet:             set.NewSet[identity.NumericIdentity](),
		testPolicyContext: &testPolicyContextType{logger: logger},
	}
	td.repo.selectorCache = td.sc
	td.repo.subjectSelectorCache = td.subjectSc
	td.testPolicyContext.sc = td.sc

	td.wildcardCachedSelector, _ = td.sc.AddIdentitySelectorForTest(dummySelectorCacheUser, EmptyStringLabels, api.WildcardEndpointSelector)
	td.sc.AddIdentitySelectorForTest(dummySelectorCacheUser, EmptyStringLabels, api.WildcardEndpointSelector)

	td.cachedSelectorCIDR = func(cidr api.CIDR) CachedSelector {
		css, _ := td.sc.AddSelectors(dummySelectorCacheUser, EmptyStringLabels, types.ToSelector(cidr))
		return css[0]
	}(api.CIDR("10.1.1.1"))

	td.cachedSelectorCIDR0 = func(cidr api.CIDR) CachedSelector {
		css, _ := td.sc.AddSelectors(dummySelectorCacheUser, EmptyStringLabels, types.ToSelector(cidr))
		return css[0]
	}(api.CIDR("0.0.0.0/0"))

	td.cachedSelectorA = td.getCachedSelectorForTest(endpointSelectorA)
	td.cachedSelectorB = td.getCachedSelectorForTest(endpointSelectorB)
	td.cachedSelectorC = td.getCachedSelectorForTest(endpointSelectorC)
	td.cachedSelectorHost = td.getCachedSelectorForTest(hostSelector)

	td.cachedFooSelector = td.getCachedSelectorForTest(fooSelector)
	td.cachedBazSelector = td.getCachedSelectorForTest(bazSelector)

	td.cachedSelectorBar1 = td.getCachedSelectorForTest(selBar1)
	td.cachedSelectorBar2 = td.getCachedSelectorForTest(selBar2)

	td.cachedSelectorWorld = td.getCachedSelectorForTest(api.EntitySelectorMapping[api.EntityWorld][0])
	td.cachedSelectorWorldV4 = td.getCachedSelectorForTest(api.EntitySelectorMapping[api.EntityWorldIPv4][0])
	td.cachedSelectorWorldV6 = td.getCachedSelectorForTest(api.EntitySelectorMapping[api.EntityWorldIPv6][0])

	td.repo.policyCache.insert(idA)
	td.repo.policyCache.insert(idB)
	td.repo.policyCache.insert(idC)

	return td
}

func (td *testData) getCachedSelectorForTest(es api.EndpointSelector) CachedSelector {
	cs, _ := td.sc.AddIdentitySelectorForTest(dummySelectorCacheUser, EmptyStringLabels, es)
	return cs
}

// withIDs loads the set of IDs in to the SelectorCache. Returns
// the same testData for easy chaining.
func (td *testData) withIDs(initIDs ...identity.IdentityMap) *testData {
	initial := identity.IdentityMap{}
	for _, im := range initIDs {
		maps.Copy(initial, im)
	}
	for id, lbls := range initial {
		td.identityManager.Add(&identity.Identity{ID: id, Labels: lbls.Labels(), LabelArray: lbls})
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(initial, nil, wg)
	wg.Wait()

	for id := range initial {
		td.idSet.Insert(id)
	}
	return td
}

func (td *testData) addIdentity(id *identity.Identity) {
	wg := &sync.WaitGroup{}
	td.subjectSc.UpdateIdentities(
		identity.IdentityMap{
			id.ID: id.LabelArray,
		}, nil, wg)
	td.sc.UpdateIdentities(
		identity.IdentityMap{
			id.ID: id.LabelArray,
		}, nil, wg)
	wg.Wait()
	td.idSet.Insert(id.ID)
}

func (td *testData) removeIdentity(id *identity.Identity) {
	wg := &sync.WaitGroup{}
	td.subjectSc.UpdateIdentities(
		nil,
		identity.IdentityMap{
			id.ID: id.LabelArray,
		}, wg)
	td.sc.UpdateIdentities(
		nil,
		identity.IdentityMap{
			id.ID: id.LabelArray,
		}, wg)
	wg.Wait()
	td.idSet.Remove(id.ID)
}

func (td *testData) addIdentitySelector(sel api.EndpointSelector) bool {
	_, added := td.sc.AddIdentitySelectorForTest(dummySelectorCacheUser, EmptyStringLabels, sel)
	return added
}

func (td *testData) verifyL4PolicyMapEqual(t *testing.T, expected, actual L4PolicyMaps, availableIDs ...identity.NumericIdentity) {
	t.Helper()

	require.Len(t, expected, len(actual))
	for i := range expected {
		require.Equal(t, expected[i].Len(), actual[i].Len())
		expected[i].ForEach(func(l4 *L4Filter) bool {
			port := l4.PortName
			if len(port) == 0 {
				port = fmt.Sprintf("%d", l4.Port)
			}

			l4B := actual[i].ExactLookup(port, l4.EndPort, string(l4.Protocol))
			require.NotNil(t, l4B, "Port Protocol lookup failed: [Port: %s, EndPort: %d, Protocol: %s]", port, l4.EndPort, string(l4.Protocol))

			// If no available IDs are provided, we assume the same pointer for
			// cached selector is used for both expected and actual L4PolicyMap,
			// just make sure L4 filter is equal
			if len(availableIDs) == 0 {
				require.True(t, l4.Equals(l4B), "Expected: %s\nActual: %s", l4.String(), l4B.String())
				return true
			}

			require.Equal(t, l4.Tier, l4B.Tier)
			require.Equal(t, l4.Port, l4B.Port)
			require.Equal(t, l4.EndPort, l4B.EndPort)
			require.Equal(t, l4.PortName, l4B.PortName)
			require.Equal(t, l4.Protocol, l4B.Protocol)
			require.Equal(t, l4.Ingress, l4B.Ingress)
			require.Equal(t, l4.wildcard, l4B.wildcard)

			require.Len(t, l4B.PerSelectorPolicies, len(l4.PerSelectorPolicies))

			for k, v := range l4.PerSelectorPolicies {
				found := false
				for bK, bV := range l4B.PerSelectorPolicies {
					if k.String() == bK.String() {
						require.True(t, v.Equal(bV), "Expected: %s\nActual: %s", perSelectorPolicyToString(v), perSelectorPolicyToString(bV))

						selActual := bK.(*identitySelector).cachedSelections
						selExpected := make(map[identity.NumericIdentity]struct{})
						for id := range k.(*identitySelector).cachedSelections {
							if slices.Contains(availableIDs, id) {
								selExpected[id] = struct{}{}
							}
						}

						require.True(t, maps.Equal(selExpected, selActual), "Expected: %v\nActual: %v", selExpected, selActual)
						found = true
					}
				}

				require.True(t, found, "Failed to find expected cached selector in PerSelectorPolicy: %s (%v)", k.String(), l4B.PerSelectorPolicies)
			}

			return true
		})
	}
}

func (td *testData) validateResolvedPolicy(t *testing.T, selPolicy *selectorPolicy, epPolicy *EndpointPolicy, expectedIn, expectedOut L4PolicyMaps) {
	t.Helper()
	logger := hivetest.Logger(t)

	if expectedIn != nil {
		td.verifyL4PolicyMapEqual(t, expectedIn, selPolicy.L4Policy.Ingress.PortRules, td.idSet.AsSlice()...)
	}

	if expectedOut != nil {
		td.verifyL4PolicyMapEqual(t, expectedOut, selPolicy.L4Policy.Egress.PortRules, td.idSet.AsSlice()...)
	}

	// Resolve the policy again and compare against the inputs to verify incremental updates
	// are applied properly.
	sp, err := td.repo.resolvePolicyLocked(idA)
	require.NoError(t, err)

	epp := sp.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
	require.NotNil(t, epp)
	epp.Ready()

	closer, _ := epPolicy.ConsumeMapChanges()
	closer()
	epPolicy.Ready()

	require.True(t, epPolicy.policyMapState.Equal(&epp.policyMapState), epPolicy.policyMapState.diff(&epp.policyMapState))

	epp.Detach(logger)
}

// policyMapEquals takes a set of policies and an expected L4PolicyMap. The policies are assumed to
// select identity A.
//
// The repository is cleared when called.
func (td *testData) policyMapEquals(t *testing.T, expectedIn, expectedOut L4PolicyMaps, rules ...*api.Rule) {
	t.Helper()
	entries := utils.RulesToPolicyEntries(rules)
	td.policyMapEqualsPolicyEntries(t, expectedIn, expectedOut, entries...)
}

func (td *testData) policyMapEqualsPolicyEntries(t *testing.T, expectedIn, expectedOut L4PolicyMaps, entries ...*types.PolicyEntry) {
	t.Helper()
	logger := hivetest.Logger(t)

	// Initialize with test identity
	td.addIdentity(idA)
	defer td.removeIdentity(idA)

	// Add the rules to policy repository.
	for _, e := range entries {
		if e.Subject == nil {
			e.Subject = labelSelectorA
		}
	}
	td.repo.ReplaceByResource(entries, "dummy-resource")

	// Resolve the Selector policy for test identity
	td.repo.mutex.RLock()
	defer td.repo.mutex.RUnlock()

	selPolicy, err := td.repo.resolvePolicyLocked(idA)
	require.NoError(t, err)
	defer selPolicy.detach(true, 0)

	// Distill Selector policy to Endpoint Policy
	epPolicy := selPolicy.DistillPolicy(logger, DummyOwner{logger: logger}, nil)
	epPolicy.Ready()

	td.validateResolvedPolicy(t, selPolicy, epPolicy, expectedIn, expectedOut)

	// Incrementally add identities
	td.addIdentity(idB)
	td.addIdentity(idC)

	td.validateResolvedPolicy(t, selPolicy, epPolicy, expectedIn, expectedOut)

	// Incrementally delete identities
	td.removeIdentity(idB)
	td.removeIdentity(idC)

	td.validateResolvedPolicy(t, selPolicy, epPolicy, expectedIn, expectedOut)
}

// policyInvalid checks that the set of rules results in an error
func (td *testData) policyInvalid(t *testing.T, errStr string, rules ...*api.Rule) {
	t.Helper()
	td.withIDs(ruleTestIDs)
	for _, r := range rules {
		if r.EndpointSelector.LabelSelector == nil {
			r.EndpointSelector = endpointSelectorA
		}
		require.NoError(t, r.Sanitize())
	}
	td.repo.ReplaceByResource(utils.RulesToPolicyEntries(rules), "dummy-resource")

	_, err := td.repo.resolvePolicyLocked(idA)
	require.Error(t, err)
	require.ErrorContains(t, err, errStr)
}

// policyValid checks that the set of rules does not results in an error
func (td *testData) policyValid(t *testing.T, rules ...*api.Rule) {
	t.Helper()
	td.withIDs(ruleTestIDs)
	for _, r := range rules {
		if r.EndpointSelector.LabelSelector == nil {
			r.EndpointSelector = endpointSelectorA
		}
		require.NoError(t, r.Sanitize())
	}
	td.repo.ReplaceByResource(utils.RulesToPolicyEntries(rules), "dummy-resource")

	_, err := td.repo.resolvePolicyLocked(idA)
	require.NoError(t, err)
}

// testPolicyContexttype is a dummy context used when evaluating rules.
type testPolicyContextType struct {
	tier               types.Tier
	priority           types.Priority
	ns                 string
	sc                 *SelectorCache
	fromFile           bool
	defaultDenyIngress bool
	defaultDenyEgress  bool
	logger             *slog.Logger
}

func (p *testPolicyContextType) AllowLocalhost() bool {
	return option.Config.AlwaysAllowLocalhost()
}

func (p *testPolicyContextType) GetNamespace() string {
	return p.ns
}

func (p *testPolicyContextType) GetSelectorCache() *SelectorCache {
	return p.sc
}

func (p *testPolicyContextType) GetTLSContext(tls *api.TLSContext) (ca, public, private string, fromFile bool, err error) {
	switch tls.Secret.Name {
	case "tls-cert":
		return "", "fake public cert", "fake private key", p.fromFile, nil
	case "tls-ca-certs":
		return "fake CA certs", "", "", p.fromFile, nil
	}
	return "", "", "", p.fromFile, fmt.Errorf("Unknown test secret '%s'", tls.Secret.Name)
}

func (p *testPolicyContextType) GetEnvoyHTTPRules(*api.L7Rules) (*cilium.HttpNetworkPolicyRules, bool) {
	return nil, true
}

// SetPriority sets the precedence level for the first rule being processed.
func (p *testPolicyContextType) SetPriority(tier types.Tier, priority types.Priority) {
	p.tier = tier
	p.priority = priority
}

// Priority returns the precedence level for the current rule.
func (p *testPolicyContextType) Priority() (types.Tier, types.Priority) {
	return p.tier, p.priority
}

func (p *testPolicyContextType) DefaultDenyIngress() bool {
	return p.defaultDenyIngress
}

func (p *testPolicyContextType) DefaultDenyEgress() bool {
	return p.defaultDenyEgress
}

func (p *testPolicyContextType) GetLogger() *slog.Logger {
	return p.logger
}

func (p *testPolicyContextType) Origin() ruleOrigin {
	return NilRuleOrigin
}

func (p *testPolicyContextType) SetOrigin(ruleOrigin) {
	panic("SetOrigin not implemented")
}

func (p *testPolicyContextType) PolicyTrace(format string, a ...any) {
	p.logger.Info(fmt.Sprintf(format, a...))
}

func TestL3Wildcarding(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// A: Specify WildcardEndpointSelector explicitly.

	// Case A1: all identities with port 80 are selected
	ruleA1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected80 := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		Ingress: true, wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected80, nil, &ruleA1)

	// Case A2: All identities with wildcard TCP port are selected
	ruleA2 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "0", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected0 := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 0, Protocol: api.ProtoTCP, U8Proto: 6,
		Ingress: true, wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected0, nil, &ruleA2)

	// Case A3: All identities with wildcard port on any protocol are selected
	ruleA3 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
			},
		},
	}

	expectedAny := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 0, Protocol: api.ProtoAny, U8Proto: 0,
		Ingress: true, wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expectedAny, nil, &ruleA3)

	//
	// B: an empty non-nil FromEndpoints never selects anything
	//

	// CaseB1: No identities are selected with port 80
	ruleB1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}
	td.policyMapEquals(t, L4PolicyMaps{makeL4PolicyMap()}, nil, &ruleB1)

	// CaseB2: No identities are selected with wildcard port
	ruleB2 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "0", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}
	td.policyMapEquals(t, L4PolicyMaps{makeL4PolicyMap()}, nil, &ruleB2)

	// CaseB3: No identities are selected without L4
	ruleB3 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
			},
		},
	}
	td.policyMapEquals(t, L4PolicyMaps{makeL4PolicyMap()}, nil, &ruleB3)

	//
	// C: Nil FromEndpoints (No L3 specified): a wildcard selector is implicitly added when
	//    ports are specified.

	// CaseC1: All identities are selected with port 80
	ruleC1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}
	td.policyMapEquals(t, expected80, nil, &ruleC1)

	// CaseC2: All identiteis are selected with a wildcard port
	ruleC2 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "0", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}
	td.policyMapEquals(t, expected0, nil, &ruleC2)

	// CaseC3: No identities are selected without L4
	ruleC3 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{},
		},
	}
	td.policyMapEquals(t, L4PolicyMaps{makeL4PolicyMap()}, nil, &ruleC3)
}

// Tests in this file:
//
// How to read this table:
//   Case:  The test / subtest number.
//   L3:    Matches at L3 for rule 1,  followed by rule 2.
//   L4:    Matches at L4.
//   L7:    Rules at L7 for rule 1, followed by rule 2.
//   Notes: Extra information about the test.
//
// +-----+-----------------+----------+-----------------+------------------------------------------------------+
// |Case | L3 (1, 2) match | L4 match | L7 match (1, 2) | Notes                                                |
// +=====+=================+==========+=================+======================================================+
// |  1A |      *, *       |  80/TCP  |      *, *       | Allow all communication on the specified port        |
// |  1B |      -, -       |  80/TCP  |      *, *       | Deny all with an empty FromEndpoints slice           |
// |  2A |      *, *       |  80/TCP  |   *, "GET /"    | Rule 1 shadows rule 2                                |
// |  2B |      *, *       |  80/TCP  |   "GET /", *    | Same as 2A, but import in reverse order              |
// |  3  |      *, *       |  80/TCP  | "GET /","GET /" | Exactly duplicate rules (HTTP)                       |
// |  4  |      *, *       | 9092/TCP |   "foo","foo"   | Exactly duplicate rules (Kafka)                      |
// |  5A |      *, *       |  80/TCP  |  "foo","GET /"  | Rules with conflicting L7 parser                     |
// |  5B |      *, *       |  80/TCP  |  "GET /","foo"  | Same as 5A, but import in reverse order              |
// |  6A |   "id=a", *     |  80/TCP  |      *, *       | Rule 2 is a superset of rule 1                       |
// |  6B |   *, "id=a"     |  80/TCP  |      *, *       | Same as 6A, but import in reverse order              |
// |  7A |   "id=a", *     |  80/TCP  |   "GET /", *    | All traffic is allowed; traffic to A goes via proxy  |
// |  7B |   *, "id=a"     |  80/TCP  |   *, "GET /"    | Same as 7A, but import in reverse order              |
// |  8A |   "id=a", *     |  80/TCP  | "GET /","GET /" | Rule 2 is the same as rule 1, except matching all L3 |
// |  8B |   *, "id=a"     |  80/TCP  | "GET /","GET /" | Same as 8A, but import in reverse order              |
// |  9A |   "id=a", *     |  80/TCP  |  "foo","GET /"  | Rules with conflicting L7 parser (+L3 match)         |
// |  9B |   *, "id=a"     |  80/TCP  |  "GET /","foo"  | Same as 9A, but import in reverse order              |
// | 10  | "id=a", "id=c"  |  80/TCP  | "GET /","GET /" | Allow at L7 for two distinct labels (disjoint set)   |
// | 11  | "id=a", "id=c"  |  80/TCP  |      *, *       | Allow at L4 for two distinct labels (disjoint set)   |
// | 12  |     "id=a",     |  80/TCP  |     "GET /"     | Configure to allow localhost traffic always          |
// | 13  |      -, -       |  80/TCP  |      *, *       | Deny all with an empty ToEndpoints slice             |
// | 14  |      *, *       |  53/UDP  |  "example.com"  | DNS L7 rules with default-allow adds wildcard        |
// | 15  |      *, *       |  80/TCP  |     "GET /"     | HTTP L7 rules with default-allow adds empty rule     |
// | 16  |      *, *       | 9092/TCP |     "topic"     | Kafka L7 rules with default-allow adds empty topic   |
// | 17  |   "id=a", *     |  53/UDP  |  "example.com"  | DNS L7 + L3 filter with default-allow adds wildcard  |
// | 18  |      *, *       |  80/TCP  | "GET /", deny   | Default-allow doesn't add wildcard to deny rules     |
// +-----+-----------------+----------+-----------------+------------------------------------------------------+

func TestMergeAllowAllL3AndAllowAllL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 1A: Specify WildcardEndpointSelector explicitly.
	rule1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		Ingress: true, wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule1)

	// Case1B: an empty non-nil FromEndpoints does not select any identity.
	rule2 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	td.policyMapEquals(t, L4PolicyMaps{makeL4PolicyMap()}, nil, &rule2)

	// Case1C: nil FromEndpoints with non-wildcard port selects all identities.
	rule3 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	td.policyMapEquals(t, expected, nil, &rule3)
}

// Case 2: allow all at L3 in both rules. Allow all in one L7 rule, but second
// rule restricts at L7. Because one L7 rule allows at L7, all traffic is allowed
// at L7, but still redirected at the proxy.
// Should resolve to one rule.
func TestMergeAllowAllL3AndShadowedL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}, {}},
				},
			},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule1)

	// Case 2B: Flip order of case 2A so that rule being merged with is different
	// than rule being consumed.
	rule2 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}, {}},
				},
			},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule2)
}

// Case 3: allow all at L3 in both rules. Both rules have same parser type and
// same API resource specified at L7 for HTTP.
func TestMergeIdenticalAllowAllL3AndRestrictedL7HTTP(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	identicalHTTPRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &identicalHTTPRule)
}

// Case 4: identical allow all at L3 with identical restrictions on Kafka.
func TestMergeIdenticalAllowAllL3AndRestrictedL7Kafka(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	identicalKafkaRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"9092/TCP": {
		Port:     9092,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeKafka,
				ListenerPriority: ListenerPriorityKafka,
				L7Rules: api.L7Rules{
					Kafka: []kafka.PortRule{{Topic: "foo"}},
				},
			},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &identicalKafkaRule)
}

// Case 5: use conflicting protocols on the same port in different rules. This
// is not supported, so return an error.
func TestMergeIdenticalAllowAllL3AndMismatchingParsers(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 5A: Kafka first, HTTP second.
	conflictingParsersRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingParsersRule)

	// Case 5B: HTTP first, Kafka second.
	conflictingParsersRule = api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
		},
	}

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingParsersRule)

	// Case 5B+: HTTP first, generic L7 second.
	conflictingParsersIngressRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: api.EndpointSelectorSlice{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						L7Proto: "testing",
						L7: []api.PortRuleL7{
							{"method": "PUT", "path": "/Foo"},
						},
					},
				}},
			},
		},
	}

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingParsersIngressRule)

	// Case 5B++: generic L7 without rules first, HTTP second.
	conflictingParsersEgressRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						L7Proto: "testing",
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingParsersEgressRule)
}

// TLS policies with and without interception

// TLS policy without L7 rules does not inspect L7, uses L7ParserType "tls"
func TestMergeTLSTCPPolicy(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	egressRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					TerminatingTLS: &api.TLSContext{
						Secret: &api.Secret{
							Name: "tls-cert",
						},
					},
					OriginatingTLS: &api.TLSContext{
						Secret: &api.Secret{
							Name: "tls-ca-certs",
						},
					},
				}},
			},
		},
	}

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeTLS,
				ListenerPriority: ListenerPriorityTLS,
				TerminatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-cert",
					CertificateChain: "fake public key tls-cert",
					PrivateKey:       "fake private key tls-cert",
					Secret: k8sTypes.NamespacedName{
						Name: "tls-cert",
					},
				},
				OriginatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-ca-certs",
					CertificateChain: "fake public key tls-ca-certs",
					PrivateKey:       "fake private key tls-ca-certs",
					Secret: k8sTypes.NamespacedName{
						Name: "tls-ca-certs",
					},
				},
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &egressRule)
}

func TestMergeTLSHTTPPolicy(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	egressRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					TerminatingTLS: &api.TLSContext{
						Secret: &api.Secret{
							Name: "tls-cert",
						},
					},
					OriginatingTLS: &api.TLSContext{
						Secret: &api.Secret{
							Name: "tls-ca-certs",
						},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{}},
					},
				}},
			},
		},
	}

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				TerminatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-cert",
					CertificateChain: "fake public key tls-cert",
					PrivateKey:       "fake private key tls-cert",
					Secret: k8sTypes.NamespacedName{
						Name: "tls-cert",
					},
				},
				OriginatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-ca-certs",
					CertificateChain: "fake public key tls-ca-certs",
					PrivateKey:       "fake private key tls-ca-certs",
					Secret: k8sTypes.NamespacedName{
						Name: "tls-ca-certs",
					},
				},
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &egressRule)
}

func TestMergeTLSSNIPolicy(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	egressRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					TerminatingTLS: &api.TLSContext{
						Secret: &api.Secret{
							Name: "tls-cert",
						},
					},
					OriginatingTLS: &api.TLSContext{
						Secret: &api.Secret{
							Name: "tls-ca-certs",
						},
					},
					ServerNames: []api.ServerName{"www.foo.com"},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					ServerNames: []api.ServerName{"www.bar.com"},
				}, {
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{}},
					},
				}},
			},
		},
	}

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				TerminatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-cert",
					CertificateChain: "fake public key tls-cert",
					PrivateKey:       "fake private key tls-cert",
					Secret: k8sTypes.NamespacedName{
						Name: "tls-cert",
					},
				},
				OriginatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-ca-certs",
					CertificateChain: "fake public key tls-ca-certs",
					PrivateKey:       "fake private key tls-ca-certs",
					Secret: k8sTypes.NamespacedName{
						Name: "tls-ca-certs",
					},
				},
				ServerNames: StringSet{"www.foo.com": {}, "www.bar.com": {}},
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &egressRule)
}

func TestMergeListenerPolicy(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	//
	// no namespace (NodeFirewall policy): Can not refer to EnvoyConfig
	//
	egressRule := api.Rule{
		NodeSelector: hostSelector,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					Listener: &api.Listener{
						EnvoyConfig: &api.EnvoyConfig{
							Kind: "CiliumEnvoyConfig",
							Name: "test-cec",
						},
						Name: "test",
					},
				}},
			},
		},
	}

	old := option.Config.EnableHostFirewall
	defer func() {
		option.Config.EnableHostFirewall = old
	}()
	option.Config.EnableHostFirewall = true

	idHost := identity.NewIdentity(identity.ReservedIdentityHost, labels.NewFrom(labels.LabelHost))
	td.withIDs(identity.IdentityMap{idHost.ID: idHost.LabelArray})
	td.repo.mustAdd(egressRule)
	_, err := td.repo.resolvePolicyLocked(idHost)
	require.ErrorContains(t, err, `Listener "test" in CCNP can not use Kind CiliumEnvoyConfig`)

	//
	// no namespace in policyContext (Clusterwide policy): Must to ClusterwideEnvoyConfig
	//
	egressRule = api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					Listener: &api.Listener{
						EnvoyConfig: &api.EnvoyConfig{
							Kind: "CiliumClusterwideEnvoyConfig",
							Name: "shared-cec",
						},
						Name: "test",
					},
				}},
			},
		},
	}

	// Since cachedSelectorB's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeCRD,
				ListenerPriority: ListenerPriorityCRD,
				Listener:         "/shared-cec/test",
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &egressRule)

	//
	// namespace in policyContext (Namespaced policy): Can refer to EnvoyConfig
	//
	egressRule = api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					Listener: &api.Listener{
						EnvoyConfig: &api.EnvoyConfig{
							Kind: "CiliumEnvoyConfig",
							Name: "test-cec",
						},
						Name: "test",
					},
				}},
			},
		},
	}

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeCRD,
				ListenerPriority: ListenerPriorityCRD,
				Listener:         "default/test-cec/test",
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &egressRule)

	//
	// namespace in policyContext (Namespaced policy): Can refer to Cluster-socoped
	// CiliumClusterwideEnvoyConfig
	//
	egressRule = api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "443", Protocol: api.ProtoTCP},
					},
					Listener: &api.Listener{
						EnvoyConfig: &api.EnvoyConfig{
							Kind: "CiliumClusterwideEnvoyConfig",
							Name: "shared-cec",
						},
						Name: "test",
					},
				}},
			},
		},
	}

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeCRD,
				ListenerPriority: ListenerPriorityCRD,
				Listener:         "/shared-cec/test",
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &egressRule)
}

// Case 6: allow all at L3/L7 in one rule, and select an endpoint and allow all on L7
// in another rule. Should resolve to just allowing all on L3/L7 (first rule
// shadows the second).
func TestL3RuleShadowedByL3AllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 6A: Specify WildcardEndpointSelector explicitly.
	shadowRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB:        nil,
			td.wildcardCachedSelector: nil,
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)

	// Case 6B: Reverse the ordering of the rules. Result should be the same.
	shadowRule = api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorB:        nil,
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)
}

// Case 7: allow all at L3/L7 in one rule, and in another rule, select an endpoint
// which restricts on L7. Should resolve to just allowing all on L3/L7 (first rule
// shadows the second), but setting traffic to the HTTP proxy.
func TestL3RuleWithL7RulePartiallyShadowedByL3AllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 7A: selects specific endpoint with L7 restrictions rule first, then
	// rule which selects all endpoints and allows all on L7. Net result sets
	// parser type to whatever is in first rule, but without the restriction
	// on L7.
	shadowRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorA: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)

	// Case 7B: selects all endpoints and allows all on L7, then selects specific
	// endpoint with L7 restrictions rule. Net result sets  parser type to whatever
	// is in first rule, but without the restriction on L7.
	shadowRule = api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorA: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
			td.cachedSelectorA:        {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)
}

// Case 8: allow all at L3 and restricts on L7 in one rule, and in another rule,
// select an endpoint which restricts the same as the first rule on L7.
// Should resolve to just allowing all on L3, but restricting on L7 for both
// wildcard and the specified endpoint.
func TestL3RuleWithL7RuleShadowedByL3AllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 8A: selects specific endpoint with L7 restrictions rule first, then
	// rule which selects all endpoints and restricts on the same resource on L7.
	// PerSelectorPolicies contains entries for both endpoints selected in each rule
	// on L7 restriction.
	case8Rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
			td.cachedSelectorA: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &case8Rule)

	// Case 8B: first insert rule which selects all endpoints and restricts on
	// the same resource on L7. Then, insert rule which  selects specific endpoint
	// with L7 restrictions rule. PerSelectorPolicies contains entries for both
	// endpoints selected in each rule on L7 restriction.
	case8Rule = api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
			td.cachedSelectorA: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &case8Rule)
}

// Case 9: allow all at L3 and restricts on L7 in one rule, and in another rule,
// on the same selector restricts on different L7 protocol.
// Should fail as cannot have conflicting parsers on same port.
func TestL3SelectingEndpointAndL3AllowAllMergeConflictingL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 9A: Kafka first, then HTTP.
	conflictingL7Rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingL7Rule)

	// Case 9B: HTTP first, then Kafka.
	conflictingL7Rule = api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
		},
	}

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingL7Rule)
}

// Case 9b: allow all at L3 and restricts on L7 in one rule, and in another rule,
// select an endpoint which restricts on different L7 protocol, but on different selectors,
// which is now possible.
func TestL3SelectingEndpointAndL3AllowAllMergeDifferentL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// Case 9A: Kafka first, then HTTP.
	conflictingL7Rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	td.policyValid(t, &conflictingL7Rule)

	// Case 9B: HTTP first, then Kafka.
	conflictingL7Rule = api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{Topic: "foo"},
						},
					},
				}},
			},
		},
	}

	td.policyValid(t, &conflictingL7Rule)
}

// Case 10: restrict same path / method on L7 in both rules,
// but select different endpoints in each rule.
func TestMergingWithDifferentEndpointsSelectedAllowSameL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	selectDifferentEndpointsRestrictL7 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
			td.cachedSelectorA: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &selectDifferentEndpointsRestrictL7)
}

// Case 11: allow all on L7 in both rules, but select different endpoints in each rule.
func TestMergingWithDifferentEndpointSelectedAllowAllL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	selectDifferentEndpointsAllowAllL7 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorA},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil,
			td.cachedSelectorC: nil,
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &selectDifferentEndpointsAllowAllL7)
}

// Case 12: allow all at L3 in one rule with restrictions at L7. Determine that
// the host should always be allowed. From Host should go to proxy allow all;
// other L3 should restrict at L7 in a separate filter.
func TestAllowingLocalhostShadowsL7(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// This test checks that when the AllowLocalhost=always option is
	// enabled, we always wildcard the host at L7. That means we need to
	// set the option in the config, and of course clean up afterwards so
	// that this test doesn't affect subsequent tests.
	// XXX: Does this affect other tests being run concurrently?
	oldLocalhostOpt := option.Config.UnsafeDaemonConfigOption.AllowLocalhost
	option.Config.UnsafeDaemonConfigOption.AllowLocalhost = option.AllowLocalhostAlways
	defer func() { option.Config.UnsafeDaemonConfigOption.AllowLocalhost = oldLocalhostOpt }()

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{Method: "GET", Path: "/"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
			},
			td.cachedSelectorHost: nil, // no proxy redirect
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule)
}

func TestEntitiesL3(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	allowWorldRule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: api.EntitySlice{api.EntityAll},
				},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"0/ANY": {
		Port:     0,
		Protocol: api.ProtoAny,
		U8Proto:  0,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		Ingress:    false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, nil, expected, &allowWorldRule)
}

// Case 13: deny all at L3 in case of an empty non-nil toEndpoints slice.
func TestEgressEmptyToEndpoints(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}

	expected := L4PolicyMaps{makeL4PolicyMap()}
	td.policyMapEquals(t, nil, expected, &rule)
}

// Case 14: Test that DNS L7 rules in default-allow mode add a wildcard
func TestDNSWildcardInDefaultAllow(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		// Set EnableDefaultDeny.Egress to false to ensure default-allow mode
		EnableDefaultDeny: api.DefaultDenyConfig{Egress: &falseValue},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
					Rules: &api.L7Rules{
						DNS: []api.PortRuleDNS{{
							MatchPattern: "example.com",
						}},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  17,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: &PerSelectorPolicy{
					Verdict: types.Allow,
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{{
							MatchPattern: "example.com",
						}, {
							// Wildcard rule should be added
							MatchPattern: "*",
						}},
					},
					L7Parser:         ParserTypeDNS,
					ListenerPriority: ListenerPriorityDNS,
				},
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
		// L3 wildcard rule is also added
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, nil, expected, &rule)
}

// Case 15: Test that HTTP L7 rules in default-allow mode add an empty rule
func TestHTTPWildcardInDefaultAllow(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		// Set EnableDefaultDeny.Ingress to false to ensure default-allow mode
		EnableDefaultDeny: api.DefaultDenyConfig{Ingress: &falseValue},
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/api",
							Method: "GET",
						}},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  6,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: &PerSelectorPolicy{
					Verdict: types.Allow,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/api",
							Method: "GET",
						}, {
							// Empty HTTP rule should be added
						}},
					},
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
				},
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
		// L3 wildcard rule is also added
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &rule)
}

// Case 16: Test that Kafka L7 rules in default-allow mode add an empty topic rule
func TestKafkaWildcardInDefaultAllow(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		// Set EnableDefaultDeny.Ingress to false to ensure default-allow mode
		EnableDefaultDeny: api.DefaultDenyConfig{Ingress: &falseValue},
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{{
							Topic: "important-topic",
						}},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  6,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: &PerSelectorPolicy{
					Verdict: types.Allow,
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{{
							Topic: "important-topic",
						}, {
							// Empty topic rule should be added
							Topic: "",
						}},
					},
					L7Parser:         ParserTypeKafka,
					ListenerPriority: ListenerPriorityKafka,
				},
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
		// L3 wildcard rule is also added
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &rule)
}

// Case 17: Test that DNS L7 rules with L3 filtering in default-allow mode add a wildcard
func TestDNSWildcardWithL3FilterInDefaultAllow(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		// Set EnableDefaultDeny.Egress to false to ensure default-allow mode
		EnableDefaultDeny: api.DefaultDenyConfig{Egress: &falseValue},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					// Specific L3 endpoint selection
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
					Rules: &api.L7Rules{
						DNS: []api.PortRuleDNS{{
							MatchPattern: "example.com",
						}},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  17,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{
					Verdict: types.Allow,
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{{
							MatchPattern: "example.com",
						}, {
							// Wildcard rule should be added
							MatchPattern: "*",
						}},
					},
					L7Parser:         ParserTypeDNS,
					ListenerPriority: ListenerPriorityDNS,
				},
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {nil}}),
		},
		// L3 wildcard rule is also added
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, nil, expected, &rule)
}

// Case 18: Test that default-deny rules in default-allow mode don't add wildcards
func TestDenyRuleNoWildcardInDefaultAllow(t *testing.T) {
	logger := hivetest.Logger(t)
	td := newTestData(t, logger)

	rule := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/api",
							Method: "GET",
						}},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  6,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: &PerSelectorPolicy{
					Verdict: types.Allow,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Path:   "/api",
							Method: "GET",
							// No wildcard rule should be added
						}},
					},
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
				},
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &rule)
}

// TestDefaultAllowL7Rules tests that when EnableDefaultDeny=false, L7 wildcard rules of various
// types are added and don't accidentally block other traffic of the same type.
func TestDefaultAllowL7Rules(t *testing.T) {
	testCases := []struct {
		name           string
		l7Rules        *api.L7Rules
		l7Parser       L7ParserType
		port           string
		proto          api.L4Proto
		verifyWildcard func(t *testing.T, policy *PerSelectorPolicy)
	}{
		{
			name: "DNS rules with default-allow",
			l7Rules: &api.L7Rules{
				DNS: []api.PortRuleDNS{{
					MatchPattern: "example.com",
				}},
			},
			l7Parser: ParserTypeDNS,
			port:     "53",
			proto:    api.ProtoUDP,
			verifyWildcard: func(t *testing.T, policy *PerSelectorPolicy) {
				found := false
				for _, dnsRule := range policy.L7Rules.DNS {
					if dnsRule.MatchPattern == "*" {
						found = true
						break
					}
				}
				require.True(t, found, "DNS wildcard rule should be added in default-allow mode")
			},
		},
		{
			name: "HTTP rules with default-allow",
			l7Rules: &api.L7Rules{
				HTTP: []api.PortRuleHTTP{{
					Path:   "/api",
					Method: "GET",
				}},
			},
			l7Parser: ParserTypeHTTP,
			port:     "80",
			proto:    api.ProtoTCP,
			verifyWildcard: func(t *testing.T, policy *PerSelectorPolicy) {
				found := false
				for _, httpRule := range policy.L7Rules.HTTP {
					if httpRule.Path == "" && httpRule.Method == "" && httpRule.Host == "" &&
						len(httpRule.Headers) == 0 && len(httpRule.HeaderMatches) == 0 {
						found = true
						break
					}
				}
				require.True(t, found, "HTTP wildcard rule should be added in default-allow mode")
			},
		},
		{
			name: "Kafka rules with default-allow",
			l7Rules: &api.L7Rules{
				Kafka: []kafka.PortRule{{
					Topic: "important-topic",
				}},
			},
			l7Parser: ParserTypeKafka,
			port:     "9092",
			proto:    api.ProtoTCP,
			verifyWildcard: func(t *testing.T, policy *PerSelectorPolicy) {
				found := false
				for _, kafkaRule := range policy.L7Rules.Kafka {
					if kafkaRule.Topic == "" {
						found = true
						break
					}
				}
				require.True(t, found, "Kafka wildcard rule should be added in default-allow mode")
			},
		},
		{
			name: "Custom L7 rules with default-allow",
			l7Rules: &api.L7Rules{
				L7Proto: "envoy.filter.protocol.dubbo",
				L7: []api.PortRuleL7{{
					"method": "Login",
				}},
			},
			l7Parser: "envoy.filter.protocol.dubbo",
			port:     "8080",
			proto:    api.ProtoTCP,
			verifyWildcard: func(t *testing.T, policy *PerSelectorPolicy) {
				found := false
				for _, l7Rule := range policy.L7Rules.L7 {
					if len(l7Rule) == 0 {
						found = true
						break
					}
				}
				require.True(t, found, "Custom L7 wildcard rule should be added in default-allow mode")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger := hivetest.Logger(t)
			td := newTestData(t, logger)

			ctx := &testPolicyContextType{
				logger:            logger,
				sc:                td.sc,
				defaultDenyEgress: false, // EnableDefaultDeny=false
			}

			egressRule := &api.PortRule{
				Ports: []api.PortProtocol{{
					Port:     tc.port,
					Protocol: tc.proto,
				}},
				Rules: tc.l7Rules,
			}

			portProto := api.PortProtocol{
				Port:     tc.port,
				Protocol: tc.proto,
			}

			entry := &types.PolicyEntry{
				L3:      types.ToSelectors(api.NewESFromLabels(labels.ParseSelectLabel("foo"))),
				L4:      []api.PortRule{*egressRule},
				Ingress: false,
				Verdict: types.Allow,
			}

			l4Filter, err := createL4Filter(ctx, entry, egressRule, portProto)

			require.NoError(t, err)
			require.NotNil(t, l4Filter)

			anyPerSelectorPolicy := false
			for _, policy := range l4Filter.PerSelectorPolicies {
				if policy != nil {
					anyPerSelectorPolicy = true
					require.Equal(t, tc.l7Parser, policy.L7Parser, "L7Parser should match")
					tc.verifyWildcard(t, policy)
				}
			}
			require.True(t, anyPerSelectorPolicy, "Should have at least one PerSelectorPolicy")
		})
	}
}

type fakeCertificateManager struct{}

const (
	fakeCA         = "fake ca"
	fakePublicKey  = "fake public key"
	fakePrivateKey = "fake private key"
)

func (_ *fakeCertificateManager) GetTLSContext(ctx context.Context, tlsCtx *api.TLSContext, ns string) (ca, public, private string, inlineSecrets bool, err error) {
	name := tlsCtx.Secret.Name
	public = fakePublicKey + " " + name
	private = fakePrivateKey + " " + name
	ca = fakeCA + " " + name

	inlineSecrets = true
	return
}
