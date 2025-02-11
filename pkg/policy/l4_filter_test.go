// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"context"
	"fmt"
	"sync"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

var (
	hostSelector = api.ReservedEndpointSelectors[labels.IDNameHost]

	dummySelectorCacheUser = &testpolicy.DummySelectorCacheUser{}
	fooSelector            = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	bazSelector            = api.NewESFromLabels(labels.ParseSelectLabel("baz"))

	selBar1 = api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 = api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))
)

type testData struct {
	sc   *SelectorCache
	repo *Repository

	testPolicyContext *testPolicyContextType

	cachedSelectorA        CachedSelector
	cachedSelectorB        CachedSelector
	cachedSelectorC        CachedSelector
	cachedSelectorHost     CachedSelector
	wildcardCachedSelector CachedSelector

	cachedFooSelector CachedSelector
	cachedBazSelector CachedSelector

	cachedSelectorBar1 CachedSelector
	cachedSelectorBar2 CachedSelector

	cachedSelectorWorld   CachedSelector
	cachedSelectorWorldV4 CachedSelector
	cachedSelectorWorldV6 CachedSelector
}

func newTestData() *testData {
	td := &testData{
		sc:                testNewSelectorCache(nil),
		repo:              NewPolicyRepository(nil, &fakeCertificateManager{}, nil, nil, api.NewPolicyMetricsNoop()),
		testPolicyContext: &testPolicyContextType{},
	}
	td.testPolicyContext.sc = td.sc
	td.repo.selectorCache = td.sc

	td.wildcardCachedSelector, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, api.WildcardEndpointSelector)

	td.cachedSelectorA, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, endpointSelectorA)
	td.cachedSelectorB, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, endpointSelectorB)
	td.cachedSelectorC, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, endpointSelectorC)
	td.cachedSelectorHost, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, hostSelector)

	td.cachedFooSelector, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, fooSelector)
	td.cachedBazSelector, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, bazSelector)

	td.cachedSelectorBar1, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, selBar1)
	td.cachedSelectorBar2, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, selBar2)

	td.cachedSelectorWorld, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, api.EntitySelectorMapping[api.EntityWorld][0])

	td.cachedSelectorWorldV4, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, api.EntitySelectorMapping[api.EntityWorldIPv4][0])

	td.cachedSelectorWorldV6, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, api.EntitySelectorMapping[api.EntityWorldIPv6][0])

	return td
}

// withIDs loads the set of IDs in to the SelectorCache. Returns
// the same testData for easy chaining.
func (td *testData) withIDs(initIDs ...identity.IdentityMap) *testData {
	initial := identity.IdentityMap{}
	for _, im := range initIDs {
		for id, lbls := range im {
			initial[id] = lbls
		}
	}
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(initial, nil, wg)
	wg.Wait()
	return td
}

func (td *testData) addIdentity(id *identity.Identity) {
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(
		identity.IdentityMap{
			id.ID: id.LabelArray,
		}, nil, wg)
	wg.Wait()
}

// policyMapEquals takes a set of policies and an expected L4PolicyMap. The policies are assumed to
// select identity A.
//
// The repository is cleared when called.
func (td *testData) policyMapEquals(t *testing.T, expectedIn, expectedOut L4PolicyMap, rules ...*api.Rule) {
	t.Helper()
	td.withIDs(ruleTestIDs)
	for _, r := range rules {
		if r.EndpointSelector.LabelSelector == nil {
			r.EndpointSelector = endpointSelectorA
		}
		require.NoError(t, r.Sanitize())
	}
	td.repo.ReplaceByLabels(rules, []labels.LabelArray{{}})

	td.repo.mutex.RLock()
	defer td.repo.mutex.RUnlock()
	pol, err := td.repo.resolvePolicyLocked(idA)
	require.NoError(t, err)
	defer pol.Detach()

	if expectedIn != nil {
		require.True(t, expectedIn.TestingOnlyEquals(pol.L4Policy.Ingress.PortRules), expectedIn.TestingOnlyDiff(pol.L4Policy.Ingress.PortRules))
	}

	if expectedOut != nil {

		require.True(t, expectedOut.TestingOnlyEquals(pol.L4Policy.Egress.PortRules), expectedOut.TestingOnlyDiff(pol.L4Policy.Egress.PortRules))
	}
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
	td.repo.ReplaceByLabels(rules, []labels.LabelArray{{}})

	_, err := td.repo.resolvePolicyLocked(idA)
	require.Error(t, err)
	require.ErrorContains(t, err, errStr)
}

// testPolicyContexttype is a dummy context used when evaluating rules.
type testPolicyContextType struct {
	isDeny   bool
	ns       string
	sc       *SelectorCache
	fromFile bool
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

func (p *testPolicyContextType) SetDeny(isDeny bool) bool {
	oldDeny := p.isDeny
	p.isDeny = isDeny
	return oldDeny
}

func (p *testPolicyContextType) IsDeny() bool {
	return p.isDeny
}

func init() {
	re.InitRegexCompileLRU(defaults.FQDNRegexCompileLRUSize)
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
// +-----+-----------------+----------+-----------------+------------------------------------------------------+

func TestMergeAllowAllL3AndAllowAllL7(t *testing.T) {
	td := newTestData()
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
		L7Parser: ParserTypeNone, Ingress: true, wildcard: td.wildcardCachedSelector,
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

	expected = NewL4PolicyMap()
	td.policyMapEquals(t, expected, nil, &rule2)
}

// Case 2: allow all at L3 in both rules. Allow all in one L7 rule, but second
// rule restricts at L7. Because one L7 rule allows at L7, all traffic is allowed
// at L7, but still redirected at the proxy.
// Should resolve to one rule.
func TestMergeAllowAllL3AndShadowedL7(t *testing.T) {
	td := newTestData()
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
		L7Parser: "http",
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}, {}},
				},
				isRedirect: true,
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}, {}},
				},
				isRedirect: true,
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
	td := newTestData()
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &identicalHTTPRule)
}

// Case 4: identical allow all at L3 with identical restrictions on Kafka.
func TestMergeIdenticalAllowAllL3AndRestrictedL7Kafka(t *testing.T) {
	td := newTestData()

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
		L7Parser: ParserTypeKafka,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					Kafka: []kafka.PortRule{{Topic: "foo"}},
				},
				isRedirect: true,
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
	td := newTestData()

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
	td := newTestData()
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
		L7Parser: ParserTypeTLS,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				TerminatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-cert",
					CertificateChain: "fake public key tls-cert",
					PrivateKey:       "fake private key tls-cert",
					Secret: types.NamespacedName{
						Name: "tls-cert",
					},
				},
				OriginatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-ca-certs",
					CertificateChain: "fake public key tls-ca-certs",
					PrivateKey:       "fake private key tls-ca-certs",
					Secret: types.NamespacedName{
						Name: "tls-ca-certs",
					},
				},
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				L7Rules:         api.L7Rules{},
				isRedirect:      true,
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
	td := newTestData()
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				TerminatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-cert",
					CertificateChain: "fake public key tls-cert",
					PrivateKey:       "fake private key tls-cert",
					Secret: types.NamespacedName{
						Name: "tls-cert",
					},
				},
				OriginatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-ca-certs",
					CertificateChain: "fake public key tls-ca-certs",
					PrivateKey:       "fake private key tls-ca-certs",
					Secret: types.NamespacedName{
						Name: "tls-ca-certs",
					},
				},
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				isRedirect: true,
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
	td := newTestData()
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
					ServerNames: []string{"www.foo.com"},
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
					ServerNames: []string{"www.bar.com"},
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				TerminatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-cert",
					CertificateChain: "fake public key tls-cert",
					PrivateKey:       "fake private key tls-cert",
					Secret: types.NamespacedName{
						Name: "tls-cert",
					},
				},
				OriginatingTLS: &TLSContext{
					FromFile:         true,
					TrustedCA:        "fake ca tls-ca-certs",
					CertificateChain: "fake public key tls-ca-certs",
					PrivateKey:       "fake private key tls-ca-certs",
					Secret: types.NamespacedName{
						Name: "tls-ca-certs",
					},
				},
				ServerNames:     StringSet{"www.foo.com": {}, "www.bar.com": {}},
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				isRedirect: true,
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
	td := newTestData()

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
		L7Parser: ParserTypeCRD,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				isRedirect:      true,
				Listener:        "/shared-cec/test",
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
		L7Parser: ParserTypeCRD,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				isRedirect:      true,
				Listener:        "default/test-cec/test",
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
		L7Parser: ParserTypeCRD,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				isRedirect:      true,
				Listener:        "/shared-cec/test",
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
	td := newTestData()
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
		L7Parser: ParserTypeNone,
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
		L7Parser: ParserTypeNone,
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
	td := newTestData()
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorA: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorA: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
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
	td := newTestData()
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
			td.cachedSelectorA: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
			td.cachedSelectorA: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
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
// select an endpoint which restricts on different L7 protocol.
// Should fail as cannot have conflicting parsers on same port.
func TestL3SelectingEndpointAndL3AllowAllMergeConflictingL7(t *testing.T) {
	td := newTestData()
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

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingL7Rule)

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

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &conflictingL7Rule)
}

// Case 10: restrict same path / method on L7 in both rules,
// but select different endpoints in each rule.
func TestMergingWithDifferentEndpointsSelectedAllowSameL7(t *testing.T) {
	td := newTestData()
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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
			td.cachedSelectorA: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
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
	td := newTestData()
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
		L7Parser: ParserTypeNone,
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
	td := newTestData()
	// This test checks that when the AllowLocalhost=always option is
	// enabled, we always wildcard the host at L7. That means we need to
	// set the option in the config, and of course clean up afterwards so
	// that this test doesn't affect subsequent tests.
	// XXX: Does this affect other tests being run concurrently?
	oldLocalhostOpt := option.Config.AllowLocalhost
	option.Config.AllowLocalhost = option.AllowLocalhostAlways
	defer func() { option.Config.AllowLocalhost = oldLocalhostOpt }()

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
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
			td.cachedSelectorHost: nil, // no proxy redirect
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule)
}

func TestEntitiesL3(t *testing.T) {
	td := newTestData()
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
		L7Parser: ParserTypeNone,
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
	td := newTestData()
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

	expected := NewL4PolicyMap()
	td.policyMapEquals(t, nil, expected, &rule)
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
