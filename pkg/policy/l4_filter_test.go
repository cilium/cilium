// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"fmt"
	stdlog "log"
	"sync"
	"testing"

	cilium "github.com/cilium/proxy/go/cilium/api"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"

	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/fqdn/re"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

var (
	hostSelector = api.ReservedEndpointSelectors[labels.IDNameHost]
	toFoo        = &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	dummySelectorCacheUser = &DummySelectorCacheUser{}
	fooSelector            = api.NewESFromLabels(labels.ParseSelectLabel("foo"))
	bazSelector            = api.NewESFromLabels(labels.ParseSelectLabel("baz"))

	selFoo  = api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 = api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 = api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))
)

type testData struct {
	sc   *SelectorCache
	repo *Repository

	testPolicyContext *testPolicyContextType

	cachedSelectorA        CachedSelector
	cachedSelectorC        CachedSelector
	cachedSelectorHost     CachedSelector
	wildcardCachedSelector CachedSelector

	cachedFooSelector CachedSelector
	cachedBazSelector CachedSelector

	cachedSelectorBar1 CachedSelector
	cachedSelectorBar2 CachedSelector
}

func newTestData() *testData {
	td := &testData{
		sc:   testNewSelectorCache(nil),
		repo: NewPolicyRepository(nil, nil, nil, nil),

		testPolicyContext: &testPolicyContextType{},
	}
	td.testPolicyContext.sc = td.sc
	td.repo.selectorCache = td.sc

	td.wildcardCachedSelector, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, api.WildcardEndpointSelector)

	td.cachedSelectorA, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, endpointSelectorA)
	td.cachedSelectorC, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, endpointSelectorC)
	td.cachedSelectorHost, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, hostSelector)

	td.cachedFooSelector, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, fooSelector)
	td.cachedBazSelector, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, bazSelector)

	td.cachedSelectorBar1, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, selBar1)
	td.cachedSelectorBar2, _ = td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, selBar2)

	return td
}

// resetRepo clears only the policy repository.
// Some tests rely on the accumulated state, but a clean repo.
func (td *testData) resetRepo() *Repository {
	td.repo = NewPolicyRepository(nil, nil, nil, nil)
	td.repo.selectorCache = td.sc
	return td.repo
}

func (td *testData) addIdentity(id *identity.Identity) {
	wg := &sync.WaitGroup{}
	td.sc.UpdateIdentities(
		identity.IdentityMap{
			id.ID: id.LabelArray,
		}, nil, wg)
	wg.Wait()
}

// testPolicyContexttype is a dummy context used when evaluating rules.
type testPolicyContextType struct {
	isDeny bool
	ns     string
	sc     *SelectorCache
}

func (p *testPolicyContextType) GetNamespace() string {
	return p.ns
}

func (p *testPolicyContextType) GetSelectorCache() *SelectorCache {
	return p.sc
}

func (p *testPolicyContextType) GetTLSContext(tls *api.TLSContext) (ca, public, private string, err error) {
	switch tls.Secret.Name {
	case "tls-cert":
		return "", "fake public cert", "fake private key", nil
	case "tls-ca-certs":
		return "fake CA certs", "", "", nil
	}
	return "", "", "", fmt.Errorf("Unknown test secret '%s'", tls.Secret.Name)
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
	td.repo.MustAddList(api.Rules{&api.Rule{
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
	}})

	buffer := new(bytes.Buffer)
	ctx := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err := td.repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.True(t, filter.SelectsAllEndpoints())

	require.Equal(t, ParserTypeNone, filter.L7Parser)
	require.Equal(t, 1, len(filter.PerSelectorPolicies))
	l4IngressPolicy.Detach(td.repo.GetSelectorCache())

	// Case1B: an empty non-nil FromEndpoints does not select any identity.
	td = newTestData()
	td.repo.MustAddList(api.Rules{&api.Rule{
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
	}})

	buffer = new(bytes.Buffer)
	ctx = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err = td.repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter = l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.Nil(t, filter)

	l4IngressPolicy.Detach(td.repo.GetSelectorCache())
}

// Case 2: allow all at L3 in both rules. Allow all in one L7 rule, but second
// rule restricts at L7. Because one L7 rule allows at L7, all traffic is allowed
// at L7, but still redirected at the proxy.
// Should resolve to one rule.
func TestMergeAllowAllL3AndShadowedL7(t *testing.T) {
	td := newTestData()
	rule1 := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctx := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	ingressState := traceState{}
	res, err := rule1.resolveIngressPolicy(td.testPolicyContext, &ctx, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)

	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	}})

	require.EqualValues(t, expected, res)
	require.Equal(t, 1, ingressState.selectedRules)
	require.Equal(t, 1, ingressState.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	// Case 2B: Flip order of case 2A so that rule being merged with is different
	// than rule being consumed.
	td = newTestData()
	td.repo.MustAddList(api.Rules{&api.Rule{
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
	}})

	buffer = new(bytes.Buffer)
	ctx = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err := td.repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.True(t, filter.SelectsAllEndpoints())

	require.Equal(t, ParserTypeHTTP, filter.L7Parser)
	require.Equal(t, 1, len(filter.PerSelectorPolicies))
	l4IngressPolicy.Detach(td.repo.GetSelectorCache())
}

// Case 3: allow all at L3 in both rules. Both rules have same parser type and
// same API resource specified at L7 for HTTP.
func TestMergeIdenticalAllowAllL3AndRestrictedL7HTTP(t *testing.T) {
	td := newTestData()
	identicalHTTPRule := &rule{
		Rule: api.Rule{
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
		}}

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	}})

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state := traceState{}
	res, err := identicalHTTPRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = identicalHTTPRule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

// Case 4: identical allow all at L3 with identical restrictions on Kafka.
func TestMergeIdenticalAllowAllL3AndRestrictedL7Kafka(t *testing.T) {
	td := newTestData()

	identicalKafkaRule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	}})

	state := traceState{}
	res, err := identicalKafkaRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = identicalKafkaRule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

// Case 5: use conflicting protocols on the same port in different rules. This
// is not supported, so return an error.
func TestMergeIdenticalAllowAllL3AndMismatchingParsers(t *testing.T) {
	td := newTestData()

	// Case 5A: Kafka first, HTTP second.
	conflictingParsersRule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state := traceState{}
	res, err := conflictingParsersRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NotNil(t, err)
	require.Nil(t, res)

	// Case 5B: HTTP first, Kafka second.
	conflictingParsersRule = &rule{
		Rule: api.Rule{
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
		}}

	buffer = new(bytes.Buffer)
	ctxToA = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state = traceState{}
	res, err = conflictingParsersRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NotNil(t, err)
	require.Nil(t, res)

	// Case 5B+: HTTP first, generic L7 second.
	conflictingParsersIngressRule := &rule{
		Rule: api.Rule{
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
		}}

	buffer = new(bytes.Buffer)
	ctxToA = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err = conflictingParsersIngressRule.Sanitize()
	require.NoError(t, err)

	state = traceState{}
	res, err = conflictingParsersIngressRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NotNil(t, err)
	require.Nil(t, res)

	// Case 5B++: generic L7 without rules first, HTTP second.
	conflictingParsersEgressRule := &rule{
		Rule: api.Rule{
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
		}}

	buffer = new(bytes.Buffer)
	ctxAToC := SearchContext{From: labelsA, To: labelsC, Trace: TRACE_VERBOSE}
	ctxAToC.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err = conflictingParsersEgressRule.Sanitize()
	require.NoError(t, err)

	state = traceState{}
	res, err = conflictingParsersEgressRule.resolveEgressPolicy(td.testPolicyContext, &ctxAToC, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NotNil(t, err)
	require.Nil(t, res)
}

// TLS policies with and without interception

// TLS policy without L7 rules does not inspect L7, uses L7ParserType "tls"
func TestMergeTLSTCPPolicy(t *testing.T) {
	td := newTestData()
	egressRule := &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer := new(bytes.Buffer)
	ctxFromFoo := SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err := egressRule.Sanitize()
	require.NoError(t, err)

	state := traceState{}
	res, err := egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeTLS,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				TerminatingTLS: &TLSContext{
					CertificateChain: "fake public cert",
					PrivateKey:       "fake private key",
				},
				OriginatingTLS: &TLSContext{
					TrustedCA: "fake CA certs",
				},
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				L7Rules:         api.L7Rules{},
				isRedirect:      true,
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	require.EqualValues(t, expected, res)

	l4Filter := res.ExactLookup("443", 0, "TCP")
	require.NotNil(t, l4Filter)
	require.Equal(t, ParserTypeTLS, l4Filter.L7Parser)
	log.Infof("res: %v", res)
}

func TestMergeTLSHTTPPolicy(t *testing.T) {
	td := newTestData()
	egressRule := &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer := new(bytes.Buffer)
	ctxFromFoo := SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err := egressRule.Sanitize()
	require.NoError(t, err)

	state := traceState{}
	res, err := egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				TerminatingTLS: &TLSContext{
					CertificateChain: "fake public cert",
					PrivateKey:       "fake private key",
				},
				OriginatingTLS: &TLSContext{
					TrustedCA: "fake CA certs",
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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	require.True(t, res.Equals(t, expected), res.Diff(t, expected))
	l4Filter := res.ExactLookup("443", 0, "TCP")
	require.NotNil(t, l4Filter)
	require.Equal(t, ParserTypeHTTP, l4Filter.L7Parser)
	log.Infof("res: %v", res)
}

func TestMergeTLSSNIPolicy(t *testing.T) {
	td := newTestData()
	egressRule := &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer := new(bytes.Buffer)
	ctxFromFoo := SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err := egressRule.Sanitize()
	require.NoError(t, err)

	state := traceState{}
	res, err := egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				TerminatingTLS: &TLSContext{
					CertificateChain: "fake public cert",
					PrivateKey:       "fake private key",
				},
				OriginatingTLS: &TLSContext{
					TrustedCA: "fake CA certs",
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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	require.EqualValues(t, expected, res)
	require.True(t, res.Equals(t, expected), res.Diff(t, expected))

	l4Filter := res.ExactLookup("443", 0, "TCP")
	require.NotNil(t, l4Filter)
	require.Equal(t, ParserTypeHTTP, l4Filter.L7Parser)
	log.Infof("res: %v", res)
}

func TestMergeListenerPolicy(t *testing.T) {
	td := newTestData()

	//
	// no namespace in policyContext (Clusterwide policy): Can not refer to EnvoyConfig
	//
	egressRule := &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer := new(bytes.Buffer)
	ctxFromFoo := SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err := egressRule.Sanitize()
	require.NoError(t, err)

	state := traceState{}
	res, err := egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.ErrorContains(t, err, "Listener \"test\" in CCNP can not use Kind CiliumEnvoyConfig")
	require.Nil(t, res)

	//
	// no namespace in policyContext (Clusterwide policy): Must to ClusterwideEnvoyConfig
	//
	egressRule = &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer = new(bytes.Buffer)
	ctxFromFoo = SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err = egressRule.Sanitize()
	require.NoError(t, err)

	state = traceState{}
	res, err = egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeCRD,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				isRedirect:      true,
				Listener:        "/shared-cec/test",
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	require.EqualValues(t, expected, res)

	l4Filter := res.ExactLookup("443", 0, "TCP")
	require.NotNil(t, l4Filter)
	require.Equal(t, ParserTypeCRD, l4Filter.L7Parser)
	log.Infof("res: %v", res)

	//
	// namespace in policyContext (Namespaced policy): Can refer to EnvoyConfig
	//
	egressRule = &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer = new(bytes.Buffer)
	ctxFromFoo = SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err = egressRule.Sanitize()
	require.NoError(t, err)

	state = traceState{}
	td.testPolicyContext.ns = "default"
	res, err = egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeCRD,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				isRedirect:      true,
				Listener:        "default/test-cec/test",
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	require.EqualValues(t, expected, res)

	l4Filter = res.ExactLookup("443", 0, "TCP")
	require.NotNil(t, l4Filter)
	require.Equal(t, ParserTypeCRD, l4Filter.L7Parser)
	log.Infof("res: %v", res)

	//
	// namespace in policyContext (Namespaced policy): Can refer to Cluster-socoped
	// CiliumClusterwideEnvoyConfig
	//
	egressRule = &rule{
		Rule: api.Rule{
			EndpointSelector: fooSelector,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorA},
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
		}}

	buffer = new(bytes.Buffer)
	ctxFromFoo = SearchContext{From: labels.ParseSelectLabelArray("foo"), Trace: TRACE_VERBOSE}
	ctxFromFoo.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	err = egressRule.Sanitize()
	require.NoError(t, err)

	state = traceState{}
	td.testPolicyContext.ns = "default"
	res, err = egressRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)

	// Since cachedSelectorA's map entry is 'nil', it will not be redirected to the proxy.
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"443/TCP": {
		Port:     443,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeCRD,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: nil, // no proxy redirect
			td.cachedSelectorC: &PerSelectorPolicy{
				EnvoyHTTPRules:  nil,
				CanShortCircuit: false,
				isRedirect:      true,
				Listener:        "/shared-cec/test",
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	require.EqualValues(t, expected, res)

	l4Filter = res.ExactLookup("443", 0, "TCP")
	require.NotNil(t, l4Filter)
	require.Equal(t, ParserTypeCRD, l4Filter.L7Parser)
	log.Infof("res: %v", res)
}

// Case 6: allow all at L3/L7 in one rule, and select an endpoint and allow all on L7
// in another rule. Should resolve to just allowing all on L3/L7 (first rule
// shadows the second).
func TestL3RuleShadowedByL3AllowAll(t *testing.T) {
	td := newTestData()
	// Case 6A: Specify WildcardEndpointSelector explicitly.
	shadowRule := &rule{
		Rule: api.Rule{
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
						FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA:        nil,
			td.wildcardCachedSelector: nil,
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := shadowRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = shadowRule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	// Case 6B: Reverse the ordering of the rules. Result should be the same.
	shadowRule = &rule{
		Rule: api.Rule{
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
					}},
				},
			},
		}}

	buffer = new(bytes.Buffer)
	ctxToA = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorA:        nil,
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state = traceState{}
	res, err = shadowRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = shadowRule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
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
	shadowRule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := shadowRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = shadowRule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	// Case 7B: selects all endpoints and allows all on L7, then selects specific
	// endpoint with L7 restrictions rule. Net result sets  parser type to whatever
	// is in first rule, but without the restriction on L7.
	shadowRule = &rule{
		Rule: api.Rule{
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
		}}

	buffer = new(bytes.Buffer)
	ctxToA = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
			td.cachedSelectorA:        {nil},
		},
	}})

	state = traceState{}
	res, err = shadowRule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = shadowRule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
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
	case8Rule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := case8Rule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = case8Rule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	// Case 8B: first insert rule which selects all endpoints and restricts on
	// the same resource on L7. Then, insert rule which  selects specific endpoint
	// with L7 restrictions rule. PerSelectorPolicies contains entries for both
	// endpoints selected in each rule on L7 restriction.
	case8Rule = &rule{
		Rule: api.Rule{
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
		}}

	buffer = new(bytes.Buffer)
	ctxToA = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state = traceState{}
	res, err = case8Rule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = case8Rule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

// Case 9: allow all at L3 and restricts on L7 in one rule, and in another rule,
// select an endpoint which restricts on different L7 protocol.
// Should fail as cannot have conflicting parsers on same port.
func TestL3SelectingEndpointAndL3AllowAllMergeConflictingL7(t *testing.T) {
	td := newTestData()
	// Case 9A: Kafka first, then HTTP.
	conflictingL7Rule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state := traceState{}
	res, err := conflictingL7Rule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NotNil(t, err)
	require.Nil(t, res)

	state = traceState{}
	res, err = conflictingL7Rule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	// Case 9B: HTTP first, then Kafka.
	conflictingL7Rule = &rule{
		Rule: api.Rule{
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
		}}

	buffer = new(bytes.Buffer)
	ctxToA = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state = traceState{}
	res, err = conflictingL7Rule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NotNil(t, err)
	require.Nil(t, res)

	state = traceState{}
	res, err = conflictingL7Rule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

// Case 10: restrict same path / method on L7 in both rules,
// but select different endpoints in each rule.
func TestMergingWithDifferentEndpointsSelectedAllowSameL7(t *testing.T) {
	td := newTestData()
	selectDifferentEndpointsRestrictL7 := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	state := traceState{}
	res, err := selectDifferentEndpointsRestrictL7.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	buffer = new(bytes.Buffer)
	ctxToC := SearchContext{To: labelsC, Trace: TRACE_VERBOSE}
	ctxToC.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state = traceState{}
	res, err = selectDifferentEndpointsRestrictL7.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

// Case 11: allow all on L7 in both rules, but select different endpoints in each rule.
func TestMergingWithDifferentEndpointSelectedAllowAllL7(t *testing.T) {
	td := newTestData()
	selectDifferentEndpointsAllowAllL7 := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		},
	}})

	state := traceState{}
	res, err := selectDifferentEndpointsAllowAllL7.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	buffer = new(bytes.Buffer)
	ctxToC := SearchContext{To: labelsC, Trace: TRACE_VERBOSE}
	ctxToC.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state = traceState{}
	res, err = selectDifferentEndpointsAllowAllL7.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
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

	rule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	}})

	state := traceState{}
	res, err := rule.resolveIngressPolicy(td.testPolicyContext, &ctxToA, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	// Endpoints not selected by the rule should not match the rule.
	buffer = new(bytes.Buffer)
	ctxToC := SearchContext{To: labelsC, Trace: TRACE_VERBOSE}
	ctxToC.Logging = stdlog.New(buffer, "", 0)

	state = traceState{}
	res, err = rule.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	t.Log(buffer)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

func TestEntitiesL3(t *testing.T) {
	td := newTestData()
	allowWorldRule := &rule{
		Rule: api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEntities: api.EntitySlice{api.EntityAll},
					},
				},
			},
		}}

	buffer := new(bytes.Buffer)
	ctxFromA := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctxFromA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

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
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	}})

	state := traceState{}
	res, err := allowWorldRule.resolveEgressPolicy(td.testPolicyContext, &ctxFromA, &state, NewL4PolicyMap(), nil, nil)

	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)
}

// Case 13: deny all at L3 in case of an empty non-nil toEndpoints slice.
func TestEgressEmptyToEndpoints(t *testing.T) {
	td := newTestData()
	rule := &rule{
		Rule: api.Rule{
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
		}}

	buffer := new(bytes.Buffer)
	ctxFromA := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctxFromA.Logging = stdlog.New(buffer, "", 0)
	t.Log(buffer)

	state := traceState{}
	res, err := rule.resolveEgressPolicy(td.testPolicyContext, &ctxFromA, &state, NewL4PolicyMap(), nil, nil)

	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}
