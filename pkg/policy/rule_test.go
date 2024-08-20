// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"fmt"
	stdlog "log"
	"strings"
	"testing"

	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestL4Policy(t *testing.T) {
	td := newTestData()

	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	fromBar := &SearchContext{From: labels.ParseSelectLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}
	fromFoo := &SearchContext{From: labels.ParseSelectLabelArray("foo")}

	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
							{Port: "8080", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "3000", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}

	l7rules := api.L7Rules{
		HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
	}
	l7map := L7DataMap{
		td.wildcardCachedSelector: &PerSelectorPolicy{
			L7Rules:    l7rules,
			isRedirect: true,
		},
	}

	expected := NewL4Policy(0)
	expected.Ingress.PortRules.Upsert("80", 0, "TCP", &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "http", PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Ingress.PortRules.Upsert("8080", 0, "TCP", &L4Filter{
		Port: 8080, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "http", PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})

	expected.Egress.PortRules.Upsert("3000", 0, "TCP", &L4Filter{
		Port: 3000, Protocol: api.ProtoTCP, U8Proto: 6, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Egress.PortRules.Upsert("3000", 0, "UDP", &L4Filter{
		Port: 3000, Protocol: api.ProtoUDP, U8Proto: 17, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Egress.PortRules.Upsert("3000", 0, "SCTP", &L4Filter{
		Port: 3000, Protocol: api.ProtoSCTP, U8Proto: 132, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})

	ingressState := traceState{}
	egressState := traceState{}
	res := NewL4Policy(0)
	var err error
	res.Ingress.PortRules, err =
		rule1.resolveIngressPolicy(td.testPolicyContext, toBar, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Ingress)

	res.Egress.PortRules, err =
		rule1.resolveEgressPolicy(td.testPolicyContext, fromBar, &egressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Egress)

	require.Equal(t, &expected, &res)
	require.Equal(t, 1, ingressState.selectedRules)
	require.Equal(t, 1, ingressState.matchedRules)

	require.Equal(t, 1, egressState.selectedRules)
	require.Equal(t, 1, egressState.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	// Foo isn't selected in the rule1's policy.
	ingressState = traceState{}
	egressState = traceState{}

	res1, err := rule1.resolveIngressPolicy(td.testPolicyContext, toFoo, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	res2, err := rule1.resolveEgressPolicy(td.testPolicyContext, fromFoo, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)

	require.Nil(t, res1)
	require.Nil(t, res2)
	require.Equal(t, 0, ingressState.selectedRules)
	require.Equal(t, 0, ingressState.matchedRules)
	require.Equal(t, 0, egressState.selectedRules)
	require.Equal(t, 0, egressState.matchedRules)

	// This rule actually overlaps with the existing ingress "http" rule,
	// so we'd expect it to merge.
	rule2 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					// Note that this allows all on 80, so the result should wildcard HTTP
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
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "3000", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}

	expected = NewL4Policy(0)
	expected.Ingress.PortRules.Upsert("80", 0, "TCP", &L4Filter{
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
		Ingress:    true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Egress.PortRules.Upsert("3000", 0, "TCP", &L4Filter{
		Port: 3000, Protocol: api.ProtoTCP, U8Proto: 6, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Egress.PortRules.Upsert("3000", 0, "UDP", &L4Filter{
		Port: 3000, Protocol: api.ProtoUDP, U8Proto: 17, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Egress.PortRules.Upsert("3000", 0, "SCTP", &L4Filter{
		Port: 3000, Protocol: api.ProtoSCTP, U8Proto: 132, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})

	ingressState = traceState{}
	egressState = traceState{}
	res = NewL4Policy(0)

	buffer := new(bytes.Buffer)
	ctx := SearchContext{To: labels.ParseSelectLabelArray("bar"), Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	res.Ingress.PortRules, err = rule2.resolveIngressPolicy(td.testPolicyContext, &ctx, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Ingress)

	t.Log(buffer)

	res.Egress.PortRules, err = rule2.resolveEgressPolicy(td.testPolicyContext, fromBar, &egressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Egress)

	require.Equal(t, 1, res.Ingress.PortRules.Len())
	require.Equal(t, &expected, &res)
	require.Equal(t, 1, ingressState.selectedRules)
	require.Equal(t, 1, ingressState.matchedRules)

	require.Equal(t, 1, egressState.selectedRules)
	require.Equal(t, 1, egressState.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	ingressState = traceState{}
	egressState = traceState{}

	res1, err = rule2.resolveIngressPolicy(td.testPolicyContext, toFoo, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res1)

	res2, err = rule2.resolveEgressPolicy(td.testPolicyContext, fromFoo, &egressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res2)

	require.Equal(t, 0, ingressState.selectedRules)
	require.Equal(t, 0, ingressState.matchedRules)

	require.Equal(t, 0, egressState.selectedRules)
	require.Equal(t, 0, egressState.matchedRules)
}

func TestMergeL4PolicyIngress(t *testing.T) {
	td := newTestData()
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	//toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{fooSelector},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{bazSelector},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	mergedES := L7DataMap{
		td.cachedFooSelector: nil,
		td.cachedBazSelector: nil,
	}
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: ParserTypeNone, PerSelectorPolicies: mergedES, Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector: {nil},
			td.cachedBazSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := rule1.resolveIngressPolicy(td.testPolicyContext, toBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)
}

func TestMergeL4PolicyEgress(t *testing.T) {
	td := newTestData()

	buffer := new(bytes.Buffer)
	fromBar := &SearchContext{
		From:    labels.ParseSelectLabelArray("bar"),
		Logging: stdlog.New(buffer, "", 0),
		Trace:   TRACE_VERBOSE,
	}

	// bar can access foo with TCP on port 80, and baz with TCP on port 80.
	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{fooSelector},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{bazSelector},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	}

	mergedES := L7DataMap{
		td.cachedFooSelector: nil,
		td.cachedBazSelector: nil,
	}
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: ParserTypeNone, PerSelectorPolicies: mergedES, Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector: {nil},
			td.cachedBazSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := rule1.resolveEgressPolicy(td.testPolicyContext, fromBar, &state, NewL4PolicyMap(), nil, nil)

	t.Log(buffer)

	require.NoError(t, err)
	require.NotNil(t, res)
	require.Equal(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)
}

func TestMergeL7PolicyIngress(t *testing.T) {
	td := newTestData()
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	toFoo := &SearchContext{To: labels.ParseSelectLabelArray("foo")}

	fooSelectorSlice := []api.EndpointSelector{
		fooSelector,
	}
	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					// Note that this allows all on 80, so the result should wildcard HTTP
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
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: fooSelectorSlice,
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
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}, {}},
				},
				isRedirect: true,
			},
			td.cachedFooSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector:      {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := rule1.resolveIngressPolicy(td.testPolicyContext, toBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = rule1.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	rule2 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
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
						FromEndpoints: fooSelectorSlice,
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
		},
	}

	l7rules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "foo"}},
	}
	l7map := L7DataMap{
		td.wildcardCachedSelector: &PerSelectorPolicy{
			L7Rules:    l7rules,
			isRedirect: true,
		},
		td.cachedFooSelector: &PerSelectorPolicy{
			L7Rules:    l7rules,
			isRedirect: true,
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "kafka", PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector:      {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state = traceState{}
	res, err = rule2.resolveIngressPolicy(td.testPolicyContext, toBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = rule2.resolveIngressPolicy(td.testPolicyContext, toFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	// Resolve rule1's policy, then try to add rule2.
	res, err = rule1.resolveIngressPolicy(td.testPolicyContext, toBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)

	state = traceState{}
	_, err = rule2.resolveIngressPolicy(td.testPolicyContext, toBar, &state, res, nil, nil)

	require.NotNil(t, err)
	res.Detach(td.sc)

	// Similar to 'rule2', but with different topics for the l3-dependent
	// rule and the l4-only rule.
	rule3 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: fooSelectorSlice,
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
							Kafka: []kafka.PortRule{
								{Topic: "bar"},
							},
						},
					}},
				},
			},
		},
	}

	fooRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "foo"}},
	}

	barRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "bar"}},
	}

	// The L3-dependent L7 rules are not merged together.
	l7map = L7DataMap{
		td.cachedFooSelector: &PerSelectorPolicy{
			L7Rules:    fooRules,
			isRedirect: true,
		},
		td.wildcardCachedSelector: &PerSelectorPolicy{
			L7Rules:    barRules,
			isRedirect: true,
		},
	}
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "kafka", PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector:      {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state = traceState{}
	res, err = rule3.resolveIngressPolicy(td.testPolicyContext, toBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)
}

func TestMergeL7PolicyEgress(t *testing.T) {
	td := newTestData()
	fromBar := &SearchContext{From: labels.ParseSelectLabelArray("bar")}
	fromFoo := &SearchContext{From: labels.ParseSelectLabelArray("foo")}

	fooSelector := []api.EndpointSelector{
		api.NewESFromLabels(labels.ParseSelectLabel("foo")),
	}

	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					// Note that this allows all on 80, so the result should wildcard HTTP
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
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/public"},
							},
						},
					}},
				},
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: fooSelector,
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/private"},
							},
						},
					}},
				},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}, {}},
				},
				isRedirect: true,
			},
			td.cachedFooSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/private", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
			td.cachedFooSelector:      {nil},
		},
	}})

	state := traceState{}
	res, err := rule1.resolveEgressPolicy(td.testPolicyContext, fromBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = rule1.resolveEgressPolicy(td.testPolicyContext, fromFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	rule2 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					// Note that this allows all on 9092, so the result should wildcard Kafka
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "9092", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
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
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: fooSelector,
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
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"9092/TCP": {
		Port: 9092, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: ParserTypeKafka,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					Kafka: []kafka.PortRule{{Topic: "foo"}, {}},
				},
				isRedirect: true,
			},
			td.cachedFooSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					Kafka: []kafka.PortRule{{Topic: "foo"}},
				},
				isRedirect: true,
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector:      {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state = traceState{}
	res, err = rule2.resolveEgressPolicy(td.testPolicyContext, fromBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = rule2.resolveEgressPolicy(td.testPolicyContext, fromFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)

	// Resolve rule1's policy, then try to add rule2.
	res, err = rule1.resolveEgressPolicy(td.testPolicyContext, fromBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	res.Detach(td.sc)

	// Similar to 'rule2', but with different topics for the l3-dependent
	// rule and the l4-only rule.
	rule3 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: fooSelector,
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
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							Kafka: []kafka.PortRule{
								{Topic: "bar"},
							},
						},
					}},
				},
			},
		},
	}

	fooRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "foo"}},
	}
	barRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "bar"}},
	}

	// The l3-dependent l7 rules are not merged together.
	l7map := L7DataMap{
		td.cachedFooSelector: &PerSelectorPolicy{
			L7Rules:    fooRules,
			isRedirect: true,
		},
		td.wildcardCachedSelector: &PerSelectorPolicy{
			L7Rules:    barRules,
			isRedirect: true,
		},
	}
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "kafka", PerSelectorPolicies: l7map, Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector:      {nil},
			td.wildcardCachedSelector: {nil},
		},
	}})

	state = traceState{}
	res, err = rule3.resolveEgressPolicy(td.testPolicyContext, fromBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)
}

func TestRuleWithNoEndpointSelector(t *testing.T) {
	apiRule1 := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromCIDR: []api.CIDR{
						"10.0.1.0/24",
						"192.168.2.0",
						"10.0.3.1",
						"2001:db8::1/48",
						"2001:db9::",
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{
						"10.1.0.0/16",
						"2001:dbf::/64",
					},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
				},
			},
		},
	}

	err := apiRule1.Sanitize()
	require.NotNil(t, err)
}

func TestL3Policy(t *testing.T) {
	apiRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),

		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromCIDR: []api.CIDR{
						"10.0.1.0/24",
						"192.168.2.0",
						"10.0.3.1",
						"2001:db8::1/48",
						"2001:db9::",
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{
						"10.1.0.0/16",
						"2001:dbf::/64",
					},
				},
			}, {
				EgressCommonRule: api.EgressCommonRule{
					ToCIDRSet: []api.CIDRRule{{Cidr: api.CIDR("10.0.0.0/8"), ExceptCIDRs: []api.CIDR{"10.96.0.0/12"}}},
				},
			},
		},
	}

	err := apiRule1.Sanitize()
	require.NoError(t, err)

	rule1 := &rule{Rule: apiRule1}
	err = rule1.Sanitize()
	require.NoError(t, err)

	// Must be parsable, make sure Validate fails when not.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDR: []api.CIDR{"10.0.1..0/24"},
			},
		}},
	}).Sanitize()
	require.NotNil(t, err)

	// Test CIDRRule with no provided CIDR or ExceptionCIDR.
	// Should fail as CIDR is required.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDRSet: []api.CIDRRule{{Cidr: "", ExceptCIDRs: nil}},
			},
		}},
	}).Sanitize()
	require.NotNil(t, err)

	// Test CIDRRule with only CIDR provided; should not fail, as ExceptionCIDR
	// is optional.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.1.0/24", ExceptCIDRs: nil}},
			},
		}},
	}).Sanitize()
	require.NoError(t, err)

	// Cannot provide just an IP to a CIDRRule; Cidr must be of format
	// <IP>/<prefix>.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.1.32", ExceptCIDRs: nil}},
			},
		}},
	}).Sanitize()
	require.NotNil(t, err)

	// Cannot exclude a range that is not part of the CIDR.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.0.0/10", ExceptCIDRs: []api.CIDR{"10.64.0.0/11"}}},
			},
		}},
	}).Sanitize()
	require.NotNil(t, err)

	// Must have a contiguous mask, make sure Validate fails when not.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDR: []api.CIDR{"10.0.1.0/128.0.0.128"},
			},
		}},
	}).Sanitize()
	require.NotNil(t, err)

	// Prefix length must be in range for the address, make sure
	// Validate fails if given prefix length is out of range.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDR: []api.CIDR{"10.0.1.0/34"},
			},
		}},
	}).Sanitize()
	require.NotNil(t, err)
}

func TestICMPPolicy(t *testing.T) {
	td := newTestData()
	var err error
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	fromBar := &SearchContext{From: labels.ParseSelectLabelArray("bar")}

	// A rule for ICMP
	icmpV4Type := intstr.FromInt(8)
	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ICMPs: api.ICMPRules{{
						Fields: []api.ICMPField{{
							Type: &icmpV4Type,
						}},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ICMPs: api.ICMPRules{{
						Fields: []api.ICMPField{{
							Type: &icmpV4Type,
						}},
					}},
				},
			},
		},
	}

	expected := NewL4Policy(0)
	expected.Ingress.PortRules.Upsert("8", 0, "ICMP", &L4Filter{
		Port:     8,
		Protocol: api.ProtoICMP,
		U8Proto:  u8proto.ProtoIDs["icmp"],
		Ingress:  true,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Egress.PortRules.Upsert("8", 0, "ICMP", &L4Filter{
		Port:     8,
		Protocol: api.ProtoICMP,
		U8Proto:  u8proto.ProtoIDs["icmp"],
		Ingress:  false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})

	ingressState := traceState{}
	egressState := traceState{}
	res := NewL4Policy(0)
	res.Ingress.PortRules, err =
		rule1.resolveIngressPolicy(td.testPolicyContext, toBar, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Ingress)

	res.Egress.PortRules, err =
		rule1.resolveEgressPolicy(td.testPolicyContext, fromBar, &egressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Egress)

	require.Equal(t, &expected, &res)
	require.Equal(t, 1, ingressState.selectedRules)
	require.Equal(t, 1, ingressState.matchedRules)
	require.Equal(t, 1, egressState.selectedRules)
	require.Equal(t, 1, egressState.matchedRules)

	res.Detach(td.sc)
	expected.Detach(td.sc)

	// A rule for Ports and ICMP
	rule2 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
					ICMPs: api.ICMPRules{{
						Fields: []api.ICMPField{{
							Type: &icmpV4Type,
						}},
					}},
				},
			},
		},
	}

	expected = NewL4Policy(0)
	expected.Ingress.PortRules.Upsert("80", 0, "TCP", &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  u8proto.ProtoIDs["tcp"],
		Ingress:  true,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})
	expected.Ingress.PortRules.Upsert("8", 0, "ICMP", &L4Filter{
		Port:     8,
		Protocol: api.ProtoICMP,
		U8Proto:  u8proto.ProtoIDs["icmp"],
		Ingress:  true,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})

	ingressState = traceState{}
	res = NewL4Policy(0)
	res.Ingress.PortRules, err =
		rule2.resolveIngressPolicy(td.testPolicyContext, toBar, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Ingress)

	require.Equal(t, &expected, &res)
	require.Equal(t, 1, ingressState.selectedRules)
	require.Equal(t, 1, ingressState.matchedRules)

	res.Detach(td.sc)
	expected.Detach(td.sc)

	// A rule for ICMPv6
	icmpV6Type := intstr.FromInt(128)
	rule3 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ICMPs: api.ICMPRules{{
						Fields: []api.ICMPField{{
							Family: "IPv6",
							Type:   &icmpV6Type,
						}},
					}},
				},
			},
		},
	}

	expected = NewL4Policy(0)
	expected.Ingress.PortRules.Upsert("128", 0, "ICMPV6", &L4Filter{
		Port:     128,
		Protocol: api.ProtoICMPv6,
		U8Proto:  u8proto.ProtoIDs["icmpv6"],
		Ingress:  true,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}},
	})

	ingressState = traceState{}
	res = NewL4Policy(0)
	res.Ingress.PortRules, err =
		rule3.resolveIngressPolicy(td.testPolicyContext, toBar, &ingressState, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res.Ingress)

	require.Equal(t, &expected, &res)
	require.Equal(t, 1, ingressState.selectedRules)
	require.Equal(t, 1, ingressState.matchedRules)
}

// Tests the restrictions of combining certain label-based L3 and L4 policies.
// This ensures that the user is informed of policy combinations that are not
// implemented in the datapath.
func TestEgressRuleRestrictions(t *testing.T) {
	fooSelector := []api.EndpointSelector{
		api.NewESFromLabels(labels.ParseSelectLabel("foo")),
	}

	// Cannot combine ToEndpoints and ToCIDR
	apiRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: []api.CIDR{
						"10.1.0.0/16",
						"2001:dbf::/64",
					},
					ToEndpoints: fooSelector,
				},
			},
		},
	}

	err := apiRule1.Sanitize()
	require.NotNil(t, err)
}

func TestPolicyEntityValidationEgress(t *testing.T) {
	r := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: []api.Entity{api.EntityWorld},
				},
			},
		},
	}
	require.Nil(t, r.Sanitize())
	require.Equal(t, 1, len(r.Egress[0].ToEntities))

	r.Egress[0].ToEntities = []api.Entity{api.EntityHost}
	require.Nil(t, r.Sanitize())
	require.Equal(t, 1, len(r.Egress[0].ToEntities))

	r.Egress[0].ToEntities = []api.Entity{"trololo"}
	require.NotNil(t, r.Sanitize())
}

func TestPolicyEntityValidationIngress(t *testing.T) {
	r := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: []api.Entity{api.EntityWorld},
				},
			},
		},
	}
	require.Nil(t, r.Sanitize())
	require.Equal(t, 1, len(r.Ingress[0].FromEntities))

	r.Ingress[0].FromEntities = []api.Entity{api.EntityHost}
	require.Nil(t, r.Sanitize())
	require.Equal(t, 1, len(r.Ingress[0].FromEntities))

	r.Ingress[0].FromEntities = []api.Entity{"trololo"}
	require.NotNil(t, r.Sanitize())
}

func TestPolicyEntityValidationEntitySelectorsFill(t *testing.T) {
	r := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: []api.Entity{api.EntityWorld, api.EntityHost},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: []api.Entity{api.EntityWorld, api.EntityHost},
				},
			},
		},
	}
	require.Nil(t, r.Sanitize())
	require.Equal(t, 2, len(r.Ingress[0].FromEntities))
	require.Equal(t, 2, len(r.Egress[0].ToEntities))
}

func TestL3RuleLabels(t *testing.T) {
	td := newTestData()
	ruleLabels := map[string]labels.LabelArray{
		"rule0": labels.ParseLabelArray("name=apiRule0"),
		"rule1": labels.ParseLabelArray("name=apiRule1"),
		"rule2": labels.ParseLabelArray("name=apiRule2"),
	}

	rules := map[string]api.Rule{
		"rule0": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule0"],
			Ingress:          []api.IngressRule{},
			Egress:           []api.EgressRule{},
		},
		"rule1": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule1"],
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromCIDR: []api.CIDR{"10.0.1.0/32"},
					},
				},
			},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToCIDR: []api.CIDR{"10.1.0.0/32"},
					},
				},
			},
		},
		"rule2": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule2"],
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromCIDR: []api.CIDR{"10.0.2.0/32"},
					},
				},
			},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToCIDR: []api.CIDR{"10.2.0.0/32"},
					},
				},
			},
		},
	}

	testCases := []struct {
		description           string                           // the description to print in asserts
		rulesToApply          []string                         // the rules from the rules map to resolve, in order
		expectedIngressLabels map[string]labels.LabelArrayList // the slice of LabelArray we should see, per CIDR prefix
		expectedEgressLabels  map[string]labels.LabelArrayList // the slice of LabelArray we should see, per CIDR prefix

	}{
		{
			description:           "Empty rule that matches. Should not apply labels",
			rulesToApply:          []string{"rule0"},
			expectedIngressLabels: nil,
			expectedEgressLabels:  nil,
		}, {
			description:           "A rule that matches. Should apply labels",
			rulesToApply:          []string{"rule1"},
			expectedIngressLabels: map[string]labels.LabelArrayList{"10.0.1.0/32": {ruleLabels["rule1"]}},
			expectedEgressLabels:  map[string]labels.LabelArrayList{"10.1.0.0/32": {ruleLabels["rule1"]}},
		}, {
			description:  "Multiple matching rules. Should apply labels from all that have rule entries",
			rulesToApply: []string{"rule0", "rule1", "rule2"},
			expectedIngressLabels: map[string]labels.LabelArrayList{
				"10.0.1.0/32": {ruleLabels["rule1"]},
				"10.0.2.0/32": {ruleLabels["rule2"]}},
			expectedEgressLabels: map[string]labels.LabelArrayList{
				"10.1.0.0/32": {ruleLabels["rule1"]},
				"10.2.0.0/32": {ruleLabels["rule2"]}},
		}}

	// endpoint selector for all tests
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar"), Trace: TRACE_VERBOSE}
	fromBar := &SearchContext{From: labels.ParseSelectLabelArray("bar"), Trace: TRACE_VERBOSE}

	for _, test := range testCases {
		finalPolicy := NewL4Policy(0)
		for _, r := range test.rulesToApply {
			apiRule := rules[r]
			err := apiRule.Sanitize()
			require.NoError(t, err, "Cannot sanitize Rule: %+v", apiRule)

			rule := &rule{Rule: apiRule}

			_, err = rule.resolveIngressPolicy(td.testPolicyContext, toBar, &traceState{}, finalPolicy.Ingress.PortRules, nil, nil)
			require.NoError(t, err)
			_, err = rule.resolveEgressPolicy(td.testPolicyContext, fromBar, &traceState{}, finalPolicy.Egress.PortRules, nil, nil)
			require.NoError(t, err)
		}
		// For debugging the test:
		//require.EqualValues(t, NewL4PolicyMap(), finalPolicy.Ingress)

		type expectedResult map[string]labels.LabelArrayList
		mapDirectionalResultsToExpectedOutput := map[*L4Filter]expectedResult{
			finalPolicy.Ingress.PortRules.ExactLookup("0", 0, "ANY"): test.expectedIngressLabels,
			finalPolicy.Egress.PortRules.ExactLookup("0", 0, "ANY"):  test.expectedEgressLabels,
		}
		for filter, exp := range mapDirectionalResultsToExpectedOutput {
			if len(exp) > 0 {
				for cidr, rule := range exp {
					matches := false
					for _, origin := range filter.RuleOrigin {
						if origin.Equals(rule) {
							matches = true
							break
						}
					}
					require.True(t, matches, fmt.Sprintf("%s: expected filter %+v to be derived from rule %s", test.description, filter, rule))

					matches = false
					for sel := range filter.PerSelectorPolicies {
						cidrLabels := labels.ParseLabelArray("cidr:" + cidr)
						t.Logf("Testing %+v", cidrLabels)
						if matches = sel.(*identitySelector).source.(*labelIdentitySelector).xxxMatches(cidrLabels); matches {
							break
						}
					}
					require.True(t, matches, fmt.Sprintf("%s: expected cidr %s to match filter %+v", test.description, cidr, filter))
				}
			}
		}
	}
}

func TestL4RuleLabels(t *testing.T) {
	td := newTestData()
	ruleLabels := map[string]labels.LabelArray{
		"rule0": labels.ParseLabelArray("name=apiRule0"),
		"rule1": labels.ParseLabelArray("name=apiRule1"),
		"rule2": labels.ParseLabelArray("name=apiRule2"),
	}

	rules := map[string]api.Rule{
		"rule0": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule0"],
			Ingress:          []api.IngressRule{},
			Egress:           []api.EgressRule{},
		},

		"rule1": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule1"],
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1010", Protocol: api.ProtoTCP}},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1100", Protocol: api.ProtoTCP}},
					}},
				},
			},
		},
		"rule2": {
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Labels:           ruleLabels["rule2"],
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1020", Protocol: api.ProtoTCP}},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{{Port: "1200", Protocol: api.ProtoTCP}},
					}},
				},
			},
		},
	}

	testCases := []struct {
		description           string                           // the description to print in asserts
		rulesToApply          []string                         // the rules from the rules map to resolve, in order
		expectedIngressLabels map[string]labels.LabelArrayList // the slice of LabelArray we should see, in order
		expectedEgressLabels  map[string]labels.LabelArrayList // the slice of LabelArray we should see, in order

	}{
		{
			description:           "Empty rule that matches. Should not apply labels",
			rulesToApply:          []string{"rule0"},
			expectedIngressLabels: map[string]labels.LabelArrayList{},
			expectedEgressLabels:  map[string]labels.LabelArrayList{},
		},
		{
			description:           "A rule that matches. Should apply labels",
			rulesToApply:          []string{"rule1"},
			expectedIngressLabels: map[string]labels.LabelArrayList{"1010/TCP": {ruleLabels["rule1"]}},
			expectedEgressLabels:  map[string]labels.LabelArrayList{"1100/TCP": {ruleLabels["rule1"]}},
		}, {
			description:  "Multiple matching rules. Should apply labels from all that have rule entries",
			rulesToApply: []string{"rule0", "rule1", "rule2"},
			expectedIngressLabels: map[string]labels.LabelArrayList{
				"1010/TCP": {ruleLabels["rule1"]},
				"1020/TCP": {ruleLabels["rule2"]}},
			expectedEgressLabels: map[string]labels.LabelArrayList{
				"1100/TCP": {ruleLabels["rule1"]},
				"1200/TCP": {ruleLabels["rule2"]}},
		}}

	// endpoint selector for all tests
	toBar := &SearchContext{To: labels.ParseSelectLabelArray("bar")}
	fromBar := &SearchContext{From: labels.ParseSelectLabelArray("bar")}

	for _, test := range testCases {
		finalPolicy := NewL4Policy(0)
		for _, r := range test.rulesToApply {
			apiRule := rules[r]
			err := apiRule.Sanitize()
			require.NoError(t, err, "Cannot sanitize api.Rule: %+v", apiRule)

			rule := &rule{Rule: apiRule}

			rule.resolveIngressPolicy(td.testPolicyContext, toBar, &traceState{}, finalPolicy.Ingress.PortRules, nil, nil)
			rule.resolveEgressPolicy(td.testPolicyContext, fromBar, &traceState{}, finalPolicy.Egress.PortRules, nil, nil)
		}

		require.Equal(t, len(test.expectedIngressLabels), finalPolicy.Ingress.PortRules.Len(), test.description)
		for portProto := range test.expectedIngressLabels {
			portProtoSlice := strings.Split(portProto, "/")
			out := finalPolicy.Ingress.PortRules.ExactLookup(portProtoSlice[0], 0, portProtoSlice[1])
			require.NotNil(t, out, test.description)
			require.Equal(t, 1, len(out.RuleOrigin), test.description)
			require.EqualValues(t, test.expectedIngressLabels[portProto], out.RuleOrigin[out.wildcard], test.description)
		}

		require.Equal(t, len(test.expectedEgressLabels), finalPolicy.Egress.PortRules.Len(), test.description)
		for portProto := range test.expectedEgressLabels {
			portProtoSlice := strings.Split(portProto, "/")
			out := finalPolicy.Egress.PortRules.ExactLookup(portProtoSlice[0], 0, portProtoSlice[1])
			require.NotNil(t, out, test.description)

			require.Equal(t, 1, len(out.RuleOrigin), test.description)
			require.EqualValues(t, test.expectedEgressLabels[portProto], out.RuleOrigin[out.wildcard], test.description)
		}
		finalPolicy.Detach(td.sc)
	}
}

var (
	labelsA = labels.LabelArray{
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
	}

	endpointSelectorA = api.NewESFromLabels(labels.ParseSelectLabel("id=a"))

	labelsB = labels.LabelArray{
		labels.NewLabel("id1", "b", labels.LabelSourceK8s),
		labels.NewLabel("id2", "t", labels.LabelSourceK8s),
	}

	labelsC = labels.LabelArray{
		labels.NewLabel("id", "t", labels.LabelSourceK8s),
	}

	endpointSelectorC = api.NewESFromLabels(labels.ParseSelectLabel("id=t"))

	ctxAToB = SearchContext{From: labelsA, To: labelsB, Trace: TRACE_VERBOSE}
	ctxAToC = SearchContext{From: labelsA, To: labelsC, Trace: TRACE_VERBOSE}
)

func expectResult(t *testing.T, expected, obtained api.Decision, buffer *bytes.Buffer) {
	if obtained != expected {
		t.Errorf("Unexpected result: obtained=%v, expected=%v", obtained, expected)
		t.Log(buffer)
	}
}

func checkIngress(t *testing.T, repo *Repository, ctx *SearchContext, verdict api.Decision) {
	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	buffer := new(bytes.Buffer)
	ctx.Logging = stdlog.New(buffer, "", 0)
	expectResult(t, verdict, repo.AllowsIngressRLocked(ctx), buffer)
}

func checkEgress(t *testing.T, repo *Repository, ctx *SearchContext, verdict api.Decision) {
	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	buffer := new(bytes.Buffer)
	ctx.Logging = stdlog.New(buffer, "", 0)
	expectResult(t, verdict, repo.AllowsEgressRLocked(ctx), buffer)
}
func TestIngressAllowAll(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorC,
			Ingress: []api.IngressRule{
				{
					// Allow all L3&L4 ingress rule
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.WildcardEndpointSelector,
						},
					},
				},
			},
		},
	})

	checkIngress(t, repo, &ctxAToB, api.Denied)
	checkIngress(t, repo, &ctxAToC, api.Allowed)

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC80, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Name: "port-90", Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC90, api.Allowed)
}

func TestIngressAllowAllL4Overlap(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorC,
			Ingress: []api.IngressRule{
				{
					// Allow all L3&L4 ingress rule
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.WildcardEndpointSelector,
						},
					},
				},
				{
					// This rule is a subset of the above
					// rule and should *NOT* restrict to
					// port 80 only
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC80, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC90, api.Allowed)
}

func TestIngressAllowAllL4OverlapNamedPort(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorC,
			Ingress: []api.IngressRule{
				{
					// Allow all L3&L4 ingress rule
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{
							api.WildcardEndpointSelector,
						},
					},
				},
				{
					// This rule is a subset of the above
					// rule and should *NOT* restrict to
					// port 80 only
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "port-80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Name: "port-80", Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC80, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC90, api.Allowed)
}

func TestIngressL4AllowAll(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorC,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC80, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC90, api.Denied)

	ctxAToCNamed90 := ctxAToC
	ctxAToCNamed90.DPorts = []*models.Port{{Name: "port-90", Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToCNamed90, api.Denied)

	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(&ctxAToC80)
	require.NoError(t, err)

	filter := l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, 1, len(filter.PerSelectorPolicies))
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	l4IngressPolicy.Detach(repo.GetSelectorCache())
}

func TestIngressL4AllowAllNamedPort(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorC,
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "port-80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	ctxAToCNamed80 := ctxAToC
	ctxAToCNamed80.DPorts = []*models.Port{{Name: "port-80", Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToCNamed80, api.Allowed)

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC80, api.Denied)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToC90, api.Denied)

	ctxAToCNamed90 := ctxAToC
	ctxAToCNamed90.DPorts = []*models.Port{{Name: "port-90", Protocol: models.PortProtocolTCP}}
	checkIngress(t, repo, &ctxAToCNamed90, api.Denied)

	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(&ctxAToCNamed80)
	require.NoError(t, err)

	filter := l4IngressPolicy.ExactLookup("port-80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(0), filter.Port)
	require.Equal(t, "port-80", filter.PortName)
	require.True(t, filter.Ingress)

	require.Equal(t, 1, len(filter.PerSelectorPolicies))
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	l4IngressPolicy.Detach(repo.GetSelectorCache())
}

func TestEgressAllowAll(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{
							api.WildcardEndpointSelector,
						},
					},
				},
			},
		},
	})

	checkEgress(t, repo, &ctxAToB, api.Allowed)
	checkEgress(t, repo, &ctxAToC, api.Allowed)

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToC80, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToC90, api.Allowed)
}

func TestEgressL4AllowAll(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	ctxAToC80 := ctxAToC
	ctxAToC80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToC80, api.Allowed)

	ctxAToC90 := ctxAToC
	ctxAToC90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToC90, api.Denied)

	buffer := new(bytes.Buffer)
	ctx := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4EgressPolicy, err := repo.ResolveL4EgressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4EgressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.Equal(t, false, filter.Ingress)

	require.Equal(t, 1, len(filter.PerSelectorPolicies))
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	l4EgressPolicy.Detach(repo.GetSelectorCache())
}

func TestEgressL4AllowWorld(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEntities: []api.Entity{api.EntityWorld},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	worldLabel := labels.ParseSelectLabelArray("reserved:world")
	ctxAToWorld80 := SearchContext{From: labelsA, To: worldLabel, Trace: TRACE_VERBOSE}
	ctxAToWorld80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld80, api.Allowed)

	ctxAToWorld90 := ctxAToWorld80
	ctxAToWorld90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld90, api.Denied)

	// Pod to pod must be denied on port 80 and 90, only world was whitelisted
	fooLabel := labels.ParseSelectLabelArray("k8s:app=foo")
	ctxAToFoo := SearchContext{From: labelsA, To: fooLabel, Trace: TRACE_VERBOSE,
		DPorts: []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}}
	checkEgress(t, repo, &ctxAToFoo, api.Denied)
	ctxAToFoo90 := ctxAToFoo
	ctxAToFoo90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToFoo90, api.Denied)

	buffer := new(bytes.Buffer)
	ctx := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4EgressPolicy, err := repo.ResolveL4EgressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4EgressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.Equal(t, false, filter.Ingress)

	require.Equal(t, 3, len(filter.PerSelectorPolicies))
	l4EgressPolicy.Detach(repo.GetSelectorCache())
}

func TestEgressL4AllowAllEntity(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEntities: []api.Entity{api.EntityAll},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
		},
	})

	worldLabel := labels.ParseSelectLabelArray("reserved:world")
	ctxAToWorld80 := SearchContext{From: labelsA, To: worldLabel, Trace: TRACE_VERBOSE}
	ctxAToWorld80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld80, api.Allowed)

	ctxAToWorld90 := ctxAToWorld80
	ctxAToWorld90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld90, api.Denied)

	// Pod to pod must be allowed on port 80, denied on port 90 (all identity)
	fooLabel := labels.ParseSelectLabelArray("k8s:app=foo")
	ctxAToFoo := SearchContext{From: labelsA, To: fooLabel, Trace: TRACE_VERBOSE,
		DPorts: []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}}
	checkEgress(t, repo, &ctxAToFoo, api.Allowed)
	ctxAToFoo90 := ctxAToFoo
	ctxAToFoo90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToFoo90, api.Denied)

	buffer := new(bytes.Buffer)
	ctx := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4EgressPolicy, err := repo.ResolveL4EgressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4EgressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.Equal(t, false, filter.Ingress)

	require.Equal(t, 1, len(filter.PerSelectorPolicies))
	l4EgressPolicy.Detach(repo.GetSelectorCache())
}

func TestEgressL3AllowWorld(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEntities: []api.Entity{api.EntityWorld},
					},
				},
			},
		},
	})

	worldLabel := labels.ParseSelectLabelArray("reserved:world")
	ctxAToWorld80 := SearchContext{From: labelsA, To: worldLabel, Trace: TRACE_VERBOSE}
	ctxAToWorld80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld80, api.Allowed)

	ctxAToWorld90 := ctxAToWorld80
	ctxAToWorld90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld90, api.Allowed)

	// Pod to pod must be denied on port 80 and 90, only world was whitelisted
	fooLabel := labels.ParseSelectLabelArray("k8s:app=foo")
	ctxAToFoo := SearchContext{From: labelsA, To: fooLabel, Trace: TRACE_VERBOSE,
		DPorts: []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}}
	checkEgress(t, repo, &ctxAToFoo, api.Denied)
	ctxAToFoo90 := ctxAToFoo
	ctxAToFoo90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToFoo90, api.Denied)

	buffer := new(bytes.Buffer)
	ctx := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)
}

func TestEgressL3AllowAllEntity(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEntities: []api.Entity{api.EntityAll},
					},
				},
			},
		},
	})

	worldLabel := labels.ParseSelectLabelArray("reserved:world")
	ctxAToWorld80 := SearchContext{From: labelsA, To: worldLabel, Trace: TRACE_VERBOSE}
	ctxAToWorld80.DPorts = []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld80, api.Allowed)

	ctxAToWorld90 := ctxAToWorld80
	ctxAToWorld90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToWorld90, api.Allowed)

	// Pod to pod must be allowed on both port 80 and 90 (L3 only rule)
	fooLabel := labels.ParseSelectLabelArray("k8s:app=foo")
	ctxAToFoo := SearchContext{From: labelsA, To: fooLabel, Trace: TRACE_VERBOSE,
		DPorts: []*models.Port{{Port: 80, Protocol: models.PortProtocolTCP}}}
	checkEgress(t, repo, &ctxAToFoo, api.Allowed)
	ctxAToFoo90 := ctxAToFoo
	ctxAToFoo90.DPorts = []*models.Port{{Port: 90, Protocol: models.PortProtocolTCP}}
	checkEgress(t, repo, &ctxAToFoo90, api.Allowed)

	buffer := new(bytes.Buffer)
	ctx := SearchContext{From: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)
}

func TestL4WildcardMerge(t *testing.T) {

	// First, test implicit case.
	//
	// Test the case where if we have rules that select the same endpoint on the
	// same port-protocol tuple with one that is L4-only, and the other applying
	// at L4 and L7, that the L4-only rule shadows the L4-L7 rule. This is because
	// L4-only rule implicitly allows all traffic at L7, so the L7-related
	// parts of the L4-L7 rule are useless.
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
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
			{
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
						{Port: "7000", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						L7Proto: "testparser",
						L7: []api.PortRuleL7{
							{"Key": "Value"},
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
						{Port: "7000", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}})

	expected := &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "http",
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorC: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}

	buffer := new(bytes.Buffer)
	ctx := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.NotNil(t, filter.PerSelectorPolicies[td.cachedSelectorC])
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	require.EqualValues(t, expected, filter)
	require.Equal(t, ParserTypeHTTP, filter.L7Parser)

	expectedL7 := &L4Filter{
		Port: 7000, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: "testparser",
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					L7Proto: "testparser",
					L7:      []api.PortRuleL7{{"Key": "Value"}, {}},
				},
				isRedirect: true,
			},
		},
		Ingress:    true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorC: {nil}},
	}

	filterL7 := l4IngressPolicy.ExactLookup("7000", 0, "TCP")
	require.NotNil(t, filterL7)
	require.Equal(t, uint16(7000), filterL7.Port)
	require.True(t, filterL7.Ingress)

	require.Equal(t, 1, len(filterL7.PerSelectorPolicies))
	require.NotNil(t, filterL7.PerSelectorPolicies[td.cachedSelectorC])
	require.Nil(t, filterL7.PerSelectorPolicies[td.wildcardCachedSelector])
	require.EqualValues(t, expectedL7, filterL7)
	require.Equal(t, L7ParserType("testparser"), filterL7.L7Parser)

	l4IngressPolicy.Detach(repo.GetSelectorCache())

	// Test the reverse order as well; ensure that we check both conditions
	// for if L4-only policy is in the L4Filter for the same port-protocol tuple,
	// and L7 metadata exists in the L4Filter we are adding; expect to resolve
	// to L4-only policy without any L7-metadata.
	repo = td.resetRepo()
	repo.MustAddList(api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "7000", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "7000", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						L7Proto: "testparser",
						L7: []api.PortRuleL7{
							{"Key": "Value"},
						},
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
	}})

	buffer = new(bytes.Buffer)
	ctx = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter = l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	require.NotNil(t, filter.PerSelectorPolicies[td.cachedSelectorC])
	require.EqualValues(t, expected, filter)
	require.Equal(t, ParserTypeHTTP, filter.L7Parser)

	filterL7 = l4IngressPolicy.ExactLookup("7000", 0, "TCP")
	require.NotNil(t, filterL7)
	require.Equal(t, uint16(7000), filterL7.Port)
	require.True(t, filterL7.Ingress)

	require.Equal(t, 1, len(filterL7.PerSelectorPolicies))
	require.NotNil(t, filterL7.PerSelectorPolicies[td.cachedSelectorC])
	require.Nil(t, filterL7.PerSelectorPolicies[td.wildcardCachedSelector])
	require.EqualValues(t, expectedL7, filterL7)
	require.Equal(t, L7ParserType("testparser"), filterL7.L7Parser)

	// Second, test the expeicit allow at L3.
	repo = td.resetRepo()
	repo.MustAddList(api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
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

	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter = l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, ParserTypeHTTP, filter.L7Parser)
	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.EqualValues(t, expected, filter)

	// Test the reverse order as well; ensure that we check both conditions
	// for if L4-only policy is in the L4Filter for the same port-protocol tuple,
	// and L7 metadata exists in the L4Filter we are adding; expect to resolve
	// to L4-only policy without any L7-metadata.
	repo = td.resetRepo()
	repo.MustAddList(api.Rules{&api.Rule{
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
	}})

	buffer = new(bytes.Buffer)
	ctx = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter = l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, ParserTypeHTTP, filter.L7Parser)
	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.EqualValues(t, expected, filter)
}

func TestL3L4L7Merge(t *testing.T) {

	// First rule allows ingress from all endpoints to port 80 only on
	// GET to "/". However, second rule allows all traffic on port 80 only to a
	// specific endpoint. When these rules are merged, it equates to allowing
	// all traffic from port 80 from any endpoint.
	//
	// TODO: This comment can't be correct, the resulting policy
	// should allow all on port 80 only from endpoint C, traffic
	// from all other endpoints should still only allow only GET
	// on "/".
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
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
				}},
			},
		},
	}})

	buffer := new(bytes.Buffer)
	ctx := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter := l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.NotNil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	require.Nil(t, filter.PerSelectorPolicies[td.cachedSelectorC])

	require.Equal(t, ParserTypeHTTP, filter.L7Parser)
	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.Equal(t, &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "http",
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: nil,
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}, filter)

	repo = td.resetRepo()
	repo.MustAddList(api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
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
			{
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
	}})

	buffer = new(bytes.Buffer)
	ctx = SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctx.Logging = stdlog.New(buffer, "", 0)

	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(&ctx)
	require.NoError(t, err)

	t.Log(buffer)

	filter = l4IngressPolicy.ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Equal(t, ParserTypeHTTP, filter.L7Parser)
	require.Equal(t, 2, len(filter.PerSelectorPolicies))
	require.NotNil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
	require.Nil(t, filter.PerSelectorPolicies[td.cachedSelectorC])
	require.Equal(t, &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		L7Parser: "http",
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: nil,
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		},
	}, filter)

}

func TestMatches(t *testing.T) {
	td := newTestData()
	repo := td.repo
	repo.MustAddList(api.Rules{
		&api.Rule{
			EndpointSelector: endpointSelectorA,
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorC},
					},
				},
			},
		},
		&api.Rule{
			NodeSelector: endpointSelectorA,
			Ingress: []api.IngressRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorC},
					},
				},
			},
		},
	})

	epRule := repo.rules[ruleKey{idx: 0}]
	hostRule := repo.rules[ruleKey{idx: 1}]

	selectedEpLabels := labels.ParseSelectLabel("id=a")
	selectedIdentity := identity.NewIdentity(54321, labels.Labels{selectedEpLabels.Key: selectedEpLabels})
	td.addIdentity(selectedIdentity)

	notSelectedEpLabels := labels.ParseSelectLabel("id=b")
	notSelectedIdentity := identity.NewIdentity(9876, labels.Labels{notSelectedEpLabels.Key: notSelectedEpLabels})
	td.addIdentity(notSelectedIdentity)

	hostLabels := labels.Labels{selectedEpLabels.Key: selectedEpLabels}
	hostLabels.MergeLabels(labels.LabelHost)
	hostIdentity := identity.NewIdentity(identity.ReservedIdentityHost, hostLabels)
	td.addIdentity(hostIdentity)

	// notSelectedEndpoint is not selected by rule, so we it shouldn't be added
	// to EndpointsSelected.
	require.Equal(t, false, epRule.matchesSubject(notSelectedIdentity))

	// selectedEndpoint is selected by rule, so we it should be added to
	// EndpointsSelected.
	require.True(t, epRule.matchesSubject(selectedIdentity))

	// Test again to check for caching working correctly.
	require.True(t, epRule.matchesSubject(selectedIdentity))

	// Possible scenario where an endpoint is deleted, and soon after another
	// endpoint is added with the same ID, but with a different identity. Matching
	// needs to handle this case correctly.
	require.Equal(t, false, epRule.matchesSubject(notSelectedIdentity))

	// host endpoint is not selected by rule, so we it shouldn't be added to EndpointsSelected.
	require.Equal(t, false, epRule.matchesSubject(hostIdentity))

	// selectedEndpoint is not selected by rule, so we it shouldn't be added to EndpointsSelected.
	require.Equal(t, false, hostRule.matchesSubject(selectedIdentity))

	// host endpoint is selected by rule, but host labels are mutable, so don't cache them
	require.True(t, hostRule.matchesSubject(hostIdentity))

	// Assert that mutable host identities are handled
	// First, add an additional label, ensure that match succeeds
	hostLabels.MergeLabels(labels.NewLabelsFromModel([]string{"foo=bar"}))
	hostIdentity = identity.NewIdentity(identity.ReservedIdentityHost, hostLabels)
	td.addIdentity(hostIdentity)
	require.True(t, hostRule.matchesSubject(hostIdentity))

	// Then, change host to id=c, which is not selected, and ensure match is correct
	hostIdentity = identity.NewIdentity(identity.ReservedIdentityHost, labels.NewLabelsFromModel([]string{"id=c"}))
	td.addIdentity(hostIdentity)
	require.False(t, hostRule.matchesSubject(hostIdentity))
}

func BenchmarkRuleString(b *testing.B) {
	r := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Ingress: []api.IngressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
							{Port: "8080", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			Egress: []api.EgressRule{
				{
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "3000", Protocol: api.ProtoAny},
						},
					}},
				},
			},
		},
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = r.String()
	}
}

// Test merging of L7 rules when the same rules apply to multiple selectors.
// This was added to prevent regression of a bug where the merging of l7 rules for "foo"
// also affected the rules for "baz".
func TestMergeL7PolicyEgressWithMultipleSelectors(t *testing.T) {
	td := newTestData()
	fromBar := &SearchContext{From: labels.ParseSelectLabelArray("bar")}
	fromFoo := &SearchContext{From: labels.ParseSelectLabelArray("foo")}

	fooSelector := []api.EndpointSelector{
		api.NewESFromLabels(labels.ParseSelectLabel("foo")),
	}
	foobazSelector := []api.EndpointSelector{
		api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		api.NewESFromLabels(labels.ParseSelectLabel("baz")),
	}

	rule1 := &rule{
		Rule: api.Rule{
			EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: fooSelector,
					},
					// Note that this allows all on 80, so the result should wildcard HTTP to "foo"
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: foobazSelector,
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET"},
							},
						},
					}},
				},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			td.cachedFooSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Method: "GET"}, {}},
				},
				isRedirect: true,
			},
			td.cachedBazSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: false,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			td.cachedBazSelector: {nil},
			td.cachedFooSelector: {nil},
		},
	}})

	state := traceState{}
	res, err := rule1.resolveEgressPolicy(td.testPolicyContext, fromBar, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.EqualValues(t, expected, res)
	require.Equal(t, 1, state.selectedRules)
	require.Equal(t, 1, state.matchedRules)
	res.Detach(td.sc)
	expected.Detach(td.sc)

	state = traceState{}
	res, err = rule1.resolveEgressPolicy(td.testPolicyContext, fromFoo, &state, NewL4PolicyMap(), nil, nil)
	require.NoError(t, err)
	require.Nil(t, res)
	require.Equal(t, 0, state.selectedRules)
	require.Equal(t, 0, state.matchedRules)
}

func TestMergeListenerReference(t *testing.T) {
	// No listener remains a no listener
	ps := &PerSelectorPolicy{}
	err := ps.mergeListenerReference(ps)
	require.NoError(t, err)
	require.Equal(t, "", ps.Listener)
	require.Equal(t, uint16(0), ps.Priority)

	// Listener reference remains when the other has none
	ps0 := &PerSelectorPolicy{Listener: "listener0"}
	err = ps0.mergeListenerReference(ps)
	require.NoError(t, err)
	require.Equal(t, "listener0", ps0.Listener)
	require.Equal(t, uint16(0), ps0.Priority)

	// Listener reference is propagated when there is none to begin with
	err = ps.mergeListenerReference(ps0)
	require.NoError(t, err)
	require.Equal(t, "listener0", ps.Listener)
	require.Equal(t, uint16(0), ps.Priority)

	// A listener is not changed when there is no change
	err = ps0.mergeListenerReference(ps0)
	require.NoError(t, err)
	require.Equal(t, "listener0", ps0.Listener)
	require.Equal(t, uint16(0), ps0.Priority)

	// Cannot merge two different listeners with the default (zero) priority
	ps0a := &PerSelectorPolicy{Listener: "listener0a"}
	err = ps0.mergeListenerReference(ps0a)
	require.NotNil(t, err)

	err = ps0a.mergeListenerReference(ps0)
	require.NotNil(t, err)

	// Listener with a defined (non-zero) priority takes precedence over
	// a listener with an undefined (zero) priority
	ps1 := &PerSelectorPolicy{Listener: "listener1", Priority: 1}
	err = ps1.mergeListenerReference(ps0)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps1.Listener)
	require.Equal(t, uint16(1), ps1.Priority)

	err = ps0.mergeListenerReference(ps1)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps0.Listener)
	require.Equal(t, uint16(1), ps0.Priority)

	// Listener with the lower priority value takes precedence
	ps2 := &PerSelectorPolicy{Listener: "listener2", Priority: 2}
	err = ps1.mergeListenerReference(ps2)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps1.Listener)
	require.Equal(t, uint16(1), ps1.Priority)

	err = ps2.mergeListenerReference(ps1)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps2.Listener)
	require.Equal(t, uint16(1), ps2.Priority)

	// Cannot merge two different listeners with the same priority
	ps12 := &PerSelectorPolicy{Listener: "listener1", Priority: 2}
	ps2 = &PerSelectorPolicy{Listener: "listener2", Priority: 2}
	err = ps12.mergeListenerReference(ps2)
	require.NotNil(t, err)
	err = ps2.mergeListenerReference(ps12)
	require.NotNil(t, err)

	// Lower priority is propagated also when the listeners are the same
	ps23 := &PerSelectorPolicy{Listener: "listener2", Priority: 3}
	err = ps2.mergeListenerReference(ps23)
	require.NoError(t, err)
	require.Equal(t, "listener2", ps2.Listener)
	require.Equal(t, uint16(2), ps2.Priority)

	err = ps23.mergeListenerReference(ps2)
	require.NoError(t, err)
	require.Equal(t, "listener2", ps23.Listener)
	require.Equal(t, uint16(2), ps23.Priority)
}
