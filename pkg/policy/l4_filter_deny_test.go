// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	stdlog "log"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// Tests in this file:
//
// How to read this table:
//   Case:  The test / subtest number.
//   L3:    Matches at L3 for rule 1,  followed by rule 2.
//   L4:    Matches at L4.
//   Notes: Extra information about the test.
//
// +-----+-----------------+----------+------------------------------------------------------+
// |Case | L3 (1, 2) match | L4 match | Notes                                                |
// +=====+=================+==========+======================================================+
// |  1A |      *, *       |  80/TCP  | Deny all communication on the specified port         |
// |  1B |      *, *       |  80/TCP  | Same as 1A, with implicit L3 wildcards               |
// |  2A |   "id=a", *     |  80/TCP  | Rule 2 is a superset of rule 1                       |
// |  2B |   *, "id=a"     |  80/TCP  | Same as 2A, but import in reverse order              |
// |  3  | "id=a", "id=c"  |  80/TCP  | Deny at L4 for two distinct labels (disjoint set)    |
// |  4A |      *, *       |  80/TCP  | Allow all communication on the specified port        |
// |     |                 |          | and deny one endpoint selector                       |
// |  4B |      *, *       |  80/TCP  | Same as 4A, but import in reverse order              |
// |  5A |      *, *       |  80/TCP  | Deny all communication on a specified endpoint        |
// |     |                 |          | except while wildcarding all L7 policy.              |
// |  5B |      *, *       |  80/TCP  | Same as 5A, but import in reverse order              |
// +-----+-----------------+----------+------------------------------------------------------+

// Case 1: deny all at L3 in both rules.
func (ds *PolicyTestSuite) TestMergeDenyAllL3(c *C) {
	// Case 1A: Specify WildcardEndpointSelector explicitly.
	repo := parseAndAddRules(c, api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
				},
				ToPorts: []api.PortDenyRule{{
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

	l4IngressDenyPolicy, err := repo.ResolveL4IngressPolicy(&ctx)
	c.Assert(err, IsNil)

	c.Log(buffer)

	expected := L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: "",
		PerSelectorPolicies: L7DataMap{
			wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress:    true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{wildcardCachedSelector: {nil}},
	}}

	c.Assert(l4IngressDenyPolicy, checker.DeepEquals, expected)
	expected.Detach(testSelectorCache)

	filter, ok := l4IngressDenyPolicy["80/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(filter.Port, Equals, 80)
	c.Assert(filter.Ingress, Equals, true)

	c.Assert(filter.SelectsAllEndpoints(), Equals, true)

	c.Assert(filter.L7Parser, Equals, ParserTypeNone)
	c.Assert(len(filter.PerSelectorPolicies), Equals, 1)
	l4IngressDenyPolicy.Detach(repo.GetSelectorCache())

	// Case1B: implicitly deny all endpoints.
	repo = parseAndAddRules(c, api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{},
				},
				ToPorts: []api.PortDenyRule{{
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

	l4IngressDenyPolicy, err = repo.ResolveL4IngressPolicy(&ctx)
	c.Assert(err, IsNil)

	c.Log(buffer)

	filter, ok = l4IngressDenyPolicy["80/TCP"]
	c.Assert(ok, Equals, true)
	c.Assert(filter.Port, Equals, 80)
	c.Assert(filter.Ingress, Equals, true)

	c.Assert(filter.SelectsAllEndpoints(), Equals, true)
	c.Assert(filter.wildcard, Not(IsNil))
	c.Assert(filter.PerSelectorPolicies[filter.wildcard].IsDeny, Equals, true)

	c.Assert(filter.L7Parser, Equals, ParserTypeNone)
	c.Assert(len(filter.PerSelectorPolicies), Equals, 1)
	l4IngressDenyPolicy.Detach(repo.GetSelectorCache())
}

// Case 2: deny all at L3/L4 in one rule, and select an endpoint and deny all on
// in another rule. Should resolve to just allowing all on L3/L4 (first rule
// shadows the second).
func (ds *PolicyTestSuite) TestL3DenyRuleShadowedByL3DenyAll(c *C) {
	// Case 2A: Specify WildcardEndpointSelector explicitly.
	shadowRule := &rule{
		Rule: api.Rule{
			EndpointSelector: endpointSelectorA,
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					},
					ToPorts: []api.PortDenyRule{{
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
	c.Log(buffer)

	expected := L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
			wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA:        {nil},
			wildcardCachedSelector: {nil},
		},
	}}

	state := traceState{}
	resDeny, err := shadowRule.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)

	// Case 2B: Reverse the ordering of the rules. Result should be the same.
	shadowRule = &rule{
		Rule: api.Rule{
			EndpointSelector: endpointSelectorA,
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{api.WildcardEndpointSelector},
					},
					ToPorts: []api.PortDenyRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
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
	c.Log(buffer)

	expected = L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
			cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA:        {nil},
			wildcardCachedSelector: {nil},
		},
	}}

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)
}

// Case 3: deny all on L4 in both rules, but select different endpoints in each rule.
func (ds *PolicyTestSuite) TestMergingWithDifferentEndpointSelectedDenyAllL7(c *C) {

	selectDifferentEndpointsDenyAllL7 := &rule{
		Rule: api.Rule{
			EndpointSelector: endpointSelectorA,
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorC},
					},
					ToPorts: []api.PortDenyRule{{
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
	c.Log(buffer)

	expected := L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorA: &PerSelectorPolicy{IsDeny: true},
			cachedSelectorC: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA: {nil},
			cachedSelectorC: {nil},
		},
	}}

	state := traceState{}
	resDeny, err := selectDifferentEndpointsDenyAllL7.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	buffer = new(bytes.Buffer)
	ctxToC := SearchContext{To: labelsC, Trace: TRACE_VERBOSE}
	ctxToC.Logging = stdlog.New(buffer, "", 0)
	c.Log(buffer)

	state = traceState{}
	resDeny, err = selectDifferentEndpointsDenyAllL7.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)
}

// Case 4: allow all at L3/L4 in one rule, and deny a selected an endpoint in
// another rule. Should resolve to just allowing all on L3/L4 (first rule
// shadows the second) and denying that particular endpoint.
func (ds *PolicyTestSuite) TestL3AllowRuleShadowedByL3DenyAll(c *C) {
	// Case 4A: Specify WildcardEndpointSelector explicitly.
	shadowRule := &rule{
		Rule: api.Rule{
			EndpointSelector: endpointSelectorA,
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
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
		}}

	buffer := new(bytes.Buffer)
	ctxToA := SearchContext{To: labelsA, Trace: TRACE_VERBOSE}
	ctxToA.Logging = stdlog.New(buffer, "", 0)
	c.Log(buffer)

	expectedDeny := L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
			wildcardCachedSelector: nil,
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA:        {nil},
			wildcardCachedSelector: {nil},
		},
	}}

	state := traceState{}
	resDeny, err := shadowRule.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expectedDeny)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expectedDeny.Detach(testSelectorCache)

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)

	// Case 4B: Reverse the ordering of the rules. Result should be the same.
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
			},
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
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
	c.Log(buffer)

	expectedDeny = L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
			wildcardCachedSelector: nil,
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA:        {nil},
			wildcardCachedSelector: {nil},
		},
	}}

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expectedDeny)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expectedDeny.Detach(testSelectorCache)

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)
}

// Case 5: allow L4/L7 in all endpoints in one rule, and deny a selected an
// endpoint in another rule. Should resolve to just allowing all on L3/L7 and
// denying that particular endpoint.
func (ds *PolicyTestSuite) TestL3L4AllowRuleWithByL3DenyAll(c *C) {
	// Case 5A: Specify WildcardEndpointSelector explicitly.
	shadowRule := &rule{
		Rule: api.Rule{
			EndpointSelector: endpointSelectorA,
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
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
	c.Log(buffer)

	expected := L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorA: &PerSelectorPolicy{IsDeny: true},
			wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA:        {nil},
			wildcardCachedSelector: {nil},
		},
	}}

	state := traceState{}
	resDeny, err := shadowRule.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)

	// Case 5B: Reverse the ordering of the rules. Result should be the same.
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
						Rules: &api.L7Rules{
							HTTP: []api.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					}},
				},
			},
			IngressDeny: []api.IngressDenyRule{
				{
					IngressCommonRule: api.IngressCommonRule{
						FromEndpoints: []api.EndpointSelector{endpointSelectorA},
					},
					ToPorts: []api.PortDenyRule{{
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
	c.Log(buffer)

	expected = L4PolicyMap{"80/TCP": &L4Filter{
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: wildcardCachedSelector,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorA: &PerSelectorPolicy{IsDeny: true},
			wildcardCachedSelector: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
				},
				isRedirect: true,
			},
		},
		Ingress: true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{
			cachedSelectorA:        {nil},
			wildcardCachedSelector: {nil},
		},
	}}

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, &ctxToA, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, Not(IsNil))
	c.Assert(resDeny, checker.DeepEquals, expected)
	c.Assert(state.selectedRules, Equals, 1)
	c.Assert(state.matchedRules, Equals, 1)
	c.Assert(state.matchedDenyRules, Equals, 1)
	resDeny.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	state = traceState{}
	resDeny, err = shadowRule.resolveIngressPolicy(testPolicyContext, toFoo, &state, L4PolicyMap{}, nil, nil)
	c.Assert(err, IsNil)
	c.Assert(resDeny, IsNil)
	c.Assert(state.selectedRules, Equals, 0)
	c.Assert(state.matchedRules, Equals, 0)
	c.Assert(state.matchedDenyRules, Equals, 0)
}
