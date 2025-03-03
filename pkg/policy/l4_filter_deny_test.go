// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"testing"

	"github.com/cilium/hive/hivetest"

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
// |  1B |      -, -       |  80/TCP  | Don't select anything                                |
// |  2A |   "id=a", *     |  80/TCP  | Rule 2 is a superset of rule 1                       |
// |  2B |   *, "id=a"     |  80/TCP  | Same as 2A, but import in reverse order              |
// |  3  | "id=a", "id=c"  |  80/TCP  | Deny at L4 for two distinct labels (disjoint set)    |
// |  4A |      *, *       |  80/TCP  | Allow all communication on the specified port        |
// |     |                 |          | and deny one endpoint selector                       |
// |  4B |      *, *       |  80/TCP  | Same as 4A, but import in reverse order              |
// |  5A |      *, *       |  80/TCP  | Deny all communication on a specified endpoint       |
// |     |                 |          | except while wildcarding all L7 policy.              |
// |  5B |      *, *       |  80/TCP  | Same as 5A, but import in reverse order              |
// +-----+-----------------+----------+------------------------------------------------------+

// Case 1: deny all at L3 in both rules.
func TestMergeDenyAllL3(t *testing.T) {
	td := newTestData(hivetest.Logger(t))
	// Case 1A: Specify WildcardEndpointSelector explicitly.
	rule := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule)

	// Case1B: an empty non-nil FromEndpoints does not select any identity.
	rule = api.Rule{
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
	}

	expected = NewL4PolicyMap()
	td.policyMapEquals(t, expected, nil, &rule)
}

// Case 2: deny all at L3/L4 in one rule, and select an endpoint and deny all on
// in another rule. Should resolve to just allowing all on L3/L4 (first rule
// shadows the second).
func TestL3DenyRuleShadowedByL3DenyAll(t *testing.T) {
	td := newTestData(hivetest.Logger(t))
	// Case 2A: Specify WildcardEndpointSelector explicitly.
	shadowRule := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
			td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)

	// Case 2B: Reverse the ordering of the rules. Result should be the same.
	shadowRule = api.Rule{
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{IsDeny: true},
			td.cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)
}

// Case 3: deny all on L4 in both rules, but select different endpoints in each rule.
func TestMergingWithDifferentEndpointSelectedDenyAllL7(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	selectDifferentEndpointsDenyAllL7 := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: nil,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: &PerSelectorPolicy{IsDeny: true},
			td.cachedSelectorC: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &selectDifferentEndpointsDenyAllL7)
}

// Case 4: allow all at L3/L4 in one rule, and deny a selected an endpoint in
// another rule. Should resolve to just allowing all on L3/L4 (first rule
// shadows the second) and denying that particular endpoint.
func TestL3AllowRuleShadowedByL3DenyAll(t *testing.T) {
	td := newTestData(hivetest.Logger(t))
	// Case 4A: Specify WildcardEndpointSelector explicitly.
	shadowRule := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
			td.wildcardCachedSelector: nil,
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)

	// Case 4B: Reverse the ordering of the rules. Result should be the same.
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA:        &PerSelectorPolicy{IsDeny: true},
			td.wildcardCachedSelector: nil,
		},
		Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorA:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &shadowRule)
}

// Case 5: allow L4/L7 in all endpoints in one rule, and deny a selected an
// endpoint in another rule. Should resolve to just allowing all on L3/L7 and
// denying that particular endpoint.
func TestL3L4AllowRuleWithByL3DenyAll(t *testing.T) {
	td := newTestData(hivetest.Logger(t))
	// Case 5A: Specify WildcardEndpointSelector explicitly.
	shadowRule := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: &PerSelectorPolicy{IsDeny: true},
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Parser: ParserTypeHTTP,
				Priority: ListenerPriorityHTTP,
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

	// Case 5B: Reverse the ordering of the rules. Result should be the same.
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port:     80,
		Protocol: api.ProtoTCP,
		U8Proto:  6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorA: &PerSelectorPolicy{IsDeny: true},
			td.wildcardCachedSelector: &PerSelectorPolicy{
				L7Parser: ParserTypeHTTP,
				Priority: ListenerPriorityHTTP,
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
}
