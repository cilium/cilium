// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/require"

	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/identity/identitymanager"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	"github.com/cilium/cilium/pkg/policy/utils"
	"github.com/cilium/cilium/pkg/u8proto"
)

func TestL4Policy(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule1 := &api.Rule{
		EndpointSelector: endpointSelectorA,
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
	}

	// Transform to PolicyEntries and set priority level to 0.5
	require.NoError(t, rule1.Sanitize())
	entries := utils.RulesToPolicyEntries(api.Rules{rule1})
	require.Len(t, entries, 2)
	for i := range entries {
		entries[i].Priority = 0.5
	}

	l7rules := api.L7Rules{
		HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
	}
	l7map := L7DataMap{
		td.wildcardCachedSelector: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeHTTP,
			ListenerPriority: ListenerPriorityHTTP,
			L7Rules:          l7rules,
			Priority:         0, // will still be zero, since there is only one "tier" of entry priorities
		},
	}
	l7mapLevelOnly := L7DataMap{
		td.wildcardCachedSelector: nil, // allow priority zero is compressed to nil
	}

	expected := NewL4Policy(0)
	expected.Ingress.PortRules[0].Upsert("80", 0, "TCP", &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})
	expected.Ingress.PortRules[0].Upsert("8080", 0, "TCP", &L4Filter{
		Port: 8080, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})

	expected.Egress.PortRules[0].Upsert("3000", 0, "TCP", &L4Filter{
		Port: 3000, Protocol: api.ProtoTCP, U8Proto: 6, Ingress: false,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7mapLevelOnly,
		RuleOrigin:          OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})
	expected.Egress.PortRules[0].Upsert("3000", 0, "UDP", &L4Filter{
		Port: 3000, Protocol: api.ProtoUDP, U8Proto: 17, Ingress: false,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7mapLevelOnly,
		RuleOrigin:          OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})
	expected.Egress.PortRules[0].Upsert("3000", 0, "SCTP", &L4Filter{
		Port: 3000, Protocol: api.ProtoSCTP, U8Proto: 132, Ingress: false,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7mapLevelOnly,
		RuleOrigin:          OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})

	td.policyMapEqualsPolicyEntries(t, expected.Ingress.PortRules, expected.Egress.PortRules, entries...)

	// This rule actually overlaps with the existing ingress "http" rule,
	// so we'd expect it to merge.
	rule2 := api.Rule{
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
	}

	expected = NewL4Policy(0)
	expected.Ingress.PortRules[0].Upsert("80", 0, "TCP", &L4Filter{
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
	})
	expected.Egress.PortRules[0].Upsert("3000", 0, "TCP", &L4Filter{
		Port: 3000, Protocol: api.ProtoTCP, U8Proto: 6, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})
	expected.Egress.PortRules[0].Upsert("3000", 0, "UDP", &L4Filter{
		Port: 3000, Protocol: api.ProtoUDP, U8Proto: 17, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})
	expected.Egress.PortRules[0].Upsert("3000", 0, "SCTP", &L4Filter{
		Port: 3000, Protocol: api.ProtoSCTP, U8Proto: 132, Ingress: false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	})

	td.policyMapEquals(t, expected.Ingress.PortRules, expected.Egress.PortRules, &rule2)
}

func TestMergeL4PolicyIngress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule := api.Rule{
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
	}

	mergedES := L7DataMap{
		td.cachedFooSelector: nil,
		td.cachedBazSelector: nil,
	}
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		PerSelectorPolicies: mergedES, Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedFooSelector: {nil},
			td.cachedBazSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule)
}

func TestMergeL4PolicyEgress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// A can access B with TCP on port 80, and C with TCP on port 80.
	rule1 := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
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
				}},
			},
		},
	}

	mergedES := L7DataMap{
		td.cachedSelectorB: nil,
		td.cachedSelectorC: nil,
	}
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		PerSelectorPolicies: mergedES, Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &rule1)
}

func TestMergeL7PolicyIngress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
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
					FromEndpoints: api.EndpointSelectorSlice{endpointSelectorB},
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
			td.cachedSelectorB: &PerSelectorPolicy{
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
			td.cachedSelectorB:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule1)

	rule2 := api.Rule{
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
					FromEndpoints: api.EndpointSelectorSlice{endpointSelectorB},
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

	l7rules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "foo"}},
	}
	l7map := L7DataMap{
		td.wildcardCachedSelector: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeKafka,
			ListenerPriority: ListenerPriorityKafka,
			L7Rules:          l7rules,
		},
		td.cachedSelectorB: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeKafka,
			ListenerPriority: ListenerPriorityKafka,
			L7Rules:          l7rules,
		},
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule2)

	td.policyInvalid(t, "cannot merge conflicting L7 parsers", &rule1, &rule2)

	// Similar to 'rule2', but with different topics for the l3-dependent
	// rule and the l4-only rule.
	rule3 := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: api.EndpointSelectorSlice{endpointSelectorB},
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
	}

	fooRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "foo"}},
	}

	barRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "bar"}},
	}

	// The L3-dependent L7 rules are not merged together.
	l7map = L7DataMap{
		td.cachedSelectorB: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeKafka,
			ListenerPriority: ListenerPriorityKafka,
			L7Rules:          fooRules,
		},
		td.wildcardCachedSelector: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeKafka,
			ListenerPriority: ListenerPriorityKafka,
			L7Rules:          barRules,
		},
	}
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7map, Ingress: true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule3)
}

func TestMergeL7PolicyEgress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
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
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}, {}},
				},
			},
			td.cachedSelectorB: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Path: "/private", Method: "GET"}},
				},
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.wildcardCachedSelector: {nil},
			td.cachedSelectorB:        {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &rule1)

	rule2 := api.Rule{
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
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
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

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{Path: "/public", Method: "GET"}, {}},
					},
				},
				td.cachedSelectorB: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{Path: "/private", Method: "GET"}},
					},
				},
			},
			Ingress: false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.wildcardCachedSelector: {nil},
				td.cachedSelectorB:        {nil},
			}),
		},
		"9092/TCP": {
			Port: 9092, Protocol: api.ProtoTCP, U8Proto: 6,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeKafka,
					ListenerPriority: ListenerPriorityKafka,
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{{Topic: "foo"}, {}},
					},
				},
				td.cachedSelectorB: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeKafka,
					ListenerPriority: ListenerPriorityKafka,
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{{Topic: "foo"}},
					},
				},
			},
			Ingress: false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorB:        {nil},
				td.wildcardCachedSelector: {nil},
			}),
		},
	})

	td.policyMapEquals(t, nil, expected, &rule1, &rule2)

	// Similar to 'rule2', but with different topics for the l3-dependent
	// rule and the l4-only rule.
	rule3 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
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
	}
	fooRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "foo"}},
	}
	barRules := api.L7Rules{
		Kafka: []kafka.PortRule{{Topic: "bar"}},
	}

	// The l3-dependent l7 rules are not merged together.
	l7map := L7DataMap{
		td.cachedSelectorB: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeKafka,
			ListenerPriority: ListenerPriorityKafka,
			L7Rules:          fooRules,
		},
		td.wildcardCachedSelector: &PerSelectorPolicy{
			Verdict:          types.Allow,
			L7Parser:         ParserTypeKafka,
			ListenerPriority: ListenerPriorityKafka,
			L7Rules:          barRules,
		},
	}
	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard:            td.wildcardCachedSelector,
		PerSelectorPolicies: l7map, Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &rule3)
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
	require.Error(t, err)
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

	// Must be parsable, make sure Validate fails when not.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDR: []api.CIDR{"10.0.1..0/24"},
			},
		}},
	}).Sanitize()
	require.Error(t, err)

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
	require.Error(t, err)

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
	require.Error(t, err)

	// Cannot exclude a range that is not part of the CIDR.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDRSet: []api.CIDRRule{{Cidr: "10.0.0.0/10", ExceptCIDRs: []api.CIDR{"10.64.0.0/11"}}},
			},
		}},
	}).Sanitize()
	require.Error(t, err)

	// Must have a contiguous mask, make sure Validate fails when not.
	err = (&api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromCIDR: []api.CIDR{"10.0.1.0/128.0.0.128"},
			},
		}},
	}).Sanitize()
	require.Error(t, err)

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
	require.Error(t, err)
}

func TestICMPPolicy(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	// A rule for ICMP
	i8 := intstr.FromInt(8)
	i9 := intstr.FromInt(9)

	rule1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type: &i8,
					}},
				}},
			},
		},
		Egress: []api.EgressRule{
			{
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type: &i9,
					}},
				}},
			},
		},
	}

	expectedIn := NewL4PolicyMapWithValues(map[string]*L4Filter{"ICMP/8": {
		Port:     8,
		Protocol: api.ProtoICMP,
		U8Proto:  u8proto.ProtoIDs["icmp"],
		Ingress:  true,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	expectedOut := NewL4PolicyMapWithValues(map[string]*L4Filter{"ICMP/9": {
		Port:     9,
		Protocol: api.ProtoICMP,
		U8Proto:  u8proto.ProtoIDs["icmp"],
		Ingress:  false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expectedIn, expectedOut, &rule1)

	// A rule for Ports and ICMP
	rule2 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			}, {
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type: &i8,
					}},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"ICMP/8": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  u8proto.ProtoIDs["icmp"],
			Ingress:  true,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
		"TCP/80": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  u8proto.ProtoIDs["tcp"],
			Ingress:  true,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &rule2)

	// A rule for ICMPv6
	icmpV6Type := intstr.FromInt(128)
	rule3 := api.Rule{
		EndpointSelector: endpointSelectorA,
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"ICMPV6/128": {
		Port:     128,
		Protocol: api.ProtoICMPv6,
		U8Proto:  u8proto.ProtoIDs["icmp"],
		Ingress:  true,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.wildcardCachedSelector: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule3)
}

func TestIPProtocolsWithNoTransportPorts(t *testing.T) {
	old := option.Config.EnableExtendedIPProtocols
	option.Config.EnableExtendedIPProtocols = true
	t.Cleanup(func() {
		option.Config.EnableExtendedIPProtocols = old
	})
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{
							{
								Protocol: api.ProtoVRRP,
							},
							{
								Protocol: api.ProtoIGMP,
							},
						},
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToPorts: []api.PortRule{
					{
						Ports: []api.PortProtocol{
							{
								Protocol: api.ProtoVRRP,
							},
						},
					},
				},
			},
		},
	}

	expectedIn := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/vrrp": {
			Port:     0,
			Protocol: api.ProtoVRRP,
			U8Proto:  u8proto.ProtoIDs["vrrp"],
			Ingress:  true,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
		},
		"0/igmp": {
			Port:     0,
			Protocol: api.ProtoIGMP,
			U8Proto:  u8proto.ProtoIDs["igmp"],
			Ingress:  true,
			wildcard: td.wildcardCachedSelector,
			PerSelectorPolicies: L7DataMap{
				td.wildcardCachedSelector: nil,
			},
		},
	})

	expectedOut := NewL4PolicyMapWithValues(map[string]*L4Filter{"0/egress": {
		Port:     0,
		Protocol: api.ProtoVRRP,
		U8Proto:  u8proto.ProtoIDs["vrrp"],
		Ingress:  false,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
		},
	}})

	td.policyMapEquals(t, expectedIn, expectedOut, &rule1)
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
	require.Error(t, err)
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
	require.NoError(t, r.Sanitize())
	require.Len(t, r.Egress[0].ToEntities, 1)

	r.Egress[0].ToEntities = []api.Entity{api.EntityHost}
	require.NoError(t, r.Sanitize())
	require.Len(t, r.Egress[0].ToEntities, 1)

	r.Egress[0].ToEntities = []api.Entity{"trololo"}
	require.Error(t, r.Sanitize())
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
	require.NoError(t, r.Sanitize())
	require.Len(t, r.Ingress[0].FromEntities, 1)

	r.Ingress[0].FromEntities = []api.Entity{api.EntityHost}
	require.NoError(t, r.Sanitize())
	require.Len(t, r.Ingress[0].FromEntities, 1)

	r.Ingress[0].FromEntities = []api.Entity{"trololo"}
	require.Error(t, r.Sanitize())
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
	require.NoError(t, r.Sanitize())
	require.Len(t, r.Ingress[0].FromEntities, 2)
	require.Len(t, r.Egress[0].ToEntities, 2)
}

func TestL3RuleLabels(t *testing.T) {
	logger := hivetest.Logger(t)

	ruleLabels := map[string]labels.LabelArray{
		"rule0": labels.ParseLabelArray("name=apiRule0"),
		"rule1": labels.ParseLabelArray("name=apiRule1"),
		"rule2": labels.ParseLabelArray("name=apiRule2"),
	}

	rules := map[string]api.Rule{
		"rule0": {
			EndpointSelector: endpointSelectorA,
			Labels:           ruleLabels["rule0"],
			Ingress:          []api.IngressRule{{}},
			Egress:           []api.EgressRule{{}},
		},
		"rule1": {
			EndpointSelector: endpointSelectorA,
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
			EndpointSelector: endpointSelectorA,
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

	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			td := newTestData(t, logger).withIDs(ruleTestIDs)

			for _, r := range test.rulesToApply {
				td.repo.mustAdd(rules[r])
			}
			finalPolicy, err := td.repo.resolvePolicyLocked(idA)
			require.NoError(t, err)
			require.Len(t, finalPolicy.L4Policy.Ingress.PortRules, 1)
			require.Len(t, finalPolicy.L4Policy.Egress.PortRules, 1)

			type expectedResult map[string]labels.LabelArrayList
			mapDirectionalResultsToExpectedOutput := map[*L4Filter]expectedResult{
				finalPolicy.L4Policy.Ingress.PortRules[0].ExactLookup("0", 0, "ANY"): test.expectedIngressLabels,
				finalPolicy.L4Policy.Egress.PortRules[0].ExactLookup("0", 0, "ANY"):  test.expectedEgressLabels,
			}
			for filter, exp := range mapDirectionalResultsToExpectedOutput {
				if len(exp) > 0 {
					for cidr, rule := range exp {
						matches := false
						for _, origin := range filter.RuleOrigin {
							lbls := origin.GetLabelArrayList()
							if lbls.Equals(rule) {
								matches = true
								break
							}
						}
						require.True(t, matches, "%s: expected filter %+v to be derived from rule %s", test.description, filter, rule)

						matches = false
						for sel := range filter.PerSelectorPolicies {
							cidrLabels := labels.ParseLabelArray("cidr:" + cidr)
							t.Logf("Testing %+v", cidrLabels)
							if matches = sel.(*identitySelector).source.(*types.CIDRSelector).Matches(cidrLabels); matches {
								break
							}
						}
						require.True(t, matches, "%s: expected cidr %s to match filter %+v", test.description, cidr, filter)
					}
				}
			}
		})
	}
}

func TestL4RuleLabels(t *testing.T) {
	ruleLabels := map[string]labels.LabelArray{
		"rule0": labels.ParseLabelArray("name=apiRule0"),
		"rule1": labels.ParseLabelArray("name=apiRule1"),
		"rule2": labels.ParseLabelArray("name=apiRule2"),
	}

	rules := map[string]api.Rule{
		"rule0": {
			EndpointSelector: endpointSelectorA,
			Labels:           ruleLabels["rule0"],
			Ingress:          []api.IngressRule{{}},
			Egress:           []api.EgressRule{{}},
		},

		"rule1": {
			EndpointSelector: endpointSelectorA,
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
			EndpointSelector: endpointSelectorA,
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

	for i, test := range testCases {
		t.Run(fmt.Sprintf("%d", i), func(t *testing.T) {
			td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
			for _, r := range test.rulesToApply {
				td.repo.mustAdd(rules[r])
			}

			finalPolicy, err := td.repo.resolvePolicyLocked(idA)
			require.NoError(t, err)

			ingressLen := 0
			if len(finalPolicy.L4Policy.Ingress.PortRules) > 0 {
				ingressLen = finalPolicy.L4Policy.Ingress.PortRules[0].Len()
			}
			require.Equal(t, len(test.expectedIngressLabels), ingressLen, test.description)
			for portProto := range test.expectedIngressLabels {
				portProtoSlice := strings.Split(portProto, "/")
				out := finalPolicy.L4Policy.Ingress.PortRules[0].ExactLookup(portProtoSlice[0], 0, portProtoSlice[1])
				require.NotNil(t, out, test.description)
				require.Len(t, out.RuleOrigin, 1, test.description)
				lbls := out.RuleOrigin[out.wildcard].GetLabelArrayList()
				require.Equal(t, test.expectedIngressLabels[portProto], lbls, test.description)
			}

			egressLen := 0
			if len(finalPolicy.L4Policy.Egress.PortRules) > 0 {
				egressLen = finalPolicy.L4Policy.Egress.PortRules[0].Len()
			}
			require.Equal(t, len(test.expectedEgressLabels), egressLen, test.description)
			for portProto := range test.expectedEgressLabels {
				portProtoSlice := strings.Split(portProto, "/")
				out := finalPolicy.L4Policy.Egress.PortRules[0].ExactLookup(portProtoSlice[0], 0, portProtoSlice[1])
				require.NotNil(t, out, test.description)
				require.Len(t, out.RuleOrigin, 1, test.description)
				lbls := out.RuleOrigin[out.wildcard].GetLabelArrayList()
				require.Equal(t, test.expectedEgressLabels[portProto], lbls, test.description)
			}
		})
	}
}

func TestRuleLog(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)

	// test merging on a per-selector basis, as well as for overlapping selectors

	nsDefaultSelector := api.NewESFromLabels(labels.ParseSelectLabel("io.kubernetes.pod.namespace=default"))
	rules := api.Rules{
		// rule1, rule2 selects id=b -- should merge in L4Filter
		// rule3 selects namespace = default -- should merge in MapState
		{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorB},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
			Log: api.LogConfig{Value: "rule1"},
		},
		{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{endpointSelectorB},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
			Log: api.LogConfig{Value: "rule2"},
		},
		{
			EndpointSelector: endpointSelectorA,
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{nsDefaultSelector},
					},
					ToPorts: []api.PortRule{{
						Ports: []api.PortProtocol{
							{Port: "80", Protocol: api.ProtoTCP},
						},
					}},
				},
			},
			Log: api.LogConfig{Value: "rule3"},
		},
	}

	// endpoint b should have all 3 rules
	td.repo.MustAddList(rules)
	verdict, egress, _, err := LookupFlow(td.repo.logger, td.repo, td.identityManager, flowAToB, nil, nil)
	require.NoError(t, err)
	require.Equal(t, api.Allowed, verdict)
	require.Equal(t, []string{"rule1", "rule2", "rule3"}, egress.Log())

	// endpoint c should have just rule3
	verdict, egress, _, err = LookupFlow(td.repo.logger, td.repo, td.identityManager, flowAToC, nil, nil)
	require.NoError(t, err)
	require.Equal(t, api.Allowed, verdict)
	require.Equal(t, []string{"rule3"}, egress.Log())

}

var (
	labelsA = labels.LabelArray{
		labels.NewLabel("id", "a", labels.LabelSourceK8s),
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
	}
	idA               = identity.NewIdentity(1001, labelsA.Labels())
	endpointSelectorA = api.NewESFromLabels(labels.ParseSelectLabel("id=a"))
	labelSelectorA    = types.NewLabelSelector(endpointSelectorA)

	labelsB = labels.LabelArray{
		labels.NewLabel("id1", "b", labels.LabelSourceK8s),
		labels.NewLabel("id2", "t", labels.LabelSourceK8s),
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
	}
	idB               = identity.NewIdentity(1002, labelsB.Labels())
	endpointSelectorB = api.NewESFromLabels(labels.ParseSelectLabel("id1=b"))

	labelsC = labels.LabelArray{
		labels.NewLabel("id", "t", labels.LabelSourceK8s),
		labels.NewLabel("io.kubernetes.pod.namespace", "default", labels.LabelSourceK8s),
	}
	idC               = identity.NewIdentity(1003, labelsC.Labels())
	endpointSelectorC = api.NewESFromLabels(labels.ParseSelectLabel("id=t"))
	labelSelectorC    = types.NewLabelSelector(endpointSelectorC)

	flowAToB   = Flow{From: idA, To: idB, Proto: u8proto.TCP, Dport: 80}
	flowAToC   = Flow{From: idA, To: idC, Proto: u8proto.TCP, Dport: 80}
	flowAToC90 = Flow{From: idA, To: idC, Proto: u8proto.TCP, Dport: 90}

	flowAToWorld80 = Flow{From: idA, To: identity.LookupReservedIdentity(identity.ReservedIdentityWorld), Proto: u8proto.TCP, Dport: 80}
	flowAToWorld90 = Flow{From: idA, To: identity.LookupReservedIdentity(identity.ReservedIdentityWorld), Proto: u8proto.TCP, Dport: 90}

	ruleTestIDs = identity.IdentityMap{
		idA.ID: idA.LabelArray,
		idB.ID: idB.LabelArray,
		idC.ID: idC.LabelArray,
	}

	defaultDenyIngress = &types.PolicyEntry{
		Subject:     types.WildcardSelector,
		Ingress:     true,
		DefaultDeny: true,
		Verdict:     types.Allow,
	}
	namedPorts = map[string]uint16{
		"port-80": 80,
		"port-90": 90,
	}
)

func checkFlow(t *testing.T, repo *Repository, idManager identitymanager.IDManager, flow Flow, verdict api.Decision) {
	t.Helper()

	srcEP := &EndpointInfo{
		ID:            1,
		TCPNamedPorts: namedPorts,
	}

	dstEP := &EndpointInfo{
		ID:            2,
		TCPNamedPorts: namedPorts,
	}

	actual, _, _, err := LookupFlow(hivetest.Logger(t), repo, idManager, flow, srcEP, dstEP)
	require.NoError(t, err)
	require.Equal(t, verdict, actual)
}

func TestIngressAllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
	repo := td.repo
	repo.MustAddPolicyEntries(types.PolicyEntries{
		defaultDenyIngress,
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			// Allow all L3&L4 ingress rule
			L3: types.ToSelectors(api.WildcardEndpointSelector),
		}})

	checkFlow(t, repo, td.identityManager, flowAToB, api.Denied)
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)

	checkFlow(t, repo, td.identityManager, flowAToC90, api.Allowed)
}

func TestIngressAllowAllL4Overlap(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
	repo := td.repo
	repo.MustAddPolicyEntries(types.PolicyEntries{
		defaultDenyIngress,
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			// Allow all L3&L4 ingress rule
			L3: types.ToSelectors(api.WildcardEndpointSelector),
		}, &types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			// This rule is a subset of the above
			// rule and should *NOT* restrict to
			// port 80 only
			L4: []api.PortRule{{
				Ports: []api.PortProtocol{
					{Port: "80", Protocol: api.ProtoTCP},
				},
			}},
		},
	})

	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Allowed)
}

func TestIngressAllowAllNamedPort(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
	repo := td.repo
	repo.MustAddPolicyEntries(types.PolicyEntries{
		defaultDenyIngress,
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			// Allow all L3&L4 ingress rule
			L3: types.ToSelectors(api.WildcardEndpointSelector),
			L4: []api.PortRule{{
				Ports: []api.PortProtocol{
					{Port: "port-80", Protocol: api.ProtoTCP},
				},
			}},
		},
	})

	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToB, api.Denied)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)
}

func TestIngressAllowAllL4OverlapNamedPort(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
	repo := td.repo
	repo.MustAddPolicyEntries(types.PolicyEntries{
		defaultDenyIngress,
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			// Allow all L3&L4 ingress rule
			L3: types.ToSelectors(api.WildcardEndpointSelector),
		}, &types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			// This rule is a subset of the above
			// rule and should *NOT* restrict to
			// port 80 only
			L4: []api.PortRule{{
				Ports: []api.PortProtocol{
					{Port: "port-80", Protocol: api.ProtoTCP},
				},
			}},
		},
	})
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Allowed)
}

func TestIngressL4AllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
	repo := td.repo
	repo.MustAddPolicyEntries(types.PolicyEntries{
		defaultDenyIngress,
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorC,
			L3:          types.Selectors{},
			L4: []api.PortRule{{
				Ports: []api.PortProtocol{
					{Port: "80", Protocol: api.ProtoTCP},
				},
			}},
		},
	})
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)

	pol, err := repo.resolvePolicyLocked(idC)
	require.NoError(t, err)
	defer pol.detach(true, 0)

	filter := pol.L4Policy.Ingress.PortRules[0].ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.True(t, filter.Ingress)

	require.Len(t, filter.PerSelectorPolicies, 1)
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
}

func TestIngressL4AllowAllNamedPort(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
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

	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)

	pol, err := repo.resolvePolicyLocked(idC)
	require.NoError(t, err)
	defer pol.detach(true, 0)

	filter := pol.L4Policy.Ingress.PortRules[0].ExactLookup("port-80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(0), filter.Port)
	require.Equal(t, "port-80", filter.PortName)
	require.True(t, filter.Ingress)

	require.Len(t, filter.PerSelectorPolicies, 1)
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
}

func TestEgressAllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
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

	checkFlow(t, repo, td.identityManager, flowAToB, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Allowed)

}

func TestEgressL4AllowAll(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
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

	checkFlow(t, repo, td.identityManager, flowAToB, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)

	pol, err := repo.resolvePolicyLocked(idA)
	require.NoError(t, err)
	defer pol.detach(true, 0)

	t.Log(pol.L4Policy.Egress.PortRules)
	filter := pol.L4Policy.Egress.PortRules[0].ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.False(t, filter.Ingress)

	require.Len(t, filter.PerSelectorPolicies, 1)
	require.Nil(t, filter.PerSelectorPolicies[td.wildcardCachedSelector])
}

func TestEgressL4AllowWorld(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
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

	checkFlow(t, repo, td.identityManager, flowAToWorld80, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToWorld90, api.Denied)

	// Pod to pod must be denied on port 80 and 90, only world was whitelisted
	checkFlow(t, repo, td.identityManager, flowAToC, api.Denied)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)

	pol, err := repo.resolvePolicyLocked(idA)
	require.NoError(t, err)
	defer pol.detach(true, 0)

	filter := pol.L4Policy.Egress.PortRules[0].ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.False(t, filter.Ingress)

	require.Len(t, filter.PerSelectorPolicies, 3)
}

func TestEgressL4AllowAllEntity(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
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

	checkFlow(t, repo, td.identityManager, flowAToWorld80, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToWorld90, api.Denied)

	// Pod to pod must be allowed on port 80, denied on port 90 (all identity)
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)

	pol, err := repo.resolvePolicyLocked(idA)
	require.NoError(t, err)
	defer pol.detach(true, 0)

	filter := pol.L4Policy.Egress.PortRules[0].ExactLookup("80", 0, "TCP")
	require.NotNil(t, filter)
	require.Equal(t, uint16(80), filter.Port)
	require.False(t, filter.Ingress)

	require.Len(t, filter.PerSelectorPolicies, 1)
}

func TestEgressL3AllowWorld(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
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

	checkFlow(t, repo, td.identityManager, flowAToWorld80, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToWorld90, api.Allowed)

	// Pod to pod must be denied on port 80 and 90, only world was whitelisted
	checkFlow(t, repo, td.identityManager, flowAToC, api.Denied)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Denied)
}

func TestEgressL3AllowAllEntity(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
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

	checkFlow(t, repo, td.identityManager, flowAToWorld80, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToWorld90, api.Allowed)

	// Pod to pod must be allowed on both port 80 and 90 (L3 only rule)
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToC90, api.Allowed)
}

func TestL4WildcardMerge(t *testing.T) {
	// First, test implicit case.
	//
	// Test the case where if we have rules that select the same endpoint on the
	// same port-protocol tuple with one that is L4-only, and the other applying
	// at L4 and L7, that the L4-only rule shadows the L4-L7 rule. This is because
	// L4-only rule implicitly allows all traffic at L7, so the L7-related
	// parts of the L4-L7 rule are useless.
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorC: &PerSelectorPolicy{
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
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	},
		"7000/TCP": {
			Port: 7000, Protocol: api.ProtoTCP, U8Proto: 6,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorC: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         "testparser",
					ListenerPriority: ListenerPriorityNone,
					L7Rules: api.L7Rules{
						L7Proto: "testparser",
						L7:      []api.PortRuleL7{{"Key": "Value"}, {}},
					},
				},
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorC: {nil}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &rule1)

	// Test the reverse order as well; ensure that we check both conditions
	// for if L4-only policy is in the L4Filter for the same port-protocol tuple,
	// and L7 metadata exists in the L4Filter we are adding; expect to resolve
	// to L4-only policy without any L7-metadata.
	rule2 := api.Rule{
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
	}

	td.policyMapEquals(t, expected, nil, &rule2)

	// Second, test the explicit allow at L3.
	rule3 := api.Rule{
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorC: &PerSelectorPolicy{
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
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule3)

	// Test the reverse order as well; ensure that we check both conditions
	// for if L4-only policy is in the L4Filter for the same port-protocol tuple,
	// and L7 metadata exists in the L4Filter we are adding; expect to resolve
	// to L4-only policy without any L7-metadata.
	rule4 := api.Rule{
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.wildcardCachedSelector: nil,
			td.cachedSelectorC: &PerSelectorPolicy{
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
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule4)
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
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
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
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: nil,
			td.wildcardCachedSelector: &PerSelectorPolicy{
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
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})

	td.policyMapEquals(t, expected, nil, &rule1)

	rule2 := api.Rule{
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
	}

	expected = NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		wildcard: td.wildcardCachedSelector,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorC: nil,
			td.wildcardCachedSelector: &PerSelectorPolicy{
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
			td.cachedSelectorC:        {nil},
			td.wildcardCachedSelector: {nil},
		}),
	}})
	td.policyMapEquals(t, expected, nil, &rule2)
}

func TestMatches(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))
	repo := td.repo
	repo.MustAddPolicyEntries(types.PolicyEntries{
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     labelSelectorA,
			L3:          types.Selectors{labelSelectorC},
		},
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject: types.NewLabelSelectorFromLabels(
				labels.ParseSelectLabel("id=a"),
				labels.NewLabel(labels.IDNameHost, "", labels.LabelSourceReserved),
			),
			Node: true,
			L3:   types.Selectors{labelSelectorC},
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
	require.False(t, epRule.matchesSubject(notSelectedIdentity))

	// selectedEndpoint is selected by rule, so we it should be added to
	// EndpointsSelected.
	require.True(t, epRule.matchesSubject(selectedIdentity))

	// Test again to check for caching working correctly.
	require.True(t, epRule.matchesSubject(selectedIdentity))

	// Possible scenario where an endpoint is deleted, and soon after another
	// endpoint is added with the same ID, but with a different identity. Matching
	// needs to handle this case correctly.
	require.False(t, epRule.matchesSubject(notSelectedIdentity))

	// host endpoint is not selected by rule, so we it shouldn't be added to EndpointsSelected.
	require.False(t, epRule.matchesSubject(hostIdentity))

	// selectedEndpoint is not selected by rule, so we it shouldn't be added to EndpointsSelected.
	require.False(t, hostRule.matchesSubject(selectedIdentity))

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

// Test merging of L7 rules when the same rules apply to multiple selectors.
// This was added to prevent regression of a bug where the merging of l7 rules for "foo"
// also affected the rules for "baz".
func TestMergeL7PolicyEgressWithMultipleSelectors(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
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
							{Method: "GET"},
						},
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
							{Host: "foo"},
						},
					},
				}},
			},
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: nil,
			td.cachedSelectorC: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Method: "GET"}, {Host: "foo"}},
				},
			},
		},
		Ingress: false,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
			td.cachedSelectorB: {nil},
			td.cachedSelectorC: {nil},
		}),
	}})

	td.policyMapEquals(t, nil, expected, &rule1)
}

func TestMergeListenerReference(t *testing.T) {
	// No listener remains a no listener
	ps := &PerSelectorPolicy{Verdict: types.Allow}
	err := ps.mergeRedirect(ps)
	require.NoError(t, err)
	require.Empty(t, ps.Listener)
	require.Equal(t, ListenerPriority(0), ps.ListenerPriority)

	// Listener reference remains when the other has none
	ps0 := &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener0"}
	err = ps0.mergeRedirect(ps)
	require.NoError(t, err)
	require.Equal(t, "listener0", ps0.Listener)
	require.Equal(t, ListenerPriority(0), ps0.ListenerPriority)

	// Listener reference is propagated when there is none to begin with
	err = ps.mergeRedirect(ps0)
	require.NoError(t, err)
	require.Equal(t, "listener0", ps.Listener)
	require.Equal(t, ListenerPriority(0), ps.ListenerPriority)

	// A listener is not changed when there is no change
	err = ps0.mergeRedirect(ps0)
	require.NoError(t, err)
	require.Equal(t, "listener0", ps0.Listener)
	require.Equal(t, ListenerPriority(0), ps0.ListenerPriority)

	// Cannot merge two different listeners with the default (zero) priority
	ps0a := &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener0a"}
	err = ps0.mergeRedirect(ps0a)
	require.Error(t, err)

	err = ps0a.mergeRedirect(ps0)
	require.Error(t, err)

	// Listener with a defined (non-zero) priority takes precedence over
	// a listener with an undefined (zero) priority
	ps1 := &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener1", ListenerPriority: 1}
	err = ps1.mergeRedirect(ps0)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps1.Listener)
	require.Equal(t, ListenerPriority(1), ps1.ListenerPriority)

	err = ps0.mergeRedirect(ps1)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps0.Listener)
	require.Equal(t, ListenerPriority(1), ps0.ListenerPriority)

	// Listener with the lower priority value takes precedence
	ps2 := &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener2", ListenerPriority: 2}
	err = ps1.mergeRedirect(ps2)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps1.Listener)
	require.Equal(t, ListenerPriority(1), ps1.ListenerPriority)

	err = ps2.mergeRedirect(ps1)
	require.NoError(t, err)
	require.Equal(t, "listener1", ps2.Listener)
	require.Equal(t, ListenerPriority(1), ps2.ListenerPriority)

	// Cannot merge two different listeners with the same priority
	ps12 := &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener1", ListenerPriority: 2}
	ps2 = &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener2", ListenerPriority: 2}
	err = ps12.mergeRedirect(ps2)
	require.Error(t, err)
	err = ps2.mergeRedirect(ps12)
	require.Error(t, err)

	// Lower priority is propagated also when the listeners are the same
	ps23 := &PerSelectorPolicy{Verdict: types.Allow, Listener: "listener2", ListenerPriority: 3}
	err = ps2.mergeRedirect(ps23)
	require.NoError(t, err)
	require.Equal(t, "listener2", ps2.Listener)
	require.Equal(t, ListenerPriority(2), ps2.ListenerPriority)

	err = ps23.mergeRedirect(ps2)
	require.NoError(t, err)
	require.Equal(t, "listener2", ps23.Listener)
	require.Equal(t, ListenerPriority(2), ps23.ListenerPriority)
}
