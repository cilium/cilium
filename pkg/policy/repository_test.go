// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"sync"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/pkg/identity"
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
	policytypes "github.com/cilium/cilium/pkg/policy/types"
	testpolicy "github.com/cilium/cilium/pkg/testutils/policy"
)

// mustAdd inserts a rule into the policy repository
// This is just a helper function for unit testing.
// Only returns error for signature reasons
func (p *Repository) mustAdd(r api.Rule) (uint64, map[uint16]struct{}, error) {
	_, rev := p.MustAddList(api.Rules{&r})
	return rev, map[uint16]struct{}{}, nil
}

func (p *Repository) mustAddPolicyEntry(e policytypes.PolicyEntry) (uint64, map[uint16]struct{}, error) {
	_, rev := p.MustAddPolicyEntries(policytypes.PolicyEntries{&e})
	return rev, map[uint16]struct{}{}, nil
}

func TestComputePolicyEnforcementAndRules(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	td := newTestData(t, hivetest.Logger(t))
	repo := td.repo

	fooSelectLabel := labels.ParseSelectLabel("foo")
	fooNumericIdentity := 9001
	fooIdentity := identity.NewIdentity(identity.NumericIdentity(fooNumericIdentity), lbls)
	td.addIdentity(fooIdentity)
	fooIngressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule1", labels.LabelSourceAny)
	fooIngressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule2", labels.LabelSourceAny)
	fooEgressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule1", labels.LabelSourceAny)
	fooEgressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule2", labels.LabelSourceAny)
	combinedLabel := labels.NewLabel(k8sConst.PolicyLabelName, "combined", labels.LabelSourceAny)
	fooIngressRule1Resource := ipcachetypes.ResourceID("fooIngressRule1Resource")
	fooIngressRule2Resource := ipcachetypes.ResourceID("fooIngressRule2Resource")
	fooEgressRule1Resource := ipcachetypes.ResourceID("fooEgressRule1Resource")
	fooEgressRule2Resource := ipcachetypes.ResourceID("fooEgressRule2Resource")
	combinedResource := ipcachetypes.ResourceID("combinedResource")
	initIdentity := identity.LookupReservedIdentity(identity.ReservedIdentityInit)

	fooIngressRule1 := &policytypes.PolicyEntry{
		Ingress:     true,
		DefaultDeny: true,
		Verdict:     types.Allow,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooIngressRule1Label,
		},
	}

	fooIngressRule2 := &policytypes.PolicyEntry{
		Ingress:     true,
		DefaultDeny: true,
		Verdict:     types.Allow,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooIngressRule2Label,
		},
	}

	fooEgressRule1 := &policytypes.PolicyEntry{
		Ingress:     false,
		DefaultDeny: true,
		Verdict:     types.Allow,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooEgressRule1Label,
		},
	}

	fooEgressRule2 := &policytypes.PolicyEntry{
		Ingress:     false,
		DefaultDeny: true,
		Verdict:     types.Allow,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooEgressRule2Label,
		},
	}

	combinedRule := policytypes.PolicyEntries{
		&policytypes.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
			L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
			Labels: labels.LabelArray{
				combinedLabel,
			},
		}, &policytypes.PolicyEntry{
			Ingress:     false,
			DefaultDeny: true,
			Verdict:     types.Allow,
			Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
			L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
			Labels: labels.LabelArray{
				combinedLabel,
			},
		},
	}

	ing, egr, _, _, matchingRulesI, matchingRulesE := repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no rules are in repository")
	require.False(t, egr, "egress policy enforcement should not apply since no rules are in repository")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	repo.ReplaceByResource([]*policytypes.PolicyEntry{fooIngressRule1}, fooIngressRule1Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.False(t, egr, "egress policy enforcement should not apply since no egress rules select")
	require.Equal(t, *fooIngressRule1, matchingRulesI[0].PolicyEntry, "returned matching rules did not match")
	require.Len(t, matchingRulesI, 1, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	repo.ReplaceByResource([]*policytypes.PolicyEntry{fooIngressRule2}, fooIngressRule2Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.False(t, egr, "egress policy enforcement should not apply since no egress rules select")
	require.ElementsMatch(t, matchingRulesI.AsPolicyEntries(), policytypes.PolicyEntries{fooIngressRule1, fooIngressRule2})
	require.Len(t, matchingRulesI, 2, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	_, _, numDeleted := repo.ReplaceByResource(nil, fooIngressRule1Resource)
	require.Equal(t, 1, numDeleted)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.False(t, egr, "egress policy enforcement should not apply since no egress rules select")
	require.Equal(t, *fooIngressRule2, matchingRulesI[0].PolicyEntry, "returned matching rules did not match")
	require.Len(t, matchingRulesI, 1, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, fooIngressRule2Resource)
	require.Equal(t, 1, numDeleted)

	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no rules are in repository")
	require.False(t, egr, "egress policy enforcement should not apply since no rules are in repository")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	repo.ReplaceByResource([]*policytypes.PolicyEntry{fooEgressRule1}, fooEgressRule1Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no ingress rules select")
	require.True(t, egr, "egress policy enforcement should apply since egress rules select")
	require.Equal(t, *fooEgressRule1, matchingRulesE[0].PolicyEntry, "returned matching rules did not match")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Len(t, matchingRulesE, 1, "returned matching rules did not match")

	repo.ReplaceByResource(nil, fooEgressRule1Resource)
	require.Equal(t, 1, numDeleted)

	repo.ReplaceByResource([]*policytypes.PolicyEntry{fooEgressRule2}, fooEgressRule2Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no ingress rules select")
	require.True(t, egr, "egress policy enforcement should apply since egress rules select")
	require.Equal(t, *fooEgressRule2, matchingRulesE[0].PolicyEntry, "returned matching rules did not match")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Len(t, matchingRulesE, 1, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, fooEgressRule2Resource)
	require.Equal(t, 1, numDeleted)

	repo.ReplaceByResource(combinedRule, combinedResource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.True(t, egr, "egress policy enforcement should apply since egress rules selects")
	require.ElementsMatch(t, matchingRulesI.AsPolicyEntries(), combinedRule[0:1], "returned matching rules did not match")
	require.ElementsMatch(t, matchingRulesE.AsPolicyEntries(), combinedRule[1:2], "returned matching rules did not match")
	require.Len(t, matchingRulesI, 1, "returned matching rules did not match")
	require.Len(t, matchingRulesE, 1, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, combinedResource)
	require.Equal(t, 2, numDeleted)

	SetPolicyEnabled(option.AlwaysEnforce)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.True(t, egr, "egress policy enforcement should apply since egress rules selects")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	SetPolicyEnabled(option.NeverEnforce)
	_, _ = repo.MustAddPolicyEntries(combinedRule)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since policy enforcement is disabled ")
	require.False(t, egr, "egress policy enforcement should not apply since policy enforcement is disabled")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	// Test init identity.

	SetPolicyEnabled(option.DefaultEnforcement)
	// If the mode is "default", check that the policy is always enforced for
	// endpoints with the reserved:init label. If no policy rules match
	// reserved:init, this drops all ingress and egress traffic.
	ingress, egress, _, _, matchingRulesI, matchingRulesE := repo.computePolicyEnforcementAndRules(initIdentity)
	require.True(t, ingress)
	require.True(t, egress)
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	// Check that the "always" and "never" modes are not affected.
	SetPolicyEnabled(option.AlwaysEnforce)
	ingress, egress, _, _, _, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	require.True(t, ingress)
	require.True(t, egress)

	SetPolicyEnabled(option.NeverEnforce)
	ingress, egress, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(initIdentity)
	require.False(t, ingress)
	require.False(t, egress)
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

}

func TestWildcardL3RulesIngress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsICMP := labels.LabelArray{labels.ParseLabel("icmp")}
	labelsICMPv6 := labels.LabelArray{labels.ParseLabel("icmpv6")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}
	labelsL7 := labels.LabelArray{labels.ParseLabel("l7")}

	l3Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
				},
			},
		},
		Labels: labelsL3,
	}

	kafkaRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}

	httpRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
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
		Labels: labelsHTTP,
	}

	l7Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9090", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						L7Proto: "tester",
						L7:      []api.PortRuleL7{map[string]string{"method": "GET", "path": "/"}},
					},
				}},
			},
		},
		Labels: labelsL7,
	}

	icmpV4Type := intstr.FromInt(8)
	icmpRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type: &icmpV4Type,
					}},
				}},
			},
		},
		Labels: labelsICMP,
	}

	icmpV6Type := intstr.FromInt(128)
	icmpV6Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type:   &icmpV6Type,
						Family: api.IPv6Family,
					}},
				}},
			},
		},
		Labels: labelsICMPv6,
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: nil,
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL3}}),
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: nil,
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsICMP}}),
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: nil,
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsICMPv6}}),
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeKafka,
					ListenerPriority: ListenerPriorityKafka,
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsKafka}}),
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsHTTP}}),
		},
		"9090/TCP": {
			Port:     9090,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         L7ParserType("tester"),
					ListenerPriority: ListenerPriorityNone,
					L7Rules: api.L7Rules{
						L7Proto: "tester",
						L7:      []api.PortRuleL7{l7Rule.Ingress[0].ToPorts[0].Rules.L7[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsL7}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &l3Rule, &kafkaRule, &httpRule, &l7Rule, &icmpRule, &icmpV6Rule)
}

func TestWildcardL4RulesIngress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL4Kafka := labels.LabelArray{labels.ParseLabel("L4-kafka")}
	labelsL7Kafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsL4HTTP := labels.LabelArray{labels.ParseLabel("L4-http")}
	labelsL7HTTP := labels.LabelArray{labels.ParseLabel("http")}

	l49092Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL4Kafka,
	}

	kafkaRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsL7Kafka,
	}

	l480Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL4HTTP,
	}

	httpRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
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
		Labels: labelsL7HTTP,
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: nil,
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorBar1: {labelsL4HTTP},
				td.cachedSelectorBar2: {labelsL7HTTP},
			}),
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: nil,
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeKafka,
					ListenerPriority: ListenerPriorityKafka,
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorBar1: {labelsL4Kafka},
				td.cachedSelectorBar2: {labelsL7Kafka},
			}),
		},
	})

	td.policyMapEquals(t, expected, nil, &l49092Rule, &kafkaRule, &l480Rule, &httpRule)
}

func TestWildcardL3RulesEgress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL4 := labels.LabelArray{labels.ParseLabel("L4")}
	labelsDNS := labels.LabelArray{labels.ParseLabel("dns")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}
	labelsICMP := labels.LabelArray{labels.ParseLabel("icmp")}
	labelsICMPv6 := labels.LabelArray{labels.ParseLabel("icmpv6")}

	l3Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
				},
			},
		},
		Labels: labelsL4,
	}

	dnsRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
					Rules: &api.L7Rules{
						DNS: []api.PortRuleDNS{
							{MatchName: "empire.gov"},
						},
					},
				}},
			},
		},
		Labels: labelsDNS,
	}

	httpRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
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
		Labels: labelsHTTP,
	}

	icmpV4Type := intstr.FromInt(8)
	icmpRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type: &icmpV4Type,
					}},
				}},
			},
		},
		Labels: labelsICMP,
	}

	icmpV6Type := intstr.FromInt(128)
	icmpV6Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type:   &icmpV6Type,
						Family: "IPv6",
					}},
				}},
			},
		},
		Labels: labelsICMPv6,
	}

	// Traffic to bar1 should not be forwarded to the DNS or HTTP
	// proxy at all, but if it is (e.g., for visibility, the
	// "0/ANY" rule should allow such traffic through.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeDNS,
					ListenerPriority: ListenerPriorityDNS,
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{dnsRule.Egress[0].ToPorts[0].Rules.DNS[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsDNS}}),
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsHTTP}}),
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: nil,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsICMP}}),
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: nil,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsICMPv6}}),
		},
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: nil,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL4}}),
		},
	})
	td.policyMapEquals(t, nil, expected, &l3Rule, &dnsRule, &httpRule, &icmpRule, &icmpV6Rule)
}

func TestWildcardL4RulesEgress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL3DNS := labels.LabelArray{labels.ParseLabel("L3-dns")}
	labelsL7DNS := labels.LabelArray{labels.ParseLabel("dns")}
	labelsL3HTTP := labels.LabelArray{labels.ParseLabel("L3-http")}
	labelsL7HTTP := labels.LabelArray{labels.ParseLabel("http")}

	l453Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
				}},
			},
		},
		Labels: labelsL3DNS,
	}

	dnsRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
					Rules: &api.L7Rules{
						DNS: []api.PortRuleDNS{
							{MatchName: "empire.gov"},
						},
					},
				}},
			},
		},
		Labels: labelsL7DNS,
	}

	l480Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL3HTTP,
	}

	httpRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
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
		Labels: labelsL7HTTP,
	}

	// Bar1 should not be forwarded to the proxy, but if it is (e.g., for visibility),
	// the L3/L4 allow should pass it without an explicit L7 wildcard.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: nil,
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorBar1: {labelsL3HTTP},
				td.cachedSelectorBar2: {labelsL7HTTP},
			}),
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: nil,
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeDNS,
					ListenerPriority: ListenerPriorityDNS,
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{dnsRule.Egress[0].ToPorts[0].Rules.DNS[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorBar1: {labelsL3DNS},
				td.cachedSelectorBar2: {labelsL7DNS},
			}),
		},
	})

	td.policyMapEquals(t, nil, expected, &l453Rule, &dnsRule, &l480Rule, &httpRule)
}

func TestWildcardCIDRRulesEgress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	cachedSelectors, _ := td.sc.AddSelectorsTxn(dummySelectorCacheUser, EmptyStringLabels,
		types.ToSelectors(api.CIDR("192.0.0.0/3"))...)
	td.sc.Commit()

	l480Get := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: api.CIDRSlice{"192.0.0.0/3"},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{
							Port:     "80",
							Protocol: api.ProtoTCP,
						},
					},
					Rules: &api.L7Rules{
						HTTP: []api.PortRuleHTTP{
							{
								Headers: []string{"X-My-Header: true"},
								Method:  "GET",
								Path:    "/",
							},
						},
					},
				}},
			},
		},
		Labels: labelsHTTP,
	}

	l3Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: api.CIDRSlice{"192.0.0.0/3"},
				},
			},
		},
		Labels: labelsL3,
	}

	// Port 80 policy does not need the wildcard, as the "0" port policy will allow the traffic.
	// HTTP rules can have side-effects, so they need to be retained even if shadowed by a wildcard.
	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Headers: []string{"X-My-Header: true"},
							Method:  "GET",
							Path:    "/",
						}},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsHTTP}}),
		},
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: nil,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsL3}}),
		},
	})

	td.policyMapEquals(t, nil, expected, &l480Get, &l3Rule)
}

func TestWildcardL3RulesIngressFromEntities(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l3Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: api.EntitySlice{api.EntityWorld},
				},
			},
		},
		Labels: labelsL3,
	}

	kafkaRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []kafka.PortRule{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}

	httpRule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
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
		Labels: labelsHTTP,
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorWorld:   nil,
				td.cachedSelectorWorldV4: nil,
				td.cachedSelectorWorldV6: nil,
			},
			Ingress: true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorWorld:   {labelsL3},
				td.cachedSelectorWorldV4: {labelsL3},
				td.cachedSelectorWorldV6: {labelsL3},
			}),
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeKafka,
					ListenerPriority: ListenerPriorityKafka,
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsKafka}}),
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsHTTP}}),
		},
	})

	td.policyMapEquals(t, expected, nil, &l3Rule, &kafkaRule, &httpRule)
}

func TestWildcardL3RulesEgressToEntities(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsDNS := labels.LabelArray{labels.ParseLabel("dns")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l3Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: api.EntitySlice{api.EntityWorld},
				},
			},
		},
		Labels: labelsL3,
	}
	dnsRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
					Rules: &api.L7Rules{
						DNS: []api.PortRuleDNS{
							{MatchName: "empire.gov"},
						},
					},
				}},
			},
		},
		Labels: labelsDNS,
	}

	httpRule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
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
		Labels: labelsHTTP,
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorWorld:   nil,
				td.cachedSelectorWorldV4: nil,
				td.cachedSelectorWorldV6: nil,
			},
			Ingress: false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorWorld:   {labelsL3},
				td.cachedSelectorWorldV4: {labelsL3},
				td.cachedSelectorWorldV6: {labelsL3},
			}),
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeDNS,
					ListenerPriority: ListenerPriorityDNS,
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{dnsRule.Egress[0].ToPorts[0].Rules.DNS[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsDNS}}),
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar2: &PerSelectorPolicy{
					Verdict:          types.Allow,
					L7Parser:         ParserTypeHTTP,
					ListenerPriority: ListenerPriorityHTTP,
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
					},
				},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar2: {labelsHTTP}}),
		},
	})

	td.policyMapEquals(t, nil, expected, &l3Rule, &dnsRule, &httpRule)
}

func TestMinikubeGettingStarted(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	rule1 := api.Rule{
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
		},
	}

	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
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
		},
	}

	rule3 := api.Rule{
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
		},
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{"TCP/80": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: &PerSelectorPolicy{
				Verdict:          types.Allow,
				L7Parser:         ParserTypeHTTP,
				ListenerPriority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/"}, {}},
				},
			},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule1, &rule2, &rule3)
}

func TestIterate(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))
	repo := td.repo

	numWithEgress := 0
	countEgressRules := func(r *policytypes.PolicyEntry) {
		if !r.Ingress {
			numWithEgress++
		}
	}
	repo.Iterate(countEgressRules)

	require.Equal(t, 0, numWithEgress)

	numRules := 10
	lbls := make([]labels.Label, 10)
	for i := range numRules {
		it := fmt.Sprintf("baz%d", i)
		epSelector := types.NewLabelSelectorFromLabels(
			labels.NewLabel(
				"foo",
				it,
				labels.LabelSourceK8s,
			),
		)
		lbls[i] = labels.NewLabel("tag3", it, labels.LabelSourceK8s)
		_, _, err := repo.mustAddPolicyEntry(policytypes.PolicyEntry{
			Verdict: types.Allow,
			Subject: epSelector,
			Labels:  labels.LabelArray{lbls[i]},
			L3:      types.Selectors{epSelector},
		})
		require.NoError(t, err)
	}

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	require.Equal(t, numRules, numWithEgress)

	numModified := 0
	modifyRules := func(r *policytypes.PolicyEntry) {
		if r.Labels.Contains(labels.LabelArray{lbls[1]}) || r.Labels.Contains(labels.LabelArray{lbls[3]}) {
			r.Ingress = true
			numModified++
		}
	}

	repo.Iterate(modifyRules)

	require.Equal(t, 2, numModified)

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	require.Equal(t, numRules-numModified, numWithEgress)
}

// TestDefaultAllow covers the defaulting logic in determining an identity's default rule
// in the presence or absence of rules that do not enable default-deny mode.
func TestDefaultAllow(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	fooSelectLabel := labels.ParseSelectLabel("foo")

	genRule := func(ingress, defaultDeny bool) *policytypes.PolicyEntry {
		name := fmt.Sprintf("%v_%v", ingress, defaultDeny)
		r := policytypes.PolicyEntry{
			Verdict:     types.Allow,
			Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
			Labels:      labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceAny)},
			Ingress:     ingress,
			L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
			DefaultDeny: defaultDeny,
		}
		return &r
	}

	iDeny := genRule(true, true)   // ingress default deny
	iAllow := genRule(true, false) // ingress default allow

	eDeny := genRule(false, true)   // egress default deny
	eAllow := genRule(false, false) // egress default allow

	type testCase struct {
		rules           policytypes.PolicyEntries
		ingress, egress bool
		ruleC           int // count of rules; indicates wildcard
	}

	ingressCases := []testCase{
		{
			rules: nil, // default case, everything disabled
		},
		{
			rules:   policytypes.PolicyEntries{iDeny},
			ingress: true,
			ruleC:   1,
		},
		{
			rules:   policytypes.PolicyEntries{iAllow}, // Just a default-allow rule
			ingress: true,
			ruleC:   2, // wildcard must be added
		},
		{
			rules:   policytypes.PolicyEntries{iDeny, iAllow}, // default-deny takes precedence, no wildcard
			ingress: true,
			ruleC:   2,
		},
	}

	egressCases := []testCase{
		{
			rules: nil, // default case, everything disabled
		},
		{
			rules:  policytypes.PolicyEntries{eDeny},
			egress: true,
			ruleC:  1,
		},
		{
			rules:  policytypes.PolicyEntries{eAllow}, // Just a default-allow rule
			egress: true,
			ruleC:  2, // wildcard must be added
		},
		{
			rules:  policytypes.PolicyEntries{eDeny, eAllow}, // default-deny takes precedence, no wildcard
			egress: true,
			ruleC:  2,
		},
	}

	// three test runs: ingress, egress, and ingress + egress cartesian
	for i, tc := range ingressCases {
		td := newTestData(t, hivetest.Logger(t))
		td.addIdentity(fooIdentity)
		repo := td.repo

		_, _ = repo.MustAddPolicyEntries(tc.rules)

		ing, egr, _, _, matchingRulesI, matchingRulesE := repo.computePolicyEnforcementAndRules(fooIdentity)
		require.Equal(t, tc.ingress, ing, "case %d: ingress should match", i)
		require.Equal(t, tc.egress, egr, "case %d: egress should match", i)
		require.Equal(t, tc.ruleC, len(matchingRulesI)+len(matchingRulesE), "case %d: rule count should match", i)
	}

	for i, tc := range egressCases {
		td := newTestData(t, hivetest.Logger(t))
		td.addIdentity(fooIdentity)
		repo := td.repo

		_, _ = repo.MustAddPolicyEntries(tc.rules)

		ing, egr, _, _, matchingRulesI, matchingRulesE := repo.computePolicyEnforcementAndRules(fooIdentity)
		require.Equal(t, tc.ingress, ing, "case %d: ingress should match", i)
		require.Equal(t, tc.egress, egr, "case %d: egress should match", i)
		require.Equal(t, tc.ruleC, len(matchingRulesI)+len(matchingRulesE), "case %d: rule count should match", i)
	}

	// test all combinations of ingress + egress cases
	for e, etc := range egressCases {
		for i, itc := range ingressCases {
			td := newTestData(t, hivetest.Logger(t))
			td.addIdentity(fooIdentity)
			repo := td.repo

			_, _ = repo.MustAddPolicyEntries(etc.rules)
			_, _ = repo.MustAddPolicyEntries(itc.rules)

			ing, egr, _, _, matchingRulesI, matchingRulesE := repo.computePolicyEnforcementAndRules(fooIdentity)
			require.Equal(t, itc.ingress, ing, "case ingress %d + egress %d: ingress should match", i, e)
			require.Equal(t, etc.egress, egr, "case ingress %d + egress %d: egress should match", i, e)
			require.Equal(t, itc.ruleC+etc.ruleC, len(matchingRulesI)+len(matchingRulesE), "case ingress %d + egress %d: rule count should match", i, e)
		}
	}
}

func TestReplaceByResource(t *testing.T) {
	// don't use the full testdata() here, since we want to watch
	// selectorcache changes carefully
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, testpolicy.NewPolicyMetricsNoop())
	sc := testNewSelectorCache(t, hivetest.Logger(t), nil)
	repo.selectorCache = sc
	assert.True(t, sc.selectors.Empty())

	// create 10 rules, each with a subject selector that selects one identity.

	numRules := 10
	rules := make(policytypes.PolicyEntries, 0, numRules)
	ids := identity.IdentityMap{}
	// share the dest selector
	destSelector := api.NewESFromLabels(labels.NewLabel("peer", "pod", "k8s"))
	for i := range numRules {
		it := fmt.Sprintf("num-%d", i)
		ids[identity.NumericIdentity(i+100)] = labels.LabelArray{labels.Label{
			Source: labels.LabelSourceK8s,
			Key:    "subject-pod",
			Value:  it,
		}}
		epSelector := types.NewLabelSelectorFromLabels(
			labels.NewLabel(
				"subject-pod",
				it,
				labels.LabelSourceK8s,
			),
		)
		lbl := labels.NewLabel("policy-label", it, labels.LabelSourceK8s)
		rule := &policytypes.PolicyEntry{
			Verdict: types.Allow,
			Subject: epSelector,
			Labels:  labels.LabelArray{lbl},
			L3:      types.ToSelectors(destSelector),
		}
		rules = append(rules, rule)
	}
	sc.UpdateIdentities(ids, nil, &sync.WaitGroup{})

	rulesMatch := func(s ruleSlice, rs policytypes.PolicyEntries) {
		t.Helper()
		ss := make(policytypes.PolicyEntries, 0, len(s))
		for _, rule := range s {
			ss = append(ss, &rule.PolicyEntry)
		}
		assert.ElementsMatch(t, ss, rs)
	}
	toSlice := func(m map[ruleKey]*rule) ruleSlice {
		out := ruleSlice{}
		for _, v := range m {
			out = append(out, v)
		}
		return out
	}

	rID1 := ipcachetypes.ResourceID("res1")
	rID2 := ipcachetypes.ResourceID("res2")

	affectedIDs, rev, oldRuleCnt := repo.ReplaceByResource(rules[0:1], rID1)
	assert.ElementsMatch(t, []identity.NumericIdentity{100}, affectedIDs.AsSlice())
	assert.EqualValues(t, 2, rev)
	assert.Equal(t, 0, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 1)
	assert.Len(t, repo.rulesByResource, 1)
	assert.Len(t, repo.rulesByResource[rID1], 1)
	rulesMatch(toSlice(repo.rulesByResource[rID1]), rules[0:1])

	// Check that the selectorcache is sane
	// It should have one selector: the subject pod for rule 0
	assert.Equal(t, 1, sc.selectors.Len())

	// add second resource with rules 1, 2
	affectedIDs, rev, oldRuleCnt = repo.ReplaceByResource(rules[1:3], rID2)

	assert.ElementsMatch(t, []identity.NumericIdentity{101, 102}, affectedIDs.AsSlice())
	assert.EqualValues(t, 3, rev)
	assert.Equal(t, 0, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 3)
	assert.Len(t, repo.rulesByResource, 2)
	assert.Len(t, repo.rulesByResource[rID1], 1)
	assert.Len(t, repo.rulesByResource[rID2], 2)
	assert.Equal(t, 3, sc.selectors.Len())

	// replace rid1 with rules 3, 4.
	// affected IDs should be 100, 103, 104 (for outgoing)
	affectedIDs, rev, oldRuleCnt = repo.ReplaceByResource(rules[3:5], rID1)

	assert.ElementsMatch(t, []identity.NumericIdentity{100, 103, 104}, affectedIDs.AsSlice())
	assert.EqualValues(t, 4, rev)
	assert.Equal(t, 1, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 4)
	assert.Len(t, repo.rulesByResource, 2)
	assert.Len(t, repo.rulesByResource[rID1], 2)
	assert.Len(t, repo.rulesByResource[rID2], 2)
	assert.Equal(t, 4, sc.selectors.Len())

	rulesMatch(toSlice(repo.rulesByResource[rID1]), rules[3:5])

	assert.Equal(t, repo.rules[ruleKey{
		resource: rID1,
		idx:      0,
	}].PolicyEntry, *rules[3])

	// delete rid1
	affectedIDs, _, oldRuleCnt = repo.ReplaceByResource(nil, rID1)
	assert.Len(t, repo.rules, 2)
	assert.Len(t, repo.rulesByResource, 1)
	assert.Len(t, repo.rulesByResource[rID2], 2)
	assert.Equal(t, 2, sc.selectors.Len())
	assert.Equal(t, 2, oldRuleCnt)

	assert.ElementsMatch(t, []identity.NumericIdentity{103, 104}, affectedIDs.AsSlice())

	// delete rid1 again (noop)
	affectedIDs, _, oldRuleCnt = repo.ReplaceByResource(nil, rID1)
	assert.Empty(t, affectedIDs.AsSlice())

	assert.Len(t, repo.rules, 2)
	assert.Len(t, repo.rulesByResource, 1)
	assert.Len(t, repo.rulesByResource[rID2], 2)
	assert.Equal(t, 2, sc.selectors.Len())
	assert.Equal(t, 0, oldRuleCnt)

	// delete rid2
	affectedIDs, _, oldRuleCnt = repo.ReplaceByResource(nil, rID2)

	assert.ElementsMatch(t, []identity.NumericIdentity{101, 102}, affectedIDs.AsSlice())
	assert.Empty(t, repo.rules)
	assert.Empty(t, repo.rulesByResource)
	assert.True(t, sc.selectors.Empty())
	assert.Equal(t, 2, oldRuleCnt)
}
