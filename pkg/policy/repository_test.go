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
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

// mustAdd inserts a rule into the policy repository
// This is just a helper function for unit testing.
// Only returns error for signature reasons
func (p *Repository) mustAdd(r api.Rule) (uint64, map[uint16]struct{}, error) {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if err := r.Sanitize(); err != nil {
		panic(err)
	}

	newList := make([]*api.Rule, 1)
	newList[0] = &r
	_, rev := p.addListLocked(newList)
	return rev, map[uint16]struct{}{}, nil
}

func TestComputePolicyEnforcementAndRules(t *testing.T) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	td := newTestData(hivetest.Logger(t))
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
	initIdentity := identity.LookupReservedIdentity(identity.ReservedIdentityInit)

	// lal takes a single label and returns a []labels.LabelArray containing only that label
	lal := func(lbl labels.Label) []labels.LabelArray {
		return []labels.LabelArray{{lbl}}
	}

	fooIngressRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooIngressRule1Label,
		},
	}
	fooIngressRule1.Sanitize()

	fooIngressRule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooIngressRule2Label,
		},
	}
	fooIngressRule2.Sanitize()

	fooEgressRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooEgressRule1Label,
		},
	}
	fooEgressRule1.Sanitize()

	fooEgressRule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooEgressRule2Label,
		},
	}
	fooEgressRule2.Sanitize()

	combinedRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			combinedLabel,
		},
	}
	combinedRule.Sanitize()

	ing, egr, _, _, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no rules are in repository")
	require.False(t, egr, "egress policy enforcement should not apply since no rules are in repository")
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err := repo.mustAdd(fooIngressRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.False(t, egr, "egress policy enforcement should not apply since no egress rules select")
	require.Equal(t, fooIngressRule1, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, err = repo.mustAdd(fooIngressRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.False(t, egr, "egress policy enforcement should not apply since no egress rules select")
	require.ElementsMatch(t, matchingRules.AsPolicyRules(), api.Rules{&fooIngressRule1, &fooIngressRule2})

	_, _, numDeleted := repo.ReplaceByLabels(nil, lal(fooIngressRule1Label))
	require.Equal(t, 1, numDeleted)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.False(t, egr, "egress policy enforcement should not apply since no egress rules select")
	require.Equal(t, fooIngressRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(fooIngressRule2Label))
	require.Equal(t, 1, numDeleted)

	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no rules are in repository")
	require.False(t, egr, "egress policy enforcement should not apply since no rules are in repository")
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err = repo.mustAdd(fooEgressRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no ingress rules select")
	require.True(t, egr, "egress policy enforcement should apply since egress rules select")
	require.Equal(t, fooEgressRule1, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(fooEgressRule1Label))
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.mustAdd(fooEgressRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since no ingress rules select")
	require.True(t, egr, "egress policy enforcement should apply since egress rules select")
	require.Equal(t, fooEgressRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(fooEgressRule2Label))
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.mustAdd(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.True(t, egr, "egress policy enforcement should apply since egress rules selects")
	require.Equal(t, combinedRule, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(combinedLabel))
	require.Equal(t, 1, numDeleted)

	SetPolicyEnabled(option.AlwaysEnforce)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.True(t, egr, "egress policy enforcement should apply since egress rules selects")
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	SetPolicyEnabled(option.NeverEnforce)
	_, _, err = repo.mustAdd(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, "ingress policy enforcement should not apply since policy enforcement is disabled ")
	require.False(t, egr, "egress policy enforcement should not apply since policy enforcement is disabled")
	require.Nil(t, matchingRules, "no rules should be returned since policy enforcement is disabled")

	// Test init identity.

	SetPolicyEnabled(option.DefaultEnforcement)
	// If the mode is "default", check that the policy is always enforced for
	// endpoints with the reserved:init label. If no policy rules match
	// reserved:init, this drops all ingress and egress traffic.
	ingress, egress, _, _, matchingRules := repo.computePolicyEnforcementAndRules(initIdentity)
	require.True(t, ingress)
	require.True(t, egress)
	require.Equal(t, ruleSlice{}, matchingRules, "no rules should be returned since policy enforcement is disabled")

	// Check that the "always" and "never" modes are not affected.
	SetPolicyEnabled(option.AlwaysEnforce)
	ingress, egress, _, _, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	require.True(t, ingress)
	require.True(t, egress)

	SetPolicyEnabled(option.NeverEnforce)
	ingress, egress, _, _, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	require.False(t, ingress)
	require.False(t, egress)
}

func BenchmarkParseLabel(b *testing.B) {
	td := newTestData(hivetest.Logger(b))
	repo := td.repo

	var err error
	var cntAdd, cntFound int

	lbls := make([]labels.LabelArray, 100)
	for i := range 100 {
		I := fmt.Sprintf("%d", i)
		lbls[i] = labels.LabelArray{labels.NewLabel("tag3", I, labels.LabelSourceK8s), labels.NewLabel("namespace", "default", labels.LabelSourceK8s)}
	}
	for b.Loop() {
		for j := range 100 {
			J := fmt.Sprintf("%d", j)
			_, _, err = repo.mustAdd(api.Rule{
				EndpointSelector: api.NewESFromLabels(labels.NewLabel("foo", J, labels.LabelSourceK8s), labels.NewLabel("namespace", "default", labels.LabelSourceK8s)),
				Labels: labels.LabelArray{
					labels.ParseLabel("k8s:tag1"),
					labels.NewLabel("namespace", "default", labels.LabelSourceK8s),
					labels.NewLabel("tag3", J, labels.LabelSourceK8s),
				},
			})
			if err == nil {
				cntAdd++
			}
		}

		repo.mutex.RLock()
		for j := range 100 {
			cntFound += len(repo.searchRLocked(lbls[j]))
		}
		repo.mutex.RUnlock()
	}
	b.Log("Added: ", cntAdd)
	b.Log("found: ", cntFound)
}

func TestWildcardL3RulesIngress(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

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
					L7Parser: ParserTypeKafka,
					Priority: ListenerPriorityKafka,
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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
					L7Parser: L7ParserType("tester"),
					Priority: ListenerPriorityProxylib,
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
	td := newTestData(hivetest.Logger(t))

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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
					L7Parser: ParserTypeKafka,
					Priority: ListenerPriorityKafka,
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

func TestL3DependentL4IngressFromRequires(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	l480Rule := api.Rule{
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						selBar1,
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromRequires: []api.EndpointSelector{selBar2},
				},
			},
		},
	}

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, expectedSelector)

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: nil,
			},
			Ingress: true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				expectedCachedSelector: {nil},
			}),
		},
	})

	td.policyMapEquals(t, expected, nil, &l480Rule)
}

func TestL3DependentL4EgressFromRequires(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	l480Rule := api.Rule{
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						selBar1,
					},
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.WildcardEndpointSelector,
					},
					ToRequires: []api.EndpointSelector{selBar2},
				},
			},
		},
	}

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedSelector2 := api.NewESFromMatchRequirements(map[string]string{}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, expectedSelector)
	expectedCachedSelector2, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, expectedSelector2)

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector2: nil,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				expectedCachedSelector2: {nil},
			}),
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: nil,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				expectedCachedSelector: {nil},
			}),
		},
	})

	td.policyMapEquals(t, nil, expected, &l480Rule)
}

func TestWildcardL3RulesEgress(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

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
					L7Parser: ParserTypeDNS,
					Priority: ListenerPriorityDNS,
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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
	td := newTestData(hivetest.Logger(t))

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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
					L7Parser: ParserTypeDNS,
					Priority: ListenerPriorityDNS,
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
	td := newTestData(hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	cidrSlice := api.CIDRSlice{"192.0.0.0/3"}
	cidrSelectors := cidrSlice.GetAsEndpointSelectors()
	var cachedSelectors CachedSelectorSlice
	for i := range cidrSelectors {
		c, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, cidrSelectors[i])
		cachedSelectors = append(cachedSelectors, c)
		defer td.sc.RemoveSelector(c, dummySelectorCacheUser)
	}

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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
	td := newTestData(hivetest.Logger(t))

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
					L7Parser: ParserTypeKafka,
					Priority: ListenerPriorityKafka,
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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
	td := newTestData(hivetest.Logger(t))

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
					L7Parser: ParserTypeDNS,
					Priority: ListenerPriorityDNS,
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
					L7Parser: ParserTypeHTTP,
					Priority: ListenerPriorityHTTP,
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
	td := newTestData(hivetest.Logger(t))

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
				L7Parser: ParserTypeHTTP,
				Priority: ListenerPriorityHTTP,
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}, {Method: "GET", Path: "/"}},
				},
			},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {nil}}),
	}})

	td.policyMapEquals(t, expected, nil, &rule1, &rule2, &rule3)
}

func TestIterate(t *testing.T) {
	td := newTestData(hivetest.Logger(t))
	repo := td.repo

	numWithEgress := 0
	countEgressRules := func(r *api.Rule) {
		if len(r.Egress) > 0 {
			numWithEgress++
		}
	}
	repo.Iterate(countEgressRules)

	require.Equal(t, 0, numWithEgress)

	numRules := 10
	lbls := make([]labels.Label, 10)
	for i := range numRules {
		it := fmt.Sprintf("baz%d", i)
		epSelector := api.NewESFromLabels(
			labels.NewLabel(
				"foo",
				it,
				labels.LabelSourceK8s,
			),
		)
		lbls[i] = labels.NewLabel("tag3", it, labels.LabelSourceK8s)
		_, _, err := repo.mustAdd(api.Rule{
			EndpointSelector: epSelector,
			Labels:           labels.LabelArray{lbls[i]},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{
							epSelector,
						},
					},
				},
			},
		})
		require.NoError(t, err)
	}

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	require.Equal(t, numRules, numWithEgress)

	numModified := 0
	modifyRules := func(r *api.Rule) {
		if r.Labels.Contains(labels.LabelArray{lbls[1]}) || r.Labels.Contains(labels.LabelArray{lbls[3]}) {
			r.Egress = nil
			numModified++
		}
	}

	repo.Iterate(modifyRules)

	require.Equal(t, 2, numModified)

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	require.Equal(t, numRules-numModified, numWithEgress)

	_, _, numDeleted := repo.ReplaceByLabels(nil, []labels.LabelArray{{lbls[0]}})
	require.Equal(t, 1, numDeleted)

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	require.Equal(t, numRules-numModified-numDeleted, numWithEgress)
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

	genRule := func(ingress, defaultDeny bool) api.Rule {
		name := fmt.Sprintf("%v_%v", ingress, defaultDeny)
		r := api.Rule{
			EndpointSelector: api.NewESFromLabels(fooSelectLabel),
			Labels:           labels.LabelArray{labels.NewLabel(k8sConst.PolicyLabelName, name, labels.LabelSourceAny)},
		}

		if ingress {
			r.Ingress = []api.IngressRule{{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{api.NewESFromLabels(fooSelectLabel)}}}}
		} else {
			r.Egress = []api.EgressRule{{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{api.NewESFromLabels(fooSelectLabel)}}}}
		}
		if ingress {
			r.EnableDefaultDeny.Ingress = &defaultDeny
		} else {
			r.EnableDefaultDeny.Egress = &defaultDeny
		}
		require.NoError(t, r.Sanitize())
		return r
	}

	iDeny := genRule(true, true)   // ingress default deny
	iAllow := genRule(true, false) // ingress default allow

	eDeny := genRule(false, true)   // egress default deny
	eAllow := genRule(false, false) // egress default allow

	type testCase struct {
		rules           []api.Rule
		ingress, egress bool
		ruleC           int // count of rules; indicates wildcard
	}

	ingressCases := []testCase{
		{
			rules: nil, // default case, everything disabled
		},
		{
			rules:   []api.Rule{iDeny},
			ingress: true,
			ruleC:   1,
		},
		{
			rules:   []api.Rule{iAllow}, // Just a default-allow rule
			ingress: true,
			ruleC:   2, // wildcard must be added
		},
		{
			rules:   []api.Rule{iDeny, iAllow}, // default-deny takes precedence, no wildcard
			ingress: true,
			ruleC:   2,
		},
	}

	egressCases := []testCase{
		{
			rules: nil, // default case, everything disabled
		},
		{
			rules:  []api.Rule{eDeny},
			egress: true,
			ruleC:  1,
		},
		{
			rules:  []api.Rule{eAllow}, // Just a default-allow rule
			egress: true,
			ruleC:  2, // wildcard must be added
		},
		{
			rules:  []api.Rule{eDeny, eAllow}, // default-deny takes precedence, no wildcard
			egress: true,
			ruleC:  2,
		},
	}

	// three test runs: ingress, egress, and ingress + egress cartesian
	for i, tc := range ingressCases {
		td := newTestData(hivetest.Logger(t))
		td.addIdentity(fooIdentity)
		repo := td.repo

		for _, rule := range tc.rules {
			_, _, err := repo.mustAdd(rule)
			require.NoError(t, err, "unable to add rule to policy repository")
		}

		ing, egr, _, _, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
		require.Equal(t, tc.ingress, ing, "case %d: ingress should match", i)
		require.Equal(t, tc.egress, egr, "case %d: egress should match", i)
		require.Len(t, matchingRules, tc.ruleC, "case %d: rule count should match", i)
	}

	for i, tc := range egressCases {
		td := newTestData(hivetest.Logger(t))
		td.addIdentity(fooIdentity)
		repo := td.repo

		for _, rule := range tc.rules {
			_, _, err := repo.mustAdd(rule)
			require.NoError(t, err, "unable to add rule to policy repository")
		}

		ing, egr, _, _, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
		require.Equal(t, tc.ingress, ing, "case %d: ingress should match", i)
		require.Equal(t, tc.egress, egr, "case %d: egress should match", i)
		require.Len(t, matchingRules, tc.ruleC, "case %d: rule count should match", i)
	}

	// test all combinations of ingress + egress cases
	for e, etc := range egressCases {
		for i, itc := range ingressCases {
			td := newTestData(hivetest.Logger(t))
			td.addIdentity(fooIdentity)
			repo := td.repo

			for _, rule := range etc.rules {
				_, _, err := repo.mustAdd(rule)
				require.NoError(t, err, "unable to add rule to policy repository")
			}

			for _, rule := range itc.rules {
				_, _, err := repo.mustAdd(rule)
				require.NoError(t, err, "unable to add rule to policy repository")
			}

			ing, egr, _, _, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
			require.Equal(t, itc.ingress, ing, "case ingress %d + egress %d: ingress should match", i, e)
			require.Equal(t, etc.egress, egr, "case ingress %d + egress %d: egress should match", i, e)
			require.Len(t, matchingRules, itc.ruleC+etc.ruleC, "case ingress %d + egress %d: rule count should match", i, e)
		}
	}
}

func TestReplaceByResource(t *testing.T) {
	// don't use the full testdata() here, since we want to watch
	// selectorcache changes carefully
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	sc := testNewSelectorCache(hivetest.Logger(t), nil)
	repo.selectorCache = sc
	assert.Empty(t, sc.selectors)

	// create 10 rules, each with a subject selector that selects one identity.

	numRules := 10
	rules := make(api.Rules, 0, numRules)
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
		epSelector := api.NewESFromLabels(
			labels.NewLabel(
				"subject-pod",
				it,
				labels.LabelSourceK8s,
			),
		)
		lbl := labels.NewLabel("policy-label", it, labels.LabelSourceK8s)
		rule := &api.Rule{
			EndpointSelector: epSelector,
			Labels:           labels.LabelArray{lbl},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{
							destSelector,
						},
					},
				},
			},
		}
		require.NoError(t, rule.Sanitize())
		rules = append(rules, rule)
	}
	sc.UpdateIdentities(ids, nil, &sync.WaitGroup{})

	rulesMatch := func(s ruleSlice, rs api.Rules) {
		t.Helper()
		ss := make(api.Rules, 0, len(s))
		for _, rule := range s {
			ss = append(ss, &rule.Rule)
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
	assert.Len(t, sc.selectors, 1)

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
	assert.Len(t, sc.selectors, 3)

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
	assert.Len(t, sc.selectors, 4)

	rulesMatch(toSlice(repo.rulesByResource[rID1]), rules[3:5])

	assert.Equal(t, repo.rules[ruleKey{
		resource: rID1,
		idx:      0,
	}].Rule, *rules[3])

	// delete rid1
	affectedIDs, _, oldRuleCnt = repo.ReplaceByResource(nil, rID1)
	assert.Len(t, repo.rules, 2)
	assert.Len(t, repo.rulesByResource, 1)
	assert.Len(t, repo.rulesByResource[rID2], 2)
	assert.Len(t, sc.selectors, 2)
	assert.Equal(t, 2, oldRuleCnt)

	assert.ElementsMatch(t, []identity.NumericIdentity{103, 104}, affectedIDs.AsSlice())

	// delete rid1 again (noop)
	affectedIDs, _, oldRuleCnt = repo.ReplaceByResource(nil, rID1)
	assert.Empty(t, affectedIDs.AsSlice())

	assert.Len(t, repo.rules, 2)
	assert.Len(t, repo.rulesByResource, 1)
	assert.Len(t, repo.rulesByResource[rID2], 2)
	assert.Len(t, sc.selectors, 2)
	assert.Equal(t, 0, oldRuleCnt)

	// delete rid2
	affectedIDs, _, oldRuleCnt = repo.ReplaceByResource(nil, rID2)

	assert.ElementsMatch(t, []identity.NumericIdentity{101, 102}, affectedIDs.AsSlice())
	assert.Empty(t, repo.rules)
	assert.Empty(t, repo.rulesByResource)
	assert.Empty(t, sc.selectors)
	assert.Equal(t, 2, oldRuleCnt)
}

func TestReplaceByLabels(t *testing.T) {
	// don't use the full testdata() here, since we want to watch
	// selectorcache changes carefully
	repo := NewPolicyRepository(hivetest.Logger(t), nil, nil, nil, nil, api.NewPolicyMetricsNoop())
	sc := testNewSelectorCache(hivetest.Logger(t), nil)
	repo.selectorCache = sc
	assert.Empty(t, sc.selectors)

	// create 10 rules, each with a subject selector that selects one identity.

	numRules := 10
	rules := make(api.Rules, 0, numRules)
	ids := identity.IdentityMap{}
	ruleLabels := make([]labels.LabelArray, 0, numRules)
	// share the dest selector
	destSelector := api.NewESFromLabels(labels.NewLabel("peer", "pod", "k8s"))
	for i := range numRules {
		it := fmt.Sprintf("num-%d", i)
		ids[identity.NumericIdentity(i+100)] = labels.LabelArray{labels.Label{
			Source: labels.LabelSourceK8s,
			Key:    "subject-pod",
			Value:  it,
		}}
		epSelector := api.NewESFromLabels(
			labels.NewLabel(
				"subject-pod",
				it,
				labels.LabelSourceK8s,
			),
		)
		lbl := labels.NewLabel("policy-label", it, labels.LabelSourceK8s)
		rule := &api.Rule{
			EndpointSelector: epSelector,
			Labels:           labels.LabelArray{lbl},
			Egress: []api.EgressRule{
				{
					EgressCommonRule: api.EgressCommonRule{
						ToEndpoints: []api.EndpointSelector{
							destSelector,
						},
					},
				},
			},
		}
		require.NoError(t, rule.Sanitize())
		rules = append(rules, rule)
		ruleLabels = append(ruleLabels, rule.Labels)
	}
	sc.UpdateIdentities(ids, nil, &sync.WaitGroup{})

	rulesMatch := func(s ruleSlice, rs api.Rules) {
		t.Helper()
		ss := make(api.Rules, 0, len(s))
		for _, rule := range s {
			ss = append(ss, &rule.Rule)
		}
		assert.ElementsMatch(t, ss, rs)
	}
	_ = rulesMatch
	toSlice := func(m map[ruleKey]*rule) ruleSlice {
		out := ruleSlice{}
		for _, v := range m {
			out = append(out, v)
		}
		return out
	}
	_ = toSlice

	affectedIDs, rev, oldRuleCnt := repo.ReplaceByLabels(rules[0:1], ruleLabels[0:1])
	assert.ElementsMatch(t, []identity.NumericIdentity{100}, affectedIDs.AsSlice())
	assert.EqualValues(t, 2, rev)
	assert.Equal(t, 0, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 1)
	assert.Len(t, sc.selectors, 1)

	// Replace rule 0 with rule 1
	affectedIDs, rev, oldRuleCnt = repo.ReplaceByLabels(rules[1:2], ruleLabels[0:1])
	assert.ElementsMatch(t, []identity.NumericIdentity{100, 101}, affectedIDs.AsSlice())
	assert.EqualValues(t, 3, rev)
	assert.Equal(t, 1, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 1)
	assert.Len(t, sc.selectors, 1)

	// Add rules 2, 3
	affectedIDs, rev, oldRuleCnt = repo.ReplaceByLabels(rules[2:4], ruleLabels[2:4])
	assert.ElementsMatch(t, []identity.NumericIdentity{102, 103}, affectedIDs.AsSlice())
	assert.EqualValues(t, 4, rev)
	assert.Equal(t, 0, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 3)
	assert.Len(t, sc.selectors, 3)

	// Delete rules 2, 3
	affectedIDs, rev, oldRuleCnt = repo.ReplaceByLabels(nil, ruleLabels[2:4])
	assert.ElementsMatch(t, []identity.NumericIdentity{102, 103}, affectedIDs.AsSlice())
	assert.EqualValues(t, 5, rev)
	assert.Equal(t, 2, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 1)
	assert.Len(t, sc.selectors, 1)

	// delete rules 2, 3 again
	affectedIDs, _, oldRuleCnt = repo.ReplaceByLabels(nil, ruleLabels[2:4])
	assert.ElementsMatch(t, []identity.NumericIdentity{}, affectedIDs.AsSlice())
	assert.Equal(t, 0, oldRuleCnt)

	// check basic bookkeeping
	assert.Len(t, repo.rules, 1)
	assert.Len(t, sc.selectors, 1)

}
