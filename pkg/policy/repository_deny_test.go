// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"fmt"
	"testing"

	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestComputePolicyDenyEnforcementAndRules(t *testing.T) {
	td := newTestData(hivetest.Logger(t))
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	repo := td.repo

	fooSelectLabel := labels.ParseSelectLabel("foo")
	fooNumericIdentity := 9001
	fooIdentity := identity.NewIdentity(identity.NumericIdentity(fooNumericIdentity), lbls)
	fooIngressDenyRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule1", labels.LabelSourceAny)
	fooIngressDenyRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule2", labels.LabelSourceAny)
	fooEgressDenyRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule1", labels.LabelSourceAny)
	fooEgressDenyRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule2", labels.LabelSourceAny)
	combinedLabel := labels.NewLabel(k8sConst.PolicyLabelName, "combined", labels.LabelSourceAny)
	initIdentity := identity.LookupReservedIdentity(identity.ReservedIdentityInit)
	td.addIdentity(fooIdentity)

	// lal takes a single label and returns a []labels.LabelArray containing only that label
	lal := func(lbl labels.Label) []labels.LabelArray {
		return []labels.LabelArray{{lbl}}
	}

	fooIngressDenyRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooIngressDenyRule1Label,
		},
	}
	fooIngressDenyRule1.Sanitize()

	fooIngressDenyRule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooIngressDenyRule2Label,
		},
	}
	fooIngressDenyRule2.Sanitize()

	fooEgressDenyRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooEgressDenyRule1Label,
		},
	}
	fooEgressDenyRule1.Sanitize()

	fooEgressDenyRule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		Labels: labels.LabelArray{
			fooEgressDenyRule2Label,
		},
	}
	fooEgressDenyRule2.Sanitize()

	combinedRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(fooSelectLabel),
					},
				},
			},
		},
		EgressDeny: []api.EgressDenyRule{
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

	genCommentf := func(ingress, accept bool) string {
		direction := "egress"
		if ingress {
			direction = "ingress"
		}
		acceptStr := ""
		acceptStr2 := ""
		if !accept {
			acceptStr = " not"
			acceptStr2 = " no"
		}
		return fmt.Sprintf(
			"%s policy enforcement should%s be applied since%s %s rule selects it in the repository",
			direction, acceptStr, acceptStr2, direction)
	}

	ing, egr, _, _, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err := repo.mustAdd(fooIngressDenyRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.Equal(t, fooIngressDenyRule1, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, err = repo.mustAdd(fooIngressDenyRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.ElementsMatch(t, matchingRules.AsPolicyRules(), api.Rules{&fooIngressDenyRule1, &fooIngressDenyRule2}, "returned matching rules did not match")

	_, _, numDeleted := repo.ReplaceByLabels(nil, lal(fooIngressDenyRule1Label))
	require.Equal(t, 1, numDeleted)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.Equal(t, fooIngressDenyRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(fooIngressDenyRule2Label))
	require.Equal(t, 1, numDeleted)
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err = repo.mustAdd(fooEgressDenyRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.True(t, egr, genCommentf(false, true))
	require.Equal(t, fooEgressDenyRule1, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(fooEgressDenyRule1Label))
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.mustAdd(fooEgressDenyRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.True(t, egr, genCommentf(false, true))
	require.Equal(t, fooEgressDenyRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(fooEgressDenyRule2Label))
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.mustAdd(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.True(t, egr, genCommentf(false, true))
	require.Equal(t, combinedRule, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.ReplaceByLabels(nil, lal(combinedLabel))
	require.Equal(t, 1, numDeleted)

	SetPolicyEnabled(option.AlwaysEnforce)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.True(t, egr, genCommentf(false, true))
	require.Equal(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	SetPolicyEnabled(option.NeverEnforce)
	_, _, err = repo.mustAdd(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
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

func TestDeniesIngress(t *testing.T) {
	td := newTestData(hivetest.Logger(t)).withIDs(ruleTestIDs)
	repo := td.repo
	allowAll := api.Rule{
		EndpointSelector: endpointSelectorB,
		Ingress: []api.IngressRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEntities: []api.Entity{api.EntityAll},
			},
		}},
	}
	repo.mustAdd(allowAll)

	denyAtoB := api.Rule{
		EndpointSelector: endpointSelectorB,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						endpointSelectorA,
					},
				},
			},
		},
	}
	repo.mustAdd(denyAtoB)

	flowCtoB := flowAToB
	flowCtoB.From = idC

	checkFlow(t, repo, flowAToB, api.Denied)
	checkFlow(t, repo, flowCtoB, api.Allowed)
}

func TestDeniesEgress(t *testing.T) {
	td := newTestData(hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
	repo := td.repo

	allowAll := api.Rule{
		EndpointSelector: endpointSelectorA,
		Egress: []api.EgressRule{{
			EgressCommonRule: api.EgressCommonRule{
				ToEntities: []api.Entity{api.EntityAll},
			},
		}},
	}
	repo.mustAdd(allowAll)

	rule1 := api.Rule{
		EndpointSelector: endpointSelectorA,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						endpointSelectorB,
					},
				},
			},
		},
	}
	repo.mustAdd(rule1)

	checkFlow(t, repo, flowAToB, api.Denied)
	checkFlow(t, repo, flowAToC, api.Allowed)
	checkFlow(t, repo, flowAToWorld80, api.Allowed)
}

func TestWildcardL3RulesIngressDeny(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	l3Rule := api.Rule{
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
				},
			},
		},
		Labels: labelsL3,
	}

	expected := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL3}}),
		},
	})
	td.policyMapEquals(t, expected, nil, &l3Rule)
}

func TestWildcardL4RulesIngressDeny(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	labelsL4Kafka := labels.LabelArray{labels.ParseLabel("L4-kafka")}
	labelsL4HTTP := labels.LabelArray{labels.ParseLabel("L4-http")}

	l49092Rule := api.Rule{
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL4Kafka,
	}

	l480Rule := api.Rule{
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL4HTTP,
	}

	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL4HTTP}}),
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL4Kafka}}),
		},
	})
	td.policyMapEquals(t, expectedDenyPolicy, nil, &l49092Rule, &l480Rule)
}

func TestL3DependentL4IngressDenyFromRequires(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	l480Rule := api.Rule{
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						endpointSelectorA,
					},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				IngressCommonRule: api.IngressCommonRule{
					FromRequires: []api.EndpointSelector{endpointSelectorC},
				},
			},
		},
	}

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "a"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"t"},
		},
	})
	expectedCachedSelector, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, EmptyStringLabels, expectedSelector)

	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{expectedCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, expectedDenyPolicy, nil, &l480Rule)
}

func TestL3DependentL4EgressDenyFromRequires(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	l480Rule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						endpointSelectorA,
					},
				},
				ToPorts: []api.PortDenyRule{{
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
					ToRequires: []api.EndpointSelector{endpointSelectorC},
				},
			},
		},
	}

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "a"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"t"},
		},
	})
	expectedSelector2 := api.NewESFromMatchRequirements(map[string]string{}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"t"},
		},
	})
	expectedCachedSelector, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, makeStringLabels(nil), expectedSelector)
	expectedCachedSelector2, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, makeStringLabels(nil), expectedSelector2)

	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector2: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{expectedCachedSelector2: {nil}}),
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{expectedCachedSelector: {nil}}),
		},
	})

	td.policyMapEquals(t, nil, expectedDenyPolicy, &l480Rule)
}

func TestWildcardL3RulesEgressDeny(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	labelsL4 := labels.LabelArray{labels.ParseLabel("L4")}
	labelsICMP := labels.LabelArray{labels.ParseLabel("icmp")}
	labelsICMPv6 := labels.LabelArray{labels.ParseLabel("icmpv6")}

	l3Rule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
			},
		},
		Labels: labelsL4,
	}

	icmpV4Type := intstr.FromInt(8)
	icmpRule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
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
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Family: api.IPv6Family,
						Type:   &icmpV6Type,
					}},
				}},
			},
		},
		Labels: labelsICMPv6,
	}

	// Traffic to bar1 should not be forwarded to the DNS or HTTP
	// proxy at all, but if it is (e.g., for visibility, the
	// "0/ANY" rule should allow such traffic through.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL4}}),
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsICMP}}),
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsICMPv6}}),
		},
	})
	td.policyMapEquals(t, nil, expectedDenyPolicy, &l3Rule, &icmpRule, &icmpV6Rule)
}

func TestWildcardL4RulesEgressDeny(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	labelsL3DNS := labels.LabelArray{labels.ParseLabel("L3-dns")}
	labelsL3HTTP := labels.LabelArray{labels.ParseLabel("L3-http")}

	l453Rule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "53", Protocol: api.ProtoUDP},
					},
				}},
			},
		},
		Labels: labelsL3DNS,
	}

	l480Rule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{endpointSelectorB},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL3HTTP,
	}

	// Bar1 should not be forwarded to the proxy, but if it is (e.g., for visibility),
	// the L3/L4 deny should pass it without an explicit L7 wildcard.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL3HTTP}}),
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL3DNS}}),
		},
	})

	td.policyMapEquals(t, nil, expectedDenyPolicy, &l453Rule, &l480Rule)
}

func TestWildcardCIDRRulesEgressDeny(t *testing.T) {
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
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: api.CIDRSlice{"192.0.0.0/3"},
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{
							Port:     "80",
							Protocol: api.ProtoTCP,
						},
					},
				}},
			},
		},
		Labels: labelsHTTP,
	}

	l3Rule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: api.CIDRSlice{"192.0.0.0/3"},
				},
			},
		},
		Labels: labelsL3,
	}

	// Port 80 policy does not need the wildcard, as the "0" port policy will deny the traffic.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsHTTP}}),
		},
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsL3}}),
		},
	})
	td.policyMapEquals(t, nil, expectedDenyPolicy, &l480Get, &l3Rule)
}

func TestWildcardL3RulesIngressDenyFromEntities(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}

	l3Rule := api.Rule{
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: api.EntitySlice{api.EntityWorld},
				},
			},
		},
		Labels: labelsL3,
	}

	expectedPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorWorld:   &PerSelectorPolicy{IsDeny: true},
				td.cachedSelectorWorldV4: &PerSelectorPolicy{IsDeny: true},
				td.cachedSelectorWorldV6: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress: true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorWorld:   {labelsL3},
				td.cachedSelectorWorldV4: {labelsL3},
				td.cachedSelectorWorldV6: {labelsL3},
			}),
		},
	})

	td.policyMapEquals(t, expectedPolicy, nil, &l3Rule)
}

func TestWildcardL3RulesEgressDenyToEntities(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}

	l3Rule := api.Rule{
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: api.EntitySlice{api.EntityWorld},
				},
			},
		},
		Labels: labelsL3,
	}

	// We should expect an empty deny policy because the policy does not
	// contain any rules with the label 'id=foo'.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorWorld:   &PerSelectorPolicy{IsDeny: true},
				td.cachedSelectorWorldV4: &PerSelectorPolicy{IsDeny: true},
				td.cachedSelectorWorldV6: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress: false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{
				td.cachedSelectorWorld:   {labelsL3},
				td.cachedSelectorWorldV4: {labelsL3},
				td.cachedSelectorWorldV6: {labelsL3},
			}),
		},
	})

	td.policyMapEquals(t, nil, expectedDenyPolicy, &l3Rule)
}

func TestMinikubeGettingStartedDeny(t *testing.T) {
	td := newTestData(hivetest.Logger(t))

	deny80FromB := api.Rule{
		IngressDeny: []api.IngressDenyRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromEndpoints: []api.EndpointSelector{endpointSelectorB},
			},
			ToPorts: []api.PortDenyRule{{
				Ports: []api.PortProtocol{
					{Port: "80", Protocol: api.ProtoTCP},
				},
			}},
		},
		}}

	expectedDeny := NewL4PolicyMapWithValues(map[string]*L4Filter{"80/TCP": {
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		PerSelectorPolicies: L7DataMap{
			td.cachedSelectorB: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {nil}}),
	}})

	td.policyMapEquals(t, expectedDeny, nil, &deny80FromB)
}
