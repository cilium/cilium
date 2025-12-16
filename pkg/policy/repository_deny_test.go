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
	ipcachetypes "github.com/cilium/cilium/pkg/ipcache/types"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
	"github.com/cilium/cilium/pkg/policy/types"
)

func TestComputePolicyDenyEnforcementAndRules(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

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
	fooIngressDenyRule1Resource := ipcachetypes.ResourceID("fooIngressDenyRule1Resource")
	fooIngressDenyRule2Resource := ipcachetypes.ResourceID("fooIngressDenyRule2Resource")
	fooEgressDenyRule1Resource := ipcachetypes.ResourceID("fooEgressDenyRule1Resource")
	fooEgressDenyRule2Resource := ipcachetypes.ResourceID("fooEgressDenyRule2Resource")
	combinedResource := ipcachetypes.ResourceID("combinedResource")
	initIdentity := identity.LookupReservedIdentity(identity.ReservedIdentityInit)
	td.addIdentity(fooIdentity)

	fooIngressDenyRule1 := &types.PolicyEntry{
		Ingress:     true,
		DefaultDeny: true,
		Verdict:     types.Deny,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooIngressDenyRule1Label,
		},
	}

	fooIngressDenyRule2 := &types.PolicyEntry{
		Ingress:     true,
		DefaultDeny: true,
		Verdict:     types.Deny,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooIngressDenyRule2Label,
		},
	}

	fooEgressDenyRule1 := &types.PolicyEntry{
		Ingress:     false,
		DefaultDeny: true,
		Verdict:     types.Deny,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooEgressDenyRule1Label,
		},
	}

	fooEgressDenyRule2 := &types.PolicyEntry{
		Ingress:     false,
		DefaultDeny: true,
		Verdict:     types.Deny,
		Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
		L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
		Labels: labels.LabelArray{
			fooEgressDenyRule2Label,
		},
	}

	combinedRule := types.PolicyEntries{
		&types.PolicyEntry{
			Ingress:     true,
			DefaultDeny: true,
			Verdict:     types.Deny,
			Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
			L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
			Labels: labels.LabelArray{
				combinedLabel,
			},
		}, &types.PolicyEntry{
			Ingress:     false,
			DefaultDeny: true,
			Verdict:     types.Deny,
			Subject:     types.NewLabelSelectorFromLabels(fooSelectLabel),
			L3:          types.ToSelectors(api.NewESFromLabels(fooSelectLabel)),
			Labels: labels.LabelArray{
				combinedLabel,
			},
		},
	}

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

	ing, egr, _, _, matchingRulesI, matchingRulesE := repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	repo.ReplaceByResource([]*types.PolicyEntry{fooIngressDenyRule1}, fooIngressDenyRule1Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.Equal(t, *fooIngressDenyRule1, matchingRulesI[0].PolicyEntry, "returned matching rules did not match")
	require.Len(t, matchingRulesI, 1, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	repo.ReplaceByResource([]*types.PolicyEntry{fooIngressDenyRule2}, fooIngressDenyRule2Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.ElementsMatch(t, matchingRulesI.AsPolicyEntries(), types.PolicyEntries{fooIngressDenyRule1, fooIngressDenyRule2}, "returned matching rules did not match")
	require.Len(t, matchingRulesI, 2, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	_, _, numDeleted := repo.ReplaceByResource(nil, fooIngressDenyRule1Resource)
	require.Equal(t, 1, numDeleted)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.Equal(t, *fooIngressDenyRule2, matchingRulesI[0].PolicyEntry, "returned matching rules did not match")
	require.Len(t, matchingRulesI, 1, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, fooIngressDenyRule2Resource)
	require.Equal(t, 1, numDeleted)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	repo.ReplaceByResource([]*types.PolicyEntry{fooEgressDenyRule1}, fooEgressDenyRule1Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.True(t, egr, genCommentf(false, true))
	require.Equal(t, *fooEgressDenyRule1, matchingRulesE[0].PolicyEntry, "returned matching rules did not match")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Len(t, matchingRulesE, 1, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, fooEgressDenyRule1Resource)
	require.Equal(t, 1, numDeleted)

	repo.ReplaceByResource([]*types.PolicyEntry{fooEgressDenyRule2}, fooEgressDenyRule2Resource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.True(t, egr, genCommentf(false, true))
	require.Equal(t, *fooEgressDenyRule2, matchingRulesE[0].PolicyEntry, "returned matching rules did not match")
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Len(t, matchingRulesE, 1, "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, fooEgressDenyRule2Resource)
	require.Equal(t, 1, numDeleted)

	repo.ReplaceByResource(combinedRule, combinedResource)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.True(t, egr, genCommentf(false, true))
	require.Len(t, matchingRulesI, 1, "returned matching rules did not match")
	require.Len(t, matchingRulesE, 1, "returned matching rules did not match")
	require.ElementsMatch(t, matchingRulesI.AsPolicyEntries(), combinedRule[0:1], "returned matching rules did not match")
	require.ElementsMatch(t, matchingRulesE.AsPolicyEntries(), combinedRule[1:2], "returned matching rules did not match")

	_, _, numDeleted = repo.ReplaceByResource(nil, combinedResource)
	require.Equal(t, 2, numDeleted)

	SetPolicyEnabled(option.AlwaysEnforce)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.True(t, egr, genCommentf(false, true))
	require.Empty(t, matchingRulesI, "returned matching rules did not match")
	require.Empty(t, matchingRulesE, "returned matching rules did not match")

	SetPolicyEnabled(option.NeverEnforce)
	_, _ = repo.MustAddPolicyEntries(combinedRule)
	ing, egr, _, _, matchingRulesI, matchingRulesE = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
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
	ingress, egress, _, _, _, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	require.False(t, ingress)
	require.False(t, egress)

}

func TestDeniesIngress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs)
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

	checkFlow(t, repo, td.identityManager, flowAToB, api.Denied)
	checkFlow(t, repo, td.identityManager, flowCtoB, api.Allowed)
}

func TestDeniesEgress(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t)).withIDs(ruleTestIDs, identity.ListReservedIdentities())
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

	checkFlow(t, repo, td.identityManager, flowAToB, api.Denied)
	checkFlow(t, repo, td.identityManager, flowAToC, api.Allowed)
	checkFlow(t, repo, td.identityManager, flowAToWorld80, api.Allowed)
}

func TestWildcardL3RulesIngressDeny(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

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
				td.cachedSelectorBar1: denyPerSelectorPolicy,
			},
			Ingress:    true,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL3}}),
		},
	})
	td.policyMapEquals(t, expected, nil, &l3Rule)
}

func TestWildcardL4RulesIngressDeny(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

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
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL4HTTP}}),
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL4Kafka}}),
		},
	})
	td.policyMapEquals(t, expectedDenyPolicy, nil, &l49092Rule, &l480Rule)
}

func TestWildcardL3RulesEgressDeny(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

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
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL4}}),
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsICMP}}),
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			Ingress:    false,
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsICMPv6}}),
		},
	})
	td.policyMapEquals(t, nil, expectedDenyPolicy, &l3Rule, &icmpRule, &icmpV6Rule)
}

func TestWildcardL4RulesEgressDeny(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

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
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL3HTTP}}),
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorB: denyPerSelectorPolicy,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {labelsL3DNS}}),
		},
	})

	td.policyMapEquals(t, nil, expectedDenyPolicy, &l453Rule, &l480Rule)
}

func TestWildcardCIDRRulesEgressDeny(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	cachedSelectors, _ := td.sc.AddSelectors(dummySelectorCacheUser, EmptyStringLabels,
		types.ToSelector(api.CIDR("192.0.0.0/3")))
	defer td.sc.RemoveSelectors(cachedSelectors, dummySelectorCacheUser)

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
				cachedSelectors[0]: denyPerSelectorPolicy,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsHTTP}}),
		},
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: denyPerSelectorPolicy,
			},
			RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsL3}}),
		},
	})
	td.policyMapEquals(t, nil, expectedDenyPolicy, &l480Get, &l3Rule)
}

func TestWildcardL3RulesIngressDenyFromEntities(t *testing.T) {
	td := newTestData(t, hivetest.Logger(t))

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
				td.cachedSelectorWorld:   denyPerSelectorPolicy,
				td.cachedSelectorWorldV4: denyPerSelectorPolicy,
				td.cachedSelectorWorldV6: denyPerSelectorPolicy,
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
	td := newTestData(t, hivetest.Logger(t))

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
				td.cachedSelectorWorld:   denyPerSelectorPolicy,
				td.cachedSelectorWorldV4: denyPerSelectorPolicy,
				td.cachedSelectorWorldV6: denyPerSelectorPolicy,
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
	td := newTestData(t, hivetest.Logger(t))

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
			td.cachedSelectorB: denyPerSelectorPolicy,
		},
		Ingress:    true,
		RuleOrigin: OriginForTest(map[CachedSelector]labels.LabelArrayList{td.cachedSelectorB: {nil}}),
	}})

	td.policyMapEquals(t, expectedDeny, nil, &deny80FromB)
}
