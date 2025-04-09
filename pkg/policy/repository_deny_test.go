// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"fmt"
	stdlog "log"
	"testing"

	"github.com/stretchr/testify/assert"
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
	td := newTestData()
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
	require.EqualValues(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err := repo.mustAdd(fooIngressDenyRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.EqualValues(t, fooIngressDenyRule1, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, err = repo.mustAdd(fooIngressDenyRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.ElementsMatch(t, matchingRules.AsPolicyRules(), api.Rules{&fooIngressDenyRule1, &fooIngressDenyRule2}, "returned matching rules did not match")

	_, _, numDeleted := repo.deleteByLabelsLocked(labels.LabelArray{fooIngressDenyRule1Label})
	require.Equal(t, 1, numDeleted)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.False(t, egr, genCommentf(false, false))
	require.EqualValues(t, fooIngressDenyRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.deleteByLabelsLocked(labels.LabelArray{fooIngressDenyRule2Label})
	require.Equal(t, 1, numDeleted)
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.False(t, egr, genCommentf(false, false))
	require.EqualValues(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err = repo.mustAdd(fooEgressDenyRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.True(t, egr, genCommentf(false, true))
	require.EqualValues(t, fooEgressDenyRule1, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.deleteByLabelsLocked(labels.LabelArray{fooEgressDenyRule1Label})
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.mustAdd(fooEgressDenyRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.False(t, ing, genCommentf(true, false))
	require.True(t, egr, genCommentf(false, true))
	require.EqualValues(t, fooEgressDenyRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.deleteByLabelsLocked(labels.LabelArray{fooEgressDenyRule2Label})
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.mustAdd(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.True(t, egr, genCommentf(false, true))
	require.EqualValues(t, combinedRule, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.deleteByLabelsLocked(labels.LabelArray{combinedLabel})
	require.Equal(t, 1, numDeleted)

	SetPolicyEnabled(option.AlwaysEnforce)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, _, _, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.True(t, ing, genCommentf(true, true))
	require.True(t, egr, genCommentf(false, true))
	require.EqualValues(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

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
	require.EqualValues(t, ruleSlice{}, matchingRules, "no rules should be returned since policy enforcement is disabled")

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

func TestGetRulesMatching(t *testing.T) {
	td := newTestData()
	repo := td.repo

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.mutex.RLock()
	// no rules loaded: Allows() => denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fooToBar))
	repo.mutex.RUnlock()

	bar := labels.ParseSelectLabel("bar")
	foo := labels.ParseSelectLabel("foo")
	tag := labels.LabelArray{labels.ParseLabel("tag")}
	ingressDenyRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(bar),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(foo),
					},
				},
			},
		},
		Labels: tag,
	}

	egressDenyRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(bar),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(foo),
					},
				},
			},
		},
		Labels: tag,
	}

	// When no policy is applied.
	ingressMatch, egressMatch := repo.GetRulesMatching(labels.LabelArray{bar, foo})
	require.False(t, ingressMatch)
	require.False(t, egressMatch)

	// When ingress deny policy is applied.
	_, _, err := repo.mustAdd(ingressDenyRule)
	require.NoError(t, err)
	ingressMatch, egressMatch = repo.GetRulesMatching(labels.LabelArray{bar, foo})
	require.True(t, ingressMatch)
	require.False(t, egressMatch)

	// Delete igress deny policy.
	repo.deleteByLabels(tag)

	// When egress deny policy is applied.
	_, _, err = repo.mustAdd(egressDenyRule)
	require.NoError(t, err)
	ingressMatch, egressMatch = repo.GetRulesMatching(labels.LabelArray{bar, foo})
	require.False(t, ingressMatch)
	require.True(t, egressMatch)
}

func TestDeniesIngress(t *testing.T) {
	td := newTestData()
	repo := td.repo

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.mutex.RLock()
	// no rules loaded: Allows() => denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fooToBar))
	repo.mutex.RUnlock()

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("foo")),
					},
				},
			},
		},
		Labels: tag1,
	}

	// selector: groupA
	// require: groupA
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromRequires: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
					},
				},
			},
		},
		Labels: tag1,
	}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar2")),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("foo")),
					},
				},
			},
		},
		Labels: tag1,
	}

	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)
	_, _, err = repo.mustAdd(rule2)
	require.NoError(t, err)
	_, _, err = repo.mustAdd(rule3)
	require.NoError(t, err)

	// foo=>bar is not OK
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fooToBar))

	// foo=>bar2 is not OK
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}))

	// foo=>bar inside groupA is not OK
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}))

	// groupB can't talk to groupA => Denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}))

	//  restriction on groupB, unused label => not OK
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}))

	// foo=>bar3, no rule => Denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}))
}

func TestDeniesEgress(t *testing.T) {
	td := newTestData()
	repo := td.repo

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.mutex.RLock()
	// no rules loaded: Allows() => denied
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(fooToBar))
	repo.mutex.RUnlock()

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("bar")),
					},
				},
			},
		},
		Labels: tag1,
	}

	// selector: groupA
	// require: groupA
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToRequires: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
					},
				},
			},
		},
		Labels: tag1,
	}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						api.NewESFromLabels(labels.ParseSelectLabel("bar2")),
					},
				},
			},
		},
		Labels: tag1,
	}
	_, _, err := repo.mustAdd(rule1)
	require.NoError(t, err)
	_, _, err = repo.mustAdd(rule2)
	require.NoError(t, err)
	_, _, err = repo.mustAdd(rule3)
	require.NoError(t, err)

	// foo=>bar is not OK
	logBuffer := new(bytes.Buffer)
	result := repo.AllowsEgressRLocked(fooToBar.WithLogger(logBuffer))
	if !assert.EqualValues(t, api.Denied, result) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected")
	}

	// foo=>bar2 is not OK
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}))

	// foo=>bar inside groupA is not OK
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}))

	buffer := new(bytes.Buffer)
	// groupB can't talk to groupA => Denied
	ctx := &SearchContext{
		To:      labels.ParseSelectLabelArray("foo", "groupB"),
		From:    labels.ParseSelectLabelArray("bar", "groupA"),
		Logging: stdlog.New(buffer, "", 0),
		Trace:   TRACE_VERBOSE,
	}
	verdict := repo.AllowsEgressRLocked(ctx)
	require.Equal(t, api.Denied, verdict)

	// no restriction on groupB, unused label => not OK
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}))

	// foo=>bar3, no rule => Denied
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}))
}

func TestWildcardL3RulesIngressDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
				},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err := repo.mustAdd(l3Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	require.NoError(t, err)

	expectedPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL3}},
		},
	})
	require.EqualValues(t, expectedPolicy, policyDeny)
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestWildcardL4RulesIngressDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))

	labelsL4Kafka := labels.LabelArray{labels.ParseLabel("L4-kafka")}
	labelsL4HTTP := labels.LabelArray{labels.ParseLabel("L4-http")}

	l49092Rule := api.Rule{
		EndpointSelector: selFoo,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
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
	l49092Rule.Sanitize()
	_, _, err := repo.mustAdd(l49092Rule)
	require.NoError(t, err)

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar1},
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
	l480Rule.Sanitize()
	_, _, err = repo.mustAdd(l480Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	require.NoError(t, err)

	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL4HTTP}},
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL4Kafka}},
		},
	})
	require.True(t, policyDeny.TestingOnlyEquals(expectedDenyPolicy), policyDeny.TestingOnlyDiff(expectedDenyPolicy))
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestL3DependentL4IngressDenyFromRequires(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						selBar1,
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
					FromRequires: []api.EndpointSelector{selBar2},
				},
			},
		},
	}
	l480Rule.Sanitize()
	_, _, err := repo.mustAdd(l480Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	require.NoError(t, err)

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector)

	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{expectedCachedSelector: {nil}},
		},
	})
	require.EqualValues(t, expectedDenyPolicy, policyDeny)
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestL3DependentL4EgressDenyFromRequires(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{
						selBar1,
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
					ToRequires: []api.EndpointSelector{selBar2},
				},
			},
		},
	}
	l480Rule.Sanitize()
	_, _, err := repo.mustAdd(l480Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.NoError(t, err)

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
	expectedCachedSelector, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector)
	expectedCachedSelector2, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector2)

	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector2: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{expectedCachedSelector2: {nil}},
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{expectedCachedSelector: {nil}},
		},
	})
	if !assert.True(t, policyDeny.TestingOnlyEquals(expectedDenyPolicy), policyDeny.TestingOnlyDiff(expectedDenyPolicy)) {
		t.Errorf("Policy doesn't match expected:\n%s", logBuffer.String())
	}
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestWildcardL3RulesEgressDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))

	labelsL4 := labels.LabelArray{labels.ParseLabel("L4")}
	labelsICMP := labels.LabelArray{labels.ParseLabel("icmp")}
	labelsICMPv6 := labels.LabelArray{labels.ParseLabel("icmpv6")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
				},
			},
		},
		Labels: labelsL4,
	}
	l3Rule.Sanitize()
	_, _, err := repo.mustAdd(l3Rule)
	require.NoError(t, err)

	icmpV4Type := intstr.FromInt(8)
	icmpRule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
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
	err = icmpRule.Sanitize()
	require.NoError(t, err)

	_, _, err = repo.mustAdd(icmpRule)
	require.NoError(t, err)

	icmpV6Type := intstr.FromInt(128)
	icmpV6Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
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
	err = icmpV6Rule.Sanitize()
	require.NoError(t, err)

	_, _, err = repo.mustAdd(icmpV6Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.NoError(t, err)

	// Traffic to bar1 should not be forwarded to the DNS or HTTP
	// proxy at all, but if it is (e.g., for visibility, the
	// "0/ANY" rule should allow such traffic through.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL4}},
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsICMP}},
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsICMPv6}},
		},
	})
	require.Truef(t, policyDeny.TestingOnlyEquals(expectedDenyPolicy),
		"%s\nResolved policy did not match expected:\n%s", policyDeny.TestingOnlyDiff(expectedDenyPolicy), logBuffer.String())
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestWildcardL4RulesEgressDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))

	labelsL3DNS := labels.LabelArray{labels.ParseLabel("L3-dns")}
	labelsL3HTTP := labels.LabelArray{labels.ParseLabel("L3-http")}

	l453Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
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
	l453Rule.Sanitize()
	_, _, err := repo.mustAdd(l453Rule)
	require.NoError(t, err)

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
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
	l480Rule.Sanitize()
	_, _, err = repo.mustAdd(l480Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.NoError(t, err)

	// Bar1 should not be forwarded to the proxy, but if it is (e.g., for visibility),
	// the L3/L4 deny should pass it without an explicit L7 wildcard.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL3HTTP}},
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			L7Parser: ParserTypeNone,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				td.cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{td.cachedSelectorBar1: {labelsL3DNS}},
		},
	})
	if !assert.True(t, policyDeny.TestingOnlyEquals(expectedDenyPolicy), policyDeny.TestingOnlyDiff(expectedDenyPolicy)) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected")
	}
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestWildcardCIDRRulesEgressDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	cidrSlice := api.CIDRSlice{"192.0.0.0/3"}
	cidrSelectors := cidrSlice.GetAsEndpointSelectors()
	var cachedSelectors CachedSelectorSlice
	for i := range cidrSelectors {
		c, _ := td.sc.AddIdentitySelector(dummySelectorCacheUser, nil, cidrSelectors[i])
		cachedSelectors = append(cachedSelectors, c)
		defer td.sc.RemoveSelector(c, dummySelectorCacheUser)
	}
	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))

	l480Get := api.Rule{
		EndpointSelector: selFoo,
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
	l480Get.Sanitize()
	_, _, err := repo.mustAdd(l480Get)
	require.NoError(t, err)

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToCIDR: api.CIDRSlice{"192.0.0.0/3"},
				},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err = repo.mustAdd(l3Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.NoError(t, err)

	// Port 80 policy does not need the wildcard, as the "0" port policy will deny the traffic.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsHTTP}},
		},
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			L7Parser: ParserTypeNone,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsL3}},
		},
	})
	if !assert.True(t, policyDeny.TestingOnlyEquals(expectedDenyPolicy), policyDeny.TestingOnlyDiff(expectedDenyPolicy)) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestWildcardL3RulesIngressDenyFromEntities(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEntities: api.EntitySlice{api.EntityWorld},
				},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err := repo.mustAdd(l3Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, policyDeny.Len())
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	cachedSelectorWorld := td.sc.FindCachedIdentitySelector(selWorld)
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

	expectedPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				cachedSelectorWorld:   &PerSelectorPolicy{IsDeny: true},
				cachedSelectorWorldV4: &PerSelectorPolicy{IsDeny: true},
				cachedSelectorWorldV6: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress: true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorWorld:   {labelsL3},
				cachedSelectorWorldV4: {labelsL3},
				cachedSelectorWorldV6: {labelsL3},
			},
		},
	})

	require.EqualValues(t, expectedPolicy, policyDeny)
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestWildcardL3RulesEgressDenyToEntities(t *testing.T) {
	td := newTestData()
	repo := td.repo

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEntities: api.EntitySlice{api.EntityWorld},
				},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err := repo.mustAdd(l3Rule)
	require.NoError(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	policyDeny, err := repo.ResolveL4EgressPolicy(ctx)
	require.NoError(t, err)
	require.Equal(t, 1, policyDeny.Len())
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	cachedSelectorWorld := td.sc.FindCachedIdentitySelector(selWorld)
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := td.sc.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

	// We should expect an empty deny policy because the policy does not
	// contain any rules with the label 'id=foo'.
	expectedDenyPolicy := NewL4PolicyMapWithValues(map[string]*L4Filter{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				cachedSelectorWorld:   &PerSelectorPolicy{IsDeny: true},
				cachedSelectorWorldV4: &PerSelectorPolicy{IsDeny: true},
				cachedSelectorWorldV6: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress: false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorWorld:   {labelsL3},
				cachedSelectorWorldV4: {labelsL3},
				cachedSelectorWorldV6: {labelsL3},
			},
		},
	})

	require.EqualValues(t, expectedDenyPolicy, policyDeny)
	policyDeny.Detach(repo.GetSelectorCache())
}

func TestMinikubeGettingStartedDeny(t *testing.T) {
	td := newTestData()
	repo := td.repo

	app2Selector := labels.ParseSelectLabelArray("id=app2")

	fromApp2 := &SearchContext{
		From:  app2Selector,
		To:    labels.ParseSelectLabelArray("id=app1"),
		Trace: TRACE_VERBOSE,
	}

	fromApp3 := &SearchContext{
		From: labels.ParseSelectLabelArray("id=app3"),
		To:   labels.ParseSelectLabelArray("id=app1"),
	}

	repo.mutex.RLock()
	// no rules loaded: Allows() => denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fromApp2))
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fromApp3))
	repo.mutex.RUnlock()

	selFromApp2 := api.NewESFromLabels(
		labels.ParseSelectLabel("id=app2"),
	)

	selectorFromApp2 := []api.EndpointSelector{
		selFromApp2,
	}

	_, _, err := repo.mustAdd(api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: selectorFromApp2,
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	})
	require.NoError(t, err)

	_, _, err = repo.mustAdd(api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: selectorFromApp2,
				},
				ToPorts: []api.PortDenyRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	})
	require.NoError(t, err)

	repo.mutex.RLock()
	defer repo.mutex.RUnlock()

	// L4 from app2 is restricted
	logBuffer := new(bytes.Buffer)
	l4IngressDenyPolicy, err := repo.ResolveL4IngressPolicy(fromApp2.WithLogger(logBuffer))
	require.NoError(t, err)

	cachedSelectorApp2 := td.sc.FindCachedIdentitySelector(selFromApp2)
	require.NotNil(t, cachedSelectorApp2)

	expectedDeny := NewL4Policy(repo.GetRevision())
	expectedDeny.Ingress.PortRules.Upsert("80", 0, "TCP", &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorApp2: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress:    true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorApp2: {nil}},
	})

	if !assert.EqualValues(t, expectedDeny.Ingress.PortRules, l4IngressDenyPolicy) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected")
	}
	l4IngressDenyPolicy.Detach(td.sc)
	expectedDeny.Detach(td.sc)

	// L4 from app3 has no rules
	expectedDeny = NewL4Policy(repo.GetRevision())
	l4IngressDenyPolicy, err = repo.ResolveL4IngressPolicy(fromApp3)
	require.NoError(t, err)
	require.Equal(t, 0, l4IngressDenyPolicy.Len())
	require.Equal(t, expectedDeny.Ingress.PortRules, l4IngressDenyPolicy)
	l4IngressDenyPolicy.Detach(td.sc)
	expectedDeny.Detach(td.sc)
}

func buildDenyRule(from, to, port string) api.Rule {
	reservedES := api.NewESFromLabels(labels.ParseSelectLabel("reserved:host"))
	fromES := api.NewESFromLabels(labels.ParseSelectLabel(from))
	toES := api.NewESFromLabels(labels.ParseSelectLabel(to))

	ports := []api.PortDenyRule{}
	if port != "" {
		ports = []api.PortDenyRule{
			{Ports: []api.PortProtocol{{Port: port}}},
		}
	}
	return api.Rule{
		EndpointSelector: toES,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{
						reservedES,
						fromES,
					},
				},
				ToPorts: ports,
			},
		},
	}
}

func TestPolicyDenyTrace(t *testing.T) {
	td := newTestData()
	repo := td.repo

	// Add rules to allow foo=>bar
	l3rule := buildDenyRule("foo", "bar", "")
	rules := api.Rules{&l3rule}
	_, _ = repo.MustAddList(rules)

	// foo=>bar is OK
	expectedOut := `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Denies from labels {"matchLabels":{"reserved:host":""}}
    Denies from labels {"matchLabels":{"any:foo":""}}
      Found all required labels
1/1 rules selected
Found no allow rule
Found deny rule
Ingress verdict: denied
`
	ctx := buildSearchCtx("foo", "bar", 0)
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// foo=>bar:80 is OK
	ctx = buildSearchCtx("foo", "bar", 80)
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// bar=>foo is Denied
	ctx = buildSearchCtx("bar", "foo", 0)
	expectedOut = `
Resolving ingress policy for [any:foo]
0/1 rules selected
Found no allow rule
Found no deny rule
Ingress verdict: denied
`
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// bar=>foo:80 is also Denied by the same logic
	ctx = buildSearchCtx("bar", "foo", 80)
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// Now, add extra rules to allow specifically baz=>bar on port 80
	l4rule := buildDenyRule("baz", "bar", "80")
	_, _, err := repo.mustAdd(l4rule)
	require.NoError(t, err)

	// baz=>bar:80 is OK
	ctx = buildSearchCtx("baz", "bar", 80)
	expectedOut = `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Denies from labels {"matchLabels":{"reserved:host":""}}
    Denies from labels {"matchLabels":{"any:foo":""}}
      No label match for [any:baz]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Denies from labels {"matchLabels":{"reserved:host":""}}
    Denies from labels {"matchLabels":{"any:baz":""}}
      Found all required labels
      Denies port [{80 0 ANY}]
2/2 rules selected
Found no allow rule
Found deny rule
Ingress verdict: denied
`
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// bar=>bar:80 is Denied
	ctx = buildSearchCtx("bar", "bar", 80)
	expectedOut = `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Denies from labels {"matchLabels":{"reserved:host":""}}
    Denies from labels {"matchLabels":{"any:foo":""}}
      No label match for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Denies from labels {"matchLabels":{"reserved:host":""}}
    Denies from labels {"matchLabels":{"any:baz":""}}
      No label match for [any:bar]
2/2 rules selected
Found no allow rule
Found no deny rule
Ingress verdict: denied
`
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// Test that FromRequires "baz" drops "foo" traffic
	l3rule = api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		IngressDeny: []api.IngressDenyRule{{
			IngressCommonRule: api.IngressCommonRule{
				FromRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("baz")),
				},
			},
		}},
	}
	_, _, err = repo.mustAdd(l3rule)
	require.NoError(t, err)

	// foo=>bar is now denied due to the FromRequires
	ctx = buildSearchCtx("foo", "bar", 0)
	expectedOut = `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Enforcing requirements [{Key:any.baz Operator:In Values:[]}]
    Denies from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Denies from labels {"matchLabels":{"any:foo":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      No label match for [any:foo]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Enforcing requirements [{Key:any.baz Operator:In Values:[]}]
    Denies from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Denies from labels {"matchLabels":{"any:baz":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      No label match for [any:foo]
* Rule {"matchLabels":{"any:bar":""}}: selected
3/3 rules selected
Found no allow rule
Found no deny rule
Ingress verdict: denied
`
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// baz=>bar is only denied because of the L4 policy
	ctx = buildSearchCtx("baz", "bar", 0)
	expectedOut = `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Enforcing requirements [{Key:any.baz Operator:In Values:[]}]
    Denies from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Denies from labels {"matchLabels":{"any:foo":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      No label match for [any:baz]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Enforcing requirements [{Key:any.baz Operator:In Values:[]}]
    Denies from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Denies from labels {"matchLabels":{"any:baz":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      Found all required labels
      Denies port [{80 0 ANY}]
        No port match found
* Rule {"matchLabels":{"any:bar":""}}: selected
3/3 rules selected
Found no allow rule
Found no deny rule
Ingress verdict: denied
`
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// Should still be allowed with the new FromRequires constraint
	ctx = buildSearchCtx("baz", "bar", 80)
	repo.mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.mutex.RUnlock()
	require.Equal(t, api.Denied, verdict)
}
