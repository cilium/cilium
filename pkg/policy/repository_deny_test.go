// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	stdlog "log"

	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (ds *PolicyTestSuite) TestComputePolicyDenyEnforcementAndRules(c *C) {
	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	fooSelectLabel := labels.ParseSelectLabel("foo")
	fooNumericIdentity := 9001
	fooIdentity := identity.NewIdentity(identity.NumericIdentity(fooNumericIdentity), lbls)
	fooIngressDenyRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule1", labels.LabelSourceAny)
	fooIngressDenyRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule2", labels.LabelSourceAny)
	fooEgressDenyRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule1", labels.LabelSourceAny)
	fooEgressDenyRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule2", labels.LabelSourceAny)
	combinedLabel := labels.NewLabel(k8sConst.PolicyLabelName, "combined", labels.LabelSourceAny)
	initIdentity := identity.LookupReservedIdentity(identity.ReservedIdentityInit)

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

	genCommentf := func(ingress, accept bool) CommentInterface {
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
		return Commentf(
			"%s policy enforcement should%s be applied since%s %s rule selects it in the repository",
			direction, acceptStr, acceptStr2, direction)
	}

	ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, genCommentf(true, false))
	c.Assert(egr, Equals, false, genCommentf(false, false))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err := repo.Add(fooIngressDenyRule1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, genCommentf(true, true))
	c.Assert(egr, Equals, false, genCommentf(false, false))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressDenyRule1, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooIngressDenyRule2)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, genCommentf(true, true))
	c.Assert(egr, Equals, false, genCommentf(false, false))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressDenyRule1, Commentf("returned matching rules did not match"))
	c.Assert(matchingRules[1].Rule, checker.DeepEquals, fooIngressDenyRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted := repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressDenyRule1Label})
	c.Assert(numDeleted, Equals, 1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, genCommentf(true, true))
	c.Assert(egr, Equals, false, genCommentf(false, false))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressDenyRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressDenyRule2Label})
	c.Assert(numDeleted, Equals, 1)
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, genCommentf(true, false))
	c.Assert(egr, Equals, false, genCommentf(false, false))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooEgressDenyRule1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, genCommentf(true, false))
	c.Assert(egr, Equals, true, genCommentf(false, true))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooEgressDenyRule1, Commentf("returned matching rules did not match"))
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressDenyRule1Label})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(fooEgressDenyRule2)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, genCommentf(true, false))
	c.Assert(egr, Equals, true, genCommentf(false, true))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooEgressDenyRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressDenyRule2Label})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(combinedRule)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, genCommentf(true, true))
	c.Assert(egr, Equals, true, genCommentf(false, true))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, combinedRule, Commentf("returned matching rules did not match"))
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{combinedLabel})
	c.Assert(numDeleted, Equals, 1)

	SetPolicyEnabled(option.AlwaysEnforce)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, genCommentf(true, true))
	c.Assert(egr, Equals, true, genCommentf(false, true))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	SetPolicyEnabled(option.NeverEnforce)
	_, _, err = repo.Add(combinedRule)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, genCommentf(true, false))
	c.Assert(egr, Equals, false, genCommentf(false, false))
	c.Assert(matchingRules, IsNil, Commentf("no rules should be returned since policy enforcement is disabled"))

	// Test init identity.

	SetPolicyEnabled(option.DefaultEnforcement)
	// If the mode is "default", check that the policy is always enforced for
	// endpoints with the reserved:init label. If no policy rules match
	// reserved:init, this drops all ingress and egress traffic.
	ingress, egress, matchingRules := repo.computePolicyEnforcementAndRules(initIdentity)
	c.Assert(ingress, Equals, true)
	c.Assert(egress, Equals, true)
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("no rules should be returned since policy enforcement is disabled"))

	// Check that the "always" and "never" modes are not affected.
	SetPolicyEnabled(option.AlwaysEnforce)
	ingress, egress, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	c.Assert(ingress, Equals, true)
	c.Assert(egress, Equals, true)

	SetPolicyEnabled(option.NeverEnforce)
	ingress, egress, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	c.Assert(ingress, Equals, false)
	c.Assert(egress, Equals, false)

}

func (ds *PolicyTestSuite) TestGetRulesMatching(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsIngressRLocked(fooToBar), Equals, api.Denied)
	repo.Mutex.RUnlock()

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
	c.Assert(ingressMatch, Equals, false)
	c.Assert(egressMatch, Equals, false)

	// When ingress deny policy is applied.
	_, _, err := repo.Add(ingressDenyRule)
	c.Assert(err, IsNil)
	ingressMatch, egressMatch = repo.GetRulesMatching(labels.LabelArray{bar, foo})
	c.Assert(ingressMatch, Equals, true)
	c.Assert(egressMatch, Equals, false)

	// Delete igress deny policy.
	repo.DeleteByLabels(tag)

	// When egress deny policy is applied.
	_, _, err = repo.Add(egressDenyRule)
	c.Assert(err, IsNil)
	ingressMatch, egressMatch = repo.GetRulesMatching(labels.LabelArray{bar, foo})
	c.Assert(ingressMatch, Equals, false)
	c.Assert(egressMatch, Equals, true)
}

func (ds *PolicyTestSuite) TestDeniesIngress(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsIngressRLocked(fooToBar), Equals, api.Denied)
	repo.Mutex.RUnlock()

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

	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule2)
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule3)
	c.Assert(err, IsNil)

	// foo=>bar is not OK
	c.Assert(repo.AllowsIngressRLocked(fooToBar), Equals, api.Denied)

	// foo=>bar2 is not OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, api.Denied)

	// foo=>bar inside groupA is not OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Denied)

	// groupB can't talk to groupA => Denied
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Denied)

	//  restriction on groupB, unused label => not OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, api.Denied)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, api.Denied)
}

func (ds *PolicyTestSuite) TestDeniesEgress(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsEgressRLocked(fooToBar), Equals, api.Denied)
	repo.Mutex.RUnlock()

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
	_, _, err := repo.Add(rule1)
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule2)
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule3)
	c.Assert(err, IsNil)

	// foo=>bar is not OK
	logBuffer := new(bytes.Buffer)
	result := repo.AllowsEgressRLocked(fooToBar.WithLogger(logBuffer))
	if equal, err := checker.DeepEqual(result, api.Denied); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}

	// foo=>bar2 is not OK
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, api.Denied)

	// foo=>bar inside groupA is not OK
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Denied)

	buffer := new(bytes.Buffer)
	// groupB can't talk to groupA => Denied
	ctx := &SearchContext{
		To:      labels.ParseSelectLabelArray("foo", "groupB"),
		From:    labels.ParseSelectLabelArray("bar", "groupA"),
		Logging: stdlog.New(buffer, "", 0),
		Trace:   TRACE_VERBOSE,
	}
	verdict := repo.AllowsEgressRLocked(ctx)
	c.Assert(verdict, Equals, api.Denied)

	// no restriction on groupB, unused label => not OK
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, api.Denied)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, api.Denied)
}

func (ds *PolicyTestSuite) TestWildcardL3RulesIngressDeny(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l3Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedPolicy := L4PolicyMap{
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL3}},
		},
	}
	c.Assert(policyDeny, checker.DeepEquals, expectedPolicy)
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL4RulesIngressDeny(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l49092Rule)
	c.Assert(err, IsNil)

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
	_, _, err = repo.Add(l480Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedDenyPolicy := L4PolicyMap{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL4HTTP}},
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL4Kafka}},
		},
	}
	c.Assert(policyDeny, checker.DeepEquals, expectedDenyPolicy)
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestL3DependentL4IngressDenyFromRequires(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l480Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector)

	expectedDenyPolicy := L4PolicyMap{
		"80/TCP": &L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{expectedCachedSelector: {nil}},
		},
	}
	c.Assert(policyDeny, checker.DeepEquals, expectedDenyPolicy)
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestL3DependentL4EgressDenyFromRequires(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l480Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

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
	expectedCachedSelector, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector)
	expectedCachedSelector2, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector2)

	expectedDenyPolicy := L4PolicyMap{
		"0/ANY": &L4Filter{
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector2: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{expectedCachedSelector2: {nil}},
		},
		"80/TCP": &L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{expectedCachedSelector: {nil}},
		},
	}
	if !c.Check(policyDeny, checker.DeepEquals, expectedDenyPolicy) {
		c.Errorf("Policy doesn't match expected:\n%s", logBuffer.String())
	}
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgressDeny(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l3Rule)
	c.Assert(err, IsNil)

	icmpRule := api.Rule{
		EndpointSelector: selFoo,
		EgressDeny: []api.EgressDenyRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar1},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type: 8,
					}},
				}},
			},
		},
		Labels: labelsICMP,
	}
	err = icmpRule.Sanitize()
	c.Assert(err, IsNil)

	_, _, err = repo.Add(icmpRule)
	c.Assert(err, IsNil)

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
						Type:   128,
					}},
				}},
			},
		},
		Labels: labelsICMPv6,
	}
	err = icmpV6Rule.Sanitize()
	c.Assert(err, IsNil)

	_, _, err = repo.Add(icmpV6Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	// Traffic to bar1 should not be forwarded to the DNS or HTTP
	// proxy at all, but if it is (e.g., for visibility, the
	// "0/ANY" rule should allow such traffic through.
	expectedDenyPolicy := L4PolicyMap{
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL4}},
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsICMP}},
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsICMPv6}},
		},
	}
	c.Assert(policyDeny, checker.DeepEquals, expectedDenyPolicy, Commentf("Resolved policy did not match expected:\n%s", logBuffer.String()))
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL4RulesEgressDeny(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l453Rule)
	c.Assert(err, IsNil)

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
	_, _, err = repo.Add(l480Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	// Bar1 should not be forwarded to the proxy, but if it is (e.g., for visibility),
	// the L3/L4 deny should pass it without an explicit L7 wildcard.
	expectedDenyPolicy := L4PolicyMap{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeNone,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL3HTTP}},
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			L7Parser: ParserTypeNone,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: &PerSelectorPolicy{IsDeny: true},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL3DNS}},
		},
	}
	if equal, err := checker.DeepEqual(policyDeny, expectedDenyPolicy); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardCIDRRulesEgressDeny(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	cidrSlice := api.CIDRSlice{"192.0.0.0/3"}
	cidrSelectors := cidrSlice.GetAsEndpointSelectors()
	var cachedSelectors CachedSelectorSlice
	for i := range cidrSelectors {
		c, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, cidrSelectors[i])
		cachedSelectors = append(cachedSelectors, c)
		defer testSelectorCache.RemoveSelector(c, dummySelectorCacheUser)
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
	_, _, err := repo.Add(l480Get)
	c.Assert(err, IsNil)

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
	_, _, err = repo.Add(l3Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policyDeny, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	// Port 80 policy does not need the wildcard, as the "0" port policy will deny the traffic.
	expectedDenyPolicy := L4PolicyMap{
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
	}
	if equal, err := checker.DeepEqual(policyDeny, expectedDenyPolicy); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesIngressDenyFromEntities(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l3Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policyDeny, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(policyDeny), Equals, 1)
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(selWorld)
	c.Assert(cachedSelectorWorld, Not(IsNil))

	cachedSelectorWorldV4 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	c.Assert(cachedSelectorWorldV4, Not(IsNil))

	cachedSelectorWorldV6 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	c.Assert(cachedSelectorWorldV6, Not(IsNil))

	expectedPolicy := L4PolicyMap{
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
	}

	c.Assert(policyDeny, checker.DeepEquals, expectedPolicy)
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgressDenyToEntities(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
	_, _, err := repo.Add(l3Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policyDeny, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(policyDeny), Equals, 1)
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(selWorld)
	c.Assert(cachedSelectorWorld, Not(IsNil))

	cachedSelectorWorldV4 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	c.Assert(cachedSelectorWorldV4, Not(IsNil))

	cachedSelectorWorldV6 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	c.Assert(cachedSelectorWorldV6, Not(IsNil))

	// We should expect an empty deny policy because the policy does not
	// contain any rules with the label 'id=foo'.
	expectedDenyPolicy := L4PolicyMap{
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
	}

	c.Assert(policyDeny, checker.DeepEquals, expectedDenyPolicy)
	policyDeny.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestMinikubeGettingStartedDeny(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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

	repo.Mutex.RLock()
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsIngressRLocked(fromApp2), Equals, api.Denied)
	c.Assert(repo.AllowsIngressRLocked(fromApp3), Equals, api.Denied)
	repo.Mutex.RUnlock()

	selFromApp2 := api.NewESFromLabels(
		labels.ParseSelectLabel("id=app2"),
	)

	selectorFromApp2 := []api.EndpointSelector{
		selFromApp2,
	}

	_, _, err := repo.Add(api.Rule{
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
	c.Assert(err, IsNil)

	_, _, err = repo.Add(api.Rule{
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
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	logBuffer := new(bytes.Buffer)
	l4IngressDenyPolicy, err := repo.ResolveL4IngressPolicy(fromApp2.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	cachedSelectorApp2 := testSelectorCache.FindCachedIdentitySelector(selFromApp2)
	c.Assert(cachedSelectorApp2, Not(IsNil))

	expectedDeny := NewL4Policy(repo.GetRevision())
	expectedDeny.Ingress.PortRules["80/TCP"] = &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: ParserTypeNone,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorApp2: &PerSelectorPolicy{IsDeny: true},
		},
		Ingress:    true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorApp2: {nil}},
	}

	if equal, err := checker.DeepEqual(l4IngressDenyPolicy, expectedDeny.Ingress.PortRules); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	l4IngressDenyPolicy.Detach(testSelectorCache)
	expectedDeny.Detach(testSelectorCache)

	// L4 from app3 has no rules
	expectedDeny = NewL4Policy(repo.GetRevision())
	l4IngressDenyPolicy, err = repo.ResolveL4IngressPolicy(fromApp3)
	c.Assert(err, IsNil)
	c.Assert(len(l4IngressDenyPolicy), Equals, 0)
	c.Assert(l4IngressDenyPolicy, checker.Equals, expectedDeny.Ingress.PortRules)
	l4IngressDenyPolicy.Detach(testSelectorCache)
	expectedDeny.Detach(testSelectorCache)
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

func (ds *PolicyTestSuite) TestPolicyDenyTrace(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	// Add rules to allow foo=>bar
	l3rule := buildDenyRule("foo", "bar", "")
	rules := api.Rules{&l3rule}
	_, _ = repo.AddList(rules)

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
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// foo=>bar:80 is OK
	ctx = buildSearchCtx("foo", "bar", 80)
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// bar=>foo is Denied
	ctx = buildSearchCtx("bar", "foo", 0)
	expectedOut = `
Resolving ingress policy for [any:foo]
0/1 rules selected
Found no allow rule
Found no deny rule
Ingress verdict: denied
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// bar=>foo:80 is also Denied by the same logic
	ctx = buildSearchCtx("bar", "foo", 80)
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Now, add extra rules to allow specifically baz=>bar on port 80
	l4rule := buildDenyRule("baz", "bar", "80")
	_, _, err := repo.Add(l4rule)
	c.Assert(err, IsNil)

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
      Denies port [{80 }]
2/2 rules selected
Found no allow rule
Found deny rule
Ingress verdict: denied
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

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
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

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
	_, _, err = repo.Add(l3rule)
	c.Assert(err, IsNil)

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
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

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
      Denies port [{80 }]
        No port match found
* Rule {"matchLabels":{"any:bar":""}}: selected
3/3 rules selected
Found no allow rule
Found no deny rule
Ingress verdict: denied
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Should still be allowed with the new FromRequires constraint
	ctx = buildSearchCtx("baz", "bar", 80)
	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()
	c.Assert(verdict, Equals, api.Denied)
}

func (ds *PolicyTestSuite) TestRemoveIdentityFromRuleDenyCaches(c *C) {

	testRepo := parseAndAddRules(c, api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		IngressDeny: []api.IngressDenyRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{endpointSelectorC},
				},
			},
		},
	}})

	addedRule := testRepo.rules[0]

	selectedEpLabels := labels.ParseSelectLabel("id=a")
	selectedIdentity := identity.NewIdentity(54321, labels.Labels{selectedEpLabels.Key: selectedEpLabels})

	notSelectedEpLabels := labels.ParseSelectLabel("id=b")
	notSelectedIdentity := identity.NewIdentity(9876, labels.Labels{notSelectedEpLabels.Key: notSelectedEpLabels})

	// selectedEndpoint is selected by rule, so we it should be added to
	// EndpointsSelected.
	c.Assert(addedRule.matches(selectedIdentity), Equals, true)
	c.Assert(addedRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{selectedIdentity.ID: true})

	wg := testRepo.removeIdentityFromRuleCaches(selectedIdentity)
	wg.Wait()

	c.Assert(addedRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{})

	c.Assert(addedRule.matches(notSelectedIdentity), Equals, false)
	c.Assert(addedRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{notSelectedIdentity.ID: false})

	wg = testRepo.removeIdentityFromRuleCaches(notSelectedIdentity)
	wg.Wait()

	c.Assert(addedRule.metadata.IdentitySelected, checker.DeepEquals, map[identity.NumericIdentity]bool{})
}
