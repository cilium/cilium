// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"fmt"
	stdlog "log"
	"testing"

	. "github.com/cilium/checkmate"
	"github.com/cilium/proxy/pkg/policy/api/kafka"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func (ds *PolicyTestSuite) TestComputePolicyEnforcementAndRules(c *C) {

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
	fooIngressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule1", labels.LabelSourceAny)
	fooIngressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule2", labels.LabelSourceAny)
	fooEgressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule1", labels.LabelSourceAny)
	fooEgressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule2", labels.LabelSourceAny)
	combinedLabel := labels.NewLabel(k8sConst.PolicyLabelName, "combined", labels.LabelSourceAny)
	initIdentity := identity.LookupReservedIdentity(identity.ReservedIdentityInit)

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

	ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no rules are in repository"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err := repo.Add(fooIngressRule1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressRule1, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooIngressRule2)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressRule1, Commentf("returned matching rules did not match"))
	c.Assert(matchingRules[1].Rule, checker.DeepEquals, fooIngressRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted := repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressRule1Label})
	c.Assert(numDeleted, Equals, 1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressRule2Label})
	c.Assert(numDeleted, Equals, 1)

	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no rules are in repository"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooEgressRule1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no ingress rules select"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooEgressRule1, Commentf("returned matching rules did not match"))
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule1Label})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(fooEgressRule2)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no ingress rules select"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooEgressRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule2Label})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(combinedRule)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules selects"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, combinedRule, Commentf("returned matching rules did not match"))
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{combinedLabel})
	c.Assert(numDeleted, Equals, 1)

	SetPolicyEnabled(option.AlwaysEnforce)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules selects"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	SetPolicyEnabled(option.NeverEnforce)
	_, _, err = repo.Add(combinedRule)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since policy enforcement is disabled "))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since policy enforcement is disabled"))
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

func (ds *PolicyTestSuite) TestAddSearchDelete(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	// cannot add empty rule
	rev, _, err := repo.Add(api.Rule{})
	c.Assert(err, Not(IsNil))
	c.Assert(rev, Equals, uint64(1))

	lbls1 := labels.LabelArray{
		labels.ParseLabel("tag1"),
		labels.ParseLabel("tag2"),
	}
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Labels:           lbls1,
	}
	rule1.Sanitize()
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls1,
	}
	rule2.Sanitize()
	lbls2 := labels.LabelArray{labels.ParseSelectLabel("tag3")}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls2,
	}
	rule3.Sanitize()

	nextRevision := uint64(1)

	c.Assert(repo.GetRevision(), Equals, nextRevision)
	nextRevision++

	// add rule1,rule2
	rev, _, err = repo.Add(rule1)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++
	rev, _, err = repo.Add(rule2)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// rule3 should not be in there yet
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), checker.DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()

	// add rule3
	rev, _, err = repo.Add(rule3)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// search rule1,rule2
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls1), checker.DeepEquals, api.Rules{&rule1, &rule2})
	c.Assert(repo.SearchRLocked(lbls2), checker.DeepEquals, api.Rules{&rule3})
	repo.Mutex.RUnlock()

	// delete rule1, rule2
	rev, n := repo.DeleteByLabels(lbls1)
	c.Assert(n, Equals, 2)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// delete rule1, rule2 again has no effect
	rev, n = repo.DeleteByLabels(lbls1)
	c.Assert(n, Equals, 0)
	c.Assert(rev, Equals, nextRevision-1)

	// rule3 can still be found
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), checker.DeepEquals, api.Rules{&rule3})
	repo.Mutex.RUnlock()

	// delete rule3
	rev, n = repo.DeleteByLabels(lbls2)
	c.Assert(n, Equals, 1)
	c.Assert(rev, Equals, nextRevision)

	// rule1 is gone
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), checker.DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()
}

func BenchmarkParseLabel(b *testing.B) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	b.ResetTimer()
	var err error
	var cntAdd, cntFound int

	lbls := make([]labels.LabelArray, 100)
	for i := 0; i < 100; i++ {
		I := fmt.Sprintf("%d", i)
		lbls[i] = labels.LabelArray{labels.NewLabel("tag3", I, labels.LabelSourceK8s), labels.NewLabel("namespace", "default", labels.LabelSourceK8s)}
	}
	for i := 0; i < b.N; i++ {
		for j := 0; j < 100; j++ {
			J := fmt.Sprintf("%d", j)
			_, _, err = repo.Add(api.Rule{
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

		repo.Mutex.RLock()
		for j := 0; j < 100; j++ {
			cntFound += len(repo.SearchRLocked(lbls[j]))
		}
		repo.Mutex.RUnlock()
	}
	b.Log("Added: ", cntAdd)
	b.Log("found: ", cntFound)
}

func (ds *PolicyTestSuite) TestAllowsIngress(c *C) {
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
		Ingress: []api.IngressRule{
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
		Ingress: []api.IngressRule{
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
		Ingress: []api.IngressRule{
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

	// foo=>bar is OK
	c.Assert(repo.AllowsIngressRLocked(fooToBar), Equals, api.Allowed)

	// foo=>bar2 is OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, api.Allowed)

	// foo=>bar inside groupA is OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Allowed)

	// groupB can't talk to groupA => Denied
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Denied)

	// no restriction on groupB, unused label => OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, api.Allowed)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, api.Denied)
}

func (ds *PolicyTestSuite) TestAllowsEgress(c *C) {
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
		Egress: []api.EgressRule{
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
		Egress: []api.EgressRule{
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
		Egress: []api.EgressRule{
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

	// foo=>bar is OK
	logBuffer := new(bytes.Buffer)
	result := repo.AllowsEgressRLocked(fooToBar.WithLogger(logBuffer))
	if equal, err := checker.DeepEqual(result, api.Allowed); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}

	// foo=>bar2 is OK
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, api.Allowed)

	// foo=>bar inside groupA is OK
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Allowed)

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

	// no restriction on groupB, unused label => OK
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, api.Allowed)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, api.Denied)
}

func (ds *PolicyTestSuite) TestWildcardL3RulesIngress(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsICMP := labels.LabelArray{labels.ParseLabel("icmp")}
	labelsICMPv6 := labels.LabelArray{labels.ParseLabel("icmpv6")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}
	labelsL7 := labels.LabelArray{labels.ParseLabel("l7")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
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

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
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
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule)
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(httpRule)
	c.Assert(err, IsNil)

	l7Rule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(l7Rule)
	c.Assert(err, IsNil)

	icmpRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(icmpRule)
	c.Assert(err, IsNil)

	icmpV6Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: []api.EndpointSelector{selBar2},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type:   128,
						Family: api.IPv6Family,
					}},
				}},
			},
		},
		Labels: labelsICMPv6,
	}
	_, _, err = repo.Add(icmpV6Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedPolicy := L4PolicyMap{
		"0/ANY": {
			Port:     0,
			Protocol: api.ProtoAny,
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: nil,
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL3}},
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: nil,
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsICMP}},
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: nil,
			},
			Ingress:    true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsICMPv6}},
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeKafka,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsKafka}},
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsHTTP}},
		},
		"9090/TCP": {
			Port:     9090,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: L7ParserType("tester"),
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						L7Proto: "tester",
						L7:      []api.PortRuleL7{l7Rule.Ingress[0].ToPorts[0].Rules.L7[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsL7}},
		},
	}
	c.Assert(policy, checker.DeepEquals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL4RulesIngress(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL4Kafka := labels.LabelArray{labels.ParseLabel("L4-kafka")}
	labelsL7Kafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsL4HTTP := labels.LabelArray{labels.ParseLabel("L4-http")}
	labelsL7HTTP := labels.LabelArray{labels.ParseLabel("http")}

	l49092Rule := api.Rule{
		EndpointSelector: selFoo,
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
	l49092Rule.Sanitize()
	_, _, err := repo.Add(l49092Rule)
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
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
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule)
	c.Assert(err, IsNil)

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
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
	l480Rule.Sanitize()
	_, _, err = repo.Add(l480Rule)
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(httpRule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedPolicy := L4PolicyMap{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: nil,
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorBar1: {labelsL4HTTP},
				cachedSelectorBar2: {labelsL7HTTP},
			},
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeKafka,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: nil,
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorBar1: {labelsL4Kafka},
				cachedSelectorBar2: {labelsL7Kafka},
			},
		},
	}
	c.Assert(policy, checker.DeepEquals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestL3DependentL4IngressFromRequires(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
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
	l480Rule.Sanitize()
	_, _, err := repo.Add(l480Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []slim_metav1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: slim_metav1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, nil, expectedSelector)

	expectedPolicy := L4PolicyMap{
		"80/TCP": &L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: nil,
			},
			Ingress: true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				expectedCachedSelector: {nil},
			},
		},
	}
	c.Assert(policy, checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestL3DependentL4EgressFromRequires(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
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
	l480Rule.Sanitize()
	_, _, err := repo.Add(l480Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
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

	expectedPolicy := L4PolicyMap{
		"0/ANY": &L4Filter{
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector2: nil,
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				expectedCachedSelector2: {nil},
			},
		},
		"80/TCP": &L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			PerSelectorPolicies: L7DataMap{
				expectedCachedSelector: nil,
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				expectedCachedSelector: {nil},
			},
		},
	}
	if !c.Check(policy, checker.Equals, expectedPolicy) {
		c.Errorf("Policy doesn't match expected:\n%s", logBuffer.String())
	}
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgress(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL4 := labels.LabelArray{labels.ParseLabel("L4")}
	labelsDNS := labels.LabelArray{labels.ParseLabel("dns")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}
	labelsICMP := labels.LabelArray{labels.ParseLabel("icmp")}
	labelsICMPv6 := labels.LabelArray{labels.ParseLabel("icmpv6")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
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

	dnsRule := api.Rule{
		EndpointSelector: selFoo,
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
	dnsRule.Sanitize()
	_, _, err = repo.Add(dnsRule)
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(httpRule)
	c.Assert(err, IsNil)

	icmpRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(icmpRule)
	c.Assert(err, IsNil)

	icmpV6Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				EgressCommonRule: api.EgressCommonRule{
					ToEndpoints: []api.EndpointSelector{selBar2},
				},
				ICMPs: api.ICMPRules{{
					Fields: []api.ICMPField{{
						Type:   128,
						Family: "IPv6",
					}},
				}},
			},
		},
		Labels: labelsICMPv6,
	}
	_, _, err = repo.Add(icmpV6Rule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	// Traffic to bar1 should not be forwarded to the DNS or HTTP
	// proxy at all, but if it is (e.g., for visibility, the
	// "0/ANY" rule should allow such traffic through.
	expectedPolicy := L4PolicyMap{
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			L7Parser: ParserTypeDNS,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{dnsRule.Egress[0].ToPorts[0].Rules.DNS[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsDNS}},
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsHTTP}},
		},
		"8/ICMP": {
			Port:     8,
			Protocol: api.ProtoICMP,
			U8Proto:  0x1,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: nil,
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsICMP}},
		},
		"128/ICMPV6": {
			Port:     128,
			Protocol: api.ProtoICMPv6,
			U8Proto:  0x3A,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: nil,
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsICMPv6}},
		},
		"0/ANY": {
			Port:     0,
			Protocol: "ANY",
			U8Proto:  0x0,
			L7Parser: "",
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: nil,
			},
			Ingress:    false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar1: {labelsL4}},
		},
	}
	if equal, err := checker.DeepEqual(policy, expectedPolicy); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL4RulesEgress(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL3DNS := labels.LabelArray{labels.ParseLabel("L3-dns")}
	labelsL7DNS := labels.LabelArray{labels.ParseLabel("dns")}
	labelsL3HTTP := labels.LabelArray{labels.ParseLabel("L3-http")}
	labelsL7HTTP := labels.LabelArray{labels.ParseLabel("http")}

	l453Rule := api.Rule{
		EndpointSelector: selFoo,
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
	l453Rule.Sanitize()
	_, _, err := repo.Add(l453Rule)
	c.Assert(err, IsNil)

	dnsRule := api.Rule{
		EndpointSelector: selFoo,
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
	dnsRule.Sanitize()
	_, _, err = repo.Add(dnsRule)
	c.Assert(err, IsNil)

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
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
	l480Rule.Sanitize()
	_, _, err = repo.Add(l480Rule)
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(httpRule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	// Bar1 should not be forwarded to the proxy, but if it is (e.g., for visibility),
	// the L3/L4 allow should pass it without an explicit L7 wildcard.
	expectedPolicy := L4PolicyMap{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: nil,
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorBar1: {labelsL3HTTP},
				cachedSelectorBar2: {labelsL7HTTP},
			},
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			L7Parser: ParserTypeDNS,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar1: nil,
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{dnsRule.Egress[0].ToPorts[0].Rules.DNS[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorBar1: {labelsL3DNS},
				cachedSelectorBar2: {labelsL7DNS},
			},
		},
	}
	if equal, err := checker.DeepEqual(policy, expectedPolicy); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardCIDRRulesEgress(c *C) {
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
	l480Get.Sanitize()
	_, _, err := repo.Add(l480Get)
	c.Assert(err, IsNil)

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
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
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	// Port 80 policy does not need the wildcard, as the "0" port policy will allow the traffic.
	// HTTP rules can have side-effects, so they need to be retained even if shadowed by a wildcard.
	expectedPolicy := L4PolicyMap{
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectors[0]: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{{
							Headers: []string{"X-My-Header: true"},
							Method:  "GET",
							Path:    "/",
						}},
					},
					isRedirect: true,
				},
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
				cachedSelectors[0]: nil,
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectors[0]: {labelsL3}},
		},
	}
	if equal, err := checker.DeepEqual(policy, expectedPolicy); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesIngressFromEntities(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
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

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
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
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule)
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(httpRule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(policy), Equals, 3)
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	c.Assert(len(policy["80/TCP"].PerSelectorPolicies), Equals, 1)
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
				cachedSelectorWorld:   nil,
				cachedSelectorWorldV4: nil,
				cachedSelectorWorldV6: nil,
			},
			Ingress: true,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorWorld:   {labelsL3},
				cachedSelectorWorldV4: {labelsL3},
				cachedSelectorWorldV6: {labelsL3},
			},
		},
		"9092/TCP": {
			Port:     9092,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeKafka,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						Kafka: []kafka.PortRule{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsKafka}},
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  true,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsHTTP}},
		},
	}

	c.Assert(policy, checker.DeepEquals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgressToEntities(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsDNS := labels.LabelArray{labels.ParseLabel("dns")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
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

	dnsRule := api.Rule{
		EndpointSelector: selFoo,
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
	dnsRule.Sanitize()
	_, _, err = repo.Add(dnsRule)
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(httpRule)
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(policy), Equals, 3)
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	c.Assert(len(policy["80/TCP"].PerSelectorPolicies), Equals, 1)
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
				cachedSelectorWorld:   nil,
				cachedSelectorWorldV4: nil,
				cachedSelectorWorldV6: nil,
			},
			Ingress: false,
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{
				cachedSelectorWorld:   {labelsL3},
				cachedSelectorWorldV4: {labelsL3},
				cachedSelectorWorldV6: {labelsL3},
			},
		},
		"53/UDP": {
			Port:     53,
			Protocol: api.ProtoUDP,
			U8Proto:  0x11,
			L7Parser: ParserTypeDNS,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						DNS: []api.PortRuleDNS{dnsRule.Egress[0].ToPorts[0].Rules.DNS[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsDNS}},
		},
		"80/TCP": {
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			L7Parser: ParserTypeHTTP,
			Ingress:  false,
			PerSelectorPolicies: L7DataMap{
				cachedSelectorBar2: &PerSelectorPolicy{
					L7Rules: api.L7Rules{
						HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
					},
					isRedirect: true,
				},
			},
			RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorBar2: {labelsHTTP}},
		},
	}

	c.Assert(policy, checker.DeepEquals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestMinikubeGettingStarted(c *C) {
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
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: selectorFromApp2,
				},
				ToPorts: []api.PortRule{{
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
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: selectorFromApp2,
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
	})
	c.Assert(err, IsNil)

	_, _, err = repo.Add(api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		Ingress: []api.IngressRule{
			{
				IngressCommonRule: api.IngressCommonRule{
					FromEndpoints: selectorFromApp2,
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
	})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	logBuffer := new(bytes.Buffer)
	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(fromApp2.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	cachedSelectorApp2 := testSelectorCache.FindCachedIdentitySelector(selFromApp2)
	c.Assert(cachedSelectorApp2, Not(IsNil))

	expected := NewL4Policy(repo.GetRevision())
	expected.Ingress.PortRules["80/TCP"] = &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		L7Parser: ParserTypeHTTP,
		PerSelectorPolicies: L7DataMap{
			cachedSelectorApp2: &PerSelectorPolicy{
				L7Rules: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{Method: "GET", Path: "/"}, {}},
				},
				isRedirect: true,
			},
		},
		Ingress:    true,
		RuleOrigin: map[CachedSelector]labels.LabelArrayList{cachedSelectorApp2: {nil}},
	}

	if equal, err := checker.DeepEqual(l4IngressPolicy, expected.Ingress.PortRules); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	l4IngressPolicy.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	// L4 from app3 has no rules
	expected = NewL4Policy(repo.GetRevision())
	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(fromApp3)
	c.Assert(err, IsNil)
	c.Assert(len(l4IngressPolicy), Equals, 0)
	c.Assert(l4IngressPolicy, checker.Equals, expected.Ingress.PortRules)
	l4IngressPolicy.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)
}

func buildSearchCtx(from, to string, port uint16) *SearchContext {
	ports := []*models.Port{{Port: port, Protocol: string(api.ProtoAny)}}
	return &SearchContext{
		From:   labels.ParseSelectLabelArray(from),
		To:     labels.ParseSelectLabelArray(to),
		DPorts: ports,
		Trace:  TRACE_ENABLED,
	}
}

func buildRule(from, to, port string) api.Rule {
	reservedES := api.NewESFromLabels(labels.ParseSelectLabel("reserved:host"))
	fromES := api.NewESFromLabels(labels.ParseSelectLabel(from))
	toES := api.NewESFromLabels(labels.ParseSelectLabel(to))

	ports := []api.PortRule{}
	if port != "" {
		ports = []api.PortRule{
			{Ports: []api.PortProtocol{{Port: port}}},
		}
	}
	return api.Rule{
		EndpointSelector: toES,
		Ingress: []api.IngressRule{
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

func (repo *Repository) checkTrace(c *C, ctx *SearchContext, trace string,
	expectedVerdict api.Decision) {

	buffer := new(bytes.Buffer)
	ctx.Logging = stdlog.New(buffer, "", 0)

	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()

	expectedOut := "Tracing " + ctx.String() + "\n" + trace
	c.Assert(buffer.String(), checker.DeepEquals, expectedOut)
	c.Assert(verdict, Equals, expectedVerdict)
}

func (ds *PolicyTestSuite) TestPolicyTrace(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	// Add rules to allow foo=>bar
	l3rule := buildRule("foo", "bar", "")
	rules := api.Rules{&l3rule}
	_, _ = repo.AddList(rules)

	// foo=>bar is OK
	expectedOut := `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
    Allows from labels {"matchLabels":{"any:foo":""}}
      Found all required labels
1/1 rules selected
Found allow rule
Found no deny rule
Ingress verdict: allowed
`
	ctx := buildSearchCtx("foo", "bar", 0)
	repo.checkTrace(c, ctx, expectedOut, api.Allowed)

	// foo=>bar:80 is OK
	ctx = buildSearchCtx("foo", "bar", 80)
	repo.checkTrace(c, ctx, expectedOut, api.Allowed)

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
	l4rule := buildRule("baz", "bar", "80")
	_, _, err := repo.Add(l4rule)
	c.Assert(err, IsNil)

	// baz=>bar:80 is OK
	ctx = buildSearchCtx("baz", "bar", 80)
	expectedOut = `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
    Allows from labels {"matchLabels":{"any:foo":""}}
      No label match for [any:baz]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
    Allows from labels {"matchLabels":{"any:baz":""}}
      Found all required labels
      Allows port [{80 ANY}]
2/2 rules selected
Found allow rule
Found no deny rule
Ingress verdict: allowed
`
	repo.checkTrace(c, ctx, expectedOut, api.Allowed)

	// bar=>bar:80 is Denied
	ctx = buildSearchCtx("bar", "bar", 80)
	expectedOut = `
Resolving ingress policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
    Allows from labels {"matchLabels":{"any:foo":""}}
      No label match for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
    Allows from labels {"matchLabels":{"any:baz":""}}
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
		Ingress: []api.IngressRule{{
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
    Allows from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Allows from labels {"matchLabels":{"any:foo":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      No label match for [any:foo]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Enforcing requirements [{Key:any.baz Operator:In Values:[]}]
    Allows from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Allows from labels {"matchLabels":{"any:baz":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
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
    Allows from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Allows from labels {"matchLabels":{"any:foo":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      No label match for [any:baz]
* Rule {"matchLabels":{"any:bar":""}}: selected
    Enforcing requirements [{Key:any.baz Operator:In Values:[]}]
    Allows from labels {"matchLabels":{"reserved:host":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
    Allows from labels {"matchLabels":{"any:baz":""},"matchExpressions":[{"key":"any:baz","operator":"In","values":[""]}]}
      Found all required labels
      Allows port [{80 ANY}]
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
	c.Assert(verdict, Equals, api.Allowed)
}

func (ds *PolicyTestSuite) TestremoveIdentityFromRuleCaches(c *C) {

	testRepo := parseAndAddRules(c, api.Rules{&api.Rule{
		EndpointSelector: endpointSelectorA,
		Ingress: []api.IngressRule{
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

func (ds *PolicyTestSuite) TestIterate(c *C) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	numWithEgress := 0
	countEgressRules := func(r *api.Rule) {
		if len(r.Egress) > 0 {
			numWithEgress++
		}
	}
	repo.Iterate(countEgressRules)

	c.Assert(numWithEgress, Equals, 0)

	numRules := 10
	lbls := make([]labels.Label, 10)
	for i := 0; i < numRules; i++ {
		it := fmt.Sprintf("baz%d", i)
		epSelector := api.NewESFromLabels(
			labels.NewLabel(
				"foo",
				it,
				labels.LabelSourceK8s,
			),
		)
		lbls[i] = labels.NewLabel("tag3", it, labels.LabelSourceK8s)
		_, _, err := repo.Add(api.Rule{
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
		c.Assert(err, IsNil)
	}

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	c.Assert(numWithEgress, Equals, numRules)

	numModified := 0
	modifyRules := func(r *api.Rule) {
		if r.Labels.Contains(labels.LabelArray{lbls[1]}) || r.Labels.Contains(labels.LabelArray{lbls[3]}) {
			r.Egress = nil
			numModified++
		}
	}

	repo.Iterate(modifyRules)

	c.Assert(numModified, Equals, 2)

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	c.Assert(numWithEgress, Equals, numRules-numModified)

	repo.Mutex.Lock()
	_, _, numDeleted := repo.DeleteByLabelsLocked(labels.LabelArray{lbls[0]})
	repo.Mutex.Unlock()
	c.Assert(numDeleted, Equals, 1)

	numWithEgress = 0
	repo.Iterate(countEgressRules)

	c.Assert(numWithEgress, Equals, numRules-numModified-numDeleted)
}

// TestDefaultAllow covers the defaulting logic in determining an identity's default rule
// in the presence or absence of rules that do not enable default-deny mode.
func (ds *PolicyTestSuite) TestDefaultAllow(c *C) {

	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	fooSelectLabel := labels.ParseSelectLabel("foo")
	fooNumericIdentity := 9001
	fooIdentity := identity.NewIdentity(identity.NumericIdentity(fooNumericIdentity), lbls)

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
		c.Assert(r.Sanitize(), IsNil)
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
		repo := NewPolicyRepository(nil, nil, nil, nil)
		repo.selectorCache = testSelectorCache

		for _, rule := range tc.rules {
			_, _, err := repo.Add(rule)
			c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
		}

		ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
		c.Assert(ing, Equals, tc.ingress, Commentf("case %d: ingress should match", i))
		c.Assert(egr, Equals, tc.egress, Commentf("case %d: egress should match", i))
		c.Assert(len(matchingRules), Equals, tc.ruleC, Commentf("case %d: rule count should match", i))
	}

	for i, tc := range egressCases {
		repo := NewPolicyRepository(nil, nil, nil, nil)
		repo.selectorCache = testSelectorCache

		for _, rule := range tc.rules {
			_, _, err := repo.Add(rule)
			c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
		}

		ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
		c.Assert(ing, Equals, tc.ingress, Commentf("case %d: ingress should match", i))
		c.Assert(egr, Equals, tc.egress, Commentf("case %d: egress should match", i))
		c.Assert(len(matchingRules), Equals, tc.ruleC, Commentf("case %d: rule count should match", i))
	}

	// test all combinations of ingress + egress cases
	for e, etc := range egressCases {
		for i, itc := range ingressCases {
			repo := NewPolicyRepository(nil, nil, nil, nil)
			repo.selectorCache = testSelectorCache

			for _, rule := range etc.rules {
				_, _, err := repo.Add(rule)
				c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
			}

			for _, rule := range itc.rules {
				_, _, err := repo.Add(rule)
				c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
			}

			ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
			c.Assert(ing, Equals, itc.ingress, Commentf("case ingress %d + egress %d: ingress should match", i, e))
			c.Assert(egr, Equals, etc.egress, Commentf("case ingress %d + egress %d: egress should match", i, e))
			c.Assert(len(matchingRules), Equals, itc.ruleC+etc.ruleC, Commentf("case ingress %d + egress %d: rule count should match", i, e))
		}
	}
}
