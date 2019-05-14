// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !privileged_tests

package policy

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/checker"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/op/go-logging"
	. "gopkg.in/check.v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (ds *PolicyTestSuite) TestComputePolicyEnforcementAndRules(c *C) {

	// Cache policy enforcement value from when test was ran to avoid pollution
	// across tests.
	oldPolicyEnable := GetPolicyEnabled()
	defer SetPolicyEnabled(oldPolicyEnable)

	SetPolicyEnabled(option.DefaultEnforcement)

	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	fooSelectLabel := labels.ParseSelectLabel("foo")
	fooNumericIdentity := 9001
	fooIdentity := identity.NewIdentity(identity.NumericIdentity(fooNumericIdentity), lbls)
	fooIngressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule1", labels.LabelSourceAny)
	fooIngressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule2", labels.LabelSourceAny)
	fooEgressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule1", labels.LabelSourceAny)
	fooEgressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule2", labels.LabelSourceAny)
	combinedLabel := labels.NewLabel(k8sConst.PolicyLabelName, "combined", labels.LabelSourceAny)
	initIdentity := identity.ReservedIdentityCache[identity.ReservedIdentityInit]

	fooIngressRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(fooSelectLabel),
				},
			},
		},
		Labels: labels.LabelArray{
			fooIngressRule1Label,
		},
	}

	fooIngressRule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(fooSelectLabel),
				},
			},
		},
		Labels: labels.LabelArray{
			fooIngressRule2Label,
		},
	}

	fooEgressRule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(fooSelectLabel),
				},
			},
		},
		Labels: labels.LabelArray{
			fooEgressRule1Label,
		},
	}

	fooEgressRule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(fooSelectLabel),
				},
			},
		},
		Labels: labels.LabelArray{
			fooEgressRule2Label,
		},
	}

	combinedRule := api.Rule{
		EndpointSelector: api.NewESFromLabels(fooSelectLabel),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(fooSelectLabel),
				},
			},
		},
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(fooSelectLabel),
				},
			},
		},
		Labels: labels.LabelArray{
			combinedLabel,
		},
	}

	ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no rules are in repository"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err := repo.Add(fooIngressRule1, []Endpoint{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooIngressRule1, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooIngressRule2, []Endpoint{})
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

	_, _, err = repo.Add(fooEgressRule1, []Endpoint{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no ingress rules select"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooEgressRule1, Commentf("returned matching rules did not match"))
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule1Label})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(fooEgressRule2, []Endpoint{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no ingress rules select"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules select"))
	c.Assert(matchingRules[0].Rule, checker.DeepEquals, fooEgressRule2, Commentf("returned matching rules did not match"))

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule2Label})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(combinedRule, []Endpoint{})
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
	_, _, err = repo.Add(combinedRule, []Endpoint{})
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
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	// cannot add empty rule
	rev, _, err := repo.Add(api.Rule{}, []Endpoint{})
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
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls1,
	}
	lbls2 := labels.LabelArray{labels.ParseSelectLabel("tag3")}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls2,
	}

	nextRevision := uint64(1)

	c.Assert(repo.GetRevision(), Equals, nextRevision)
	nextRevision++

	// add rule1,rule2
	rev, _, err = repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++
	rev, _, err = repo.Add(rule2, []Endpoint{})
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// rule3 should not be in there yet
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), checker.DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()

	// add rule3
	rev, _, err = repo.Add(rule3, []Endpoint{})
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
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	b.ResetTimer()
	var err error
	var cntAdd, cntFound int

	lbls := make([]labels.LabelArray, 100, 100)
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
			}, []Endpoint{})
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
	repo := NewPolicyRepository()
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
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("foo")),
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
				FromRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
				},
			},
		},
		Labels: tag1,
	}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar2")),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("foo")),
				},
			},
		},
		Labels: tag1,
	}

	_, _, err := repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule2, []Endpoint{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule3, []Endpoint{})
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
	repo := NewPolicyRepository()
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
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("bar")),
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
				ToRequires: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("groupA")),
				},
			},
		},
		Labels: tag1,
	}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{
					api.NewESFromLabels(labels.ParseSelectLabel("bar2")),
				},
			},
		},
		Labels: tag1,
	}
	_, _, err := repo.Add(rule1, []Endpoint{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule2, []Endpoint{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule3, []Endpoint{})
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
		Logging: logging.NewLogBackend(buffer, "", 0),
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
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}
	labelsL7 := labels.LabelArray{labels.ParseLabel("l7")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar1},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err := repo.Add(l3Rule, []Endpoint{})
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule, []Endpoint{})
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(httpRule, []Endpoint{})
	c.Assert(err, IsNil)

	l7Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(l7Rule, []Endpoint{})
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
			Port:             0,
			Protocol:         api.ProtoAny,
			U8Proto:          0x0,
			CachedSelectors:  CachedSelectorSlice{cachedSelectorBar1},
			L7RulesPerEp:     L7DataMap{},
			Ingress:          true,
			DerivedFromRules: labels.LabelArrayList{labelsL3},
		},
		"9092/TCP": {
			Port:            9092,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorBar1},
			L7Parser:        ParserTypeKafka,
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
				},
				cachedSelectorBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL3},
		},
		"80/TCP": {
			Port:            80,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorBar1},
			L7Parser:        ParserTypeHTTP,
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
				},
				cachedSelectorBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL3},
		},
		"9090/TCP": {
			Port:            9090,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorBar1},
			L7Parser:        L7ParserType("tester"),
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar2: api.L7Rules{
					L7Proto: "tester",
					L7:      []api.PortRuleL7{l7Rule.Ingress[0].ToPorts[0].Rules.L7[0]},
				},
				cachedSelectorBar1: api.L7Rules{
					L7Proto: "tester",
					L7:      []api.PortRuleL7{},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL7, labelsL3},
		},
	}
	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL4RulesIngress(c *C) {
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL4 := labels.LabelArray{labels.ParseLabel("L4")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l49092Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar1},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL4,
	}
	l49092Rule.Sanitize()
	_, _, err := repo.Add(l49092Rule, []Endpoint{})
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule, []Endpoint{})
	c.Assert(err, IsNil)

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar1},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL4,
	}
	l480Rule.Sanitize()
	_, _, err = repo.Add(l480Rule, []Endpoint{})
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(httpRule, []Endpoint{})
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
			Port:            80,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar1, cachedSelectorBar2},
			L7Parser:        ParserTypeHTTP,
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL4, labelsHTTP, labelsL4},
		},
		"9092/TCP": {
			Port:            9092,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar1, cachedSelectorBar2},
			L7Parser:        ParserTypeKafka,
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL4, labelsKafka, labelsL4},
		},
	}
	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestL3DependentL4IngressFromRequires(c *C) {
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{
					selBar1,
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				FromRequires: []api.EndpointSelector{selBar2},
			},
		},
	}
	l480Rule.Sanitize()
	_, _, err := repo.Add(l480Rule, []Endpoint{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []v1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: v1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, expectedSelector)

	expectedPolicy := L4PolicyMap{
		"80/TCP": &L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			CachedSelectors: CachedSelectorSlice{
				expectedCachedSelector,
			},
			L7RulesPerEp:     L7DataMap{},
			Ingress:          true,
			DerivedFromRules: labels.LabelArrayList{nil},
		},
	}
	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestL3DependentL4EgressFromRequires(c *C) {
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{
					selBar1,
				},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
			{
				ToEndpoints: []api.EndpointSelector{
					api.WildcardEndpointSelector,
				},
				ToRequires: []api.EndpointSelector{selBar2},
			},
		},
	}
	l480Rule.Sanitize()
	_, _, err := repo.Add(l480Rule, []Endpoint{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []v1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: v1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedSelector2 := api.NewESFromMatchRequirements(map[string]string{}, []v1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: v1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})
	expectedCachedSelector, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, expectedSelector)
	expectedCachedSelector2, _ := testSelectorCache.AddIdentitySelector(dummySelectorCacheUser, expectedSelector2)

	expectedPolicy := L4PolicyMap{
		"0/ANY": &L4Filter{
			Port:          0,
			Protocol:      "ANY",
			U8Proto:       0x0,
			allowsAllAtL3: false,
			CachedSelectors: CachedSelectorSlice{
				expectedCachedSelector2,
			},
			L7RulesPerEp:     L7DataMap{},
			DerivedFromRules: labels.LabelArrayList{nil},
		},
		"80/TCP": &L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			CachedSelectors: CachedSelectorSlice{
				expectedCachedSelector,
			},
			L7RulesPerEp:     L7DataMap{},
			DerivedFromRules: labels.LabelArrayList{nil},
		},
	}
	if !c.Check((*policy), checker.Equals, expectedPolicy) {
		c.Errorf("Policy doesn't match expected:\n%s", logBuffer.String())
	}
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgress(c *C) {
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL4 := labels.LabelArray{labels.ParseLabel("L4")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar1},
			},
		},
		Labels: labelsL4,
	}
	l3Rule.Sanitize()
	_, _, err := repo.Add(l3Rule, []Endpoint{})
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar2},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule, []Endpoint{})
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(httpRule, []Endpoint{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedPolicy := L4PolicyMap{
		"9092/TCP": {
			Port:            9092,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorBar1},
			L7Parser:        ParserTypeKafka,
			Ingress:         false,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Egress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL4},
		},
		"80/TCP": {
			Port:            80,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorBar1},
			L7Parser:        ParserTypeHTTP,
			Ingress:         false,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL4},
		},
		"0/ANY": {
			Port:             0,
			Protocol:         "ANY",
			U8Proto:          0x0,
			allowsAllAtL3:    false,
			CachedSelectors:  CachedSelectorSlice{cachedSelectorBar1},
			L7Parser:         "",
			L7RulesPerEp:     L7DataMap{},
			Ingress:          false,
			DerivedFromRules: labels.LabelArrayList{labelsL4},
		},
	}
	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL4RulesEgress(c *C) {
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l49092Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar1},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL3,
	}
	l49092Rule.Sanitize()
	_, _, err := repo.Add(l49092Rule, []Endpoint{})
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar2},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule, []Endpoint{})
	c.Assert(err, IsNil)

	l480Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar1},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
		Labels: labelsL3,
	}
	l480Rule.Sanitize()
	_, _, err = repo.Add(l480Rule, []Endpoint{})
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(httpRule, []Endpoint{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedPolicy := L4PolicyMap{
		"80/TCP": {
			Port:            80,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar1, cachedSelectorBar2},
			L7Parser:        ParserTypeHTTP,
			Ingress:         false,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL3, labelsHTTP, labelsL3},
		},
		"9092/TCP": {
			Port:            9092,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar1, cachedSelectorBar2},
			L7Parser:        ParserTypeKafka,
			Ingress:         false,
			L7RulesPerEp: L7DataMap{
				cachedSelectorBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Egress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL3, labelsKafka, labelsL3},
		},
	}
	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesIngressFromEntities(c *C) {
	repo := NewPolicyRepository()
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
				FromEntities: api.EntitySlice{api.EntityWorld},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err := repo.Add(l3Rule, []Endpoint{})
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule, []Endpoint{})
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
		Ingress: []api.IngressRule{
			{
				FromEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(httpRule, []Endpoint{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(*policy), Equals, 3)
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	c.Assert(len((*policy)["80/TCP"].CachedSelectors), Equals, 2)
	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(selWorld)
	c.Assert(cachedSelectorWorld, Not(IsNil))

	expectedPolicy := L4PolicyMap{
		"0/ANY": {
			Port:             0,
			Protocol:         "ANY",
			U8Proto:          0x0,
			allowsAllAtL3:    false,
			CachedSelectors:  CachedSelectorSlice{cachedSelectorWorld},
			L7Parser:         "",
			L7RulesPerEp:     L7DataMap{},
			Ingress:          true,
			DerivedFromRules: labels.LabelArrayList{labelsL3},
		},
		"9092/TCP": {
			Port:            9092,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorWorld},
			L7Parser:        ParserTypeKafka,
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorWorld: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL3},
		},
		"80/TCP": {
			Port:            80,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorWorld},
			L7Parser:        ParserTypeHTTP,
			Ingress:         true,
			L7RulesPerEp: L7DataMap{
				cachedSelectorWorld: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL3},
		},
	}

	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgressToEntities(c *C) {
	repo := NewPolicyRepository()
	repo.selectorCache = testSelectorCache

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

	labelsL3 := labels.LabelArray{labels.ParseLabel("L3")}
	labelsKafka := labels.LabelArray{labels.ParseLabel("kafka")}
	labelsHTTP := labels.LabelArray{labels.ParseLabel("http")}

	l3Rule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEntities: api.EntitySlice{api.EntityWorld},
			},
		},
		Labels: labelsL3,
	}
	l3Rule.Sanitize()
	_, _, err := repo.Add(l3Rule, []Endpoint{})
	c.Assert(err, IsNil)

	kafkaRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar2},
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "9092", Protocol: api.ProtoTCP},
					},
					Rules: &api.L7Rules{
						Kafka: []api.PortRuleKafka{
							{APIKey: "produce"},
						},
					},
				}},
			},
		},
		Labels: labelsKafka,
	}
	kafkaRule.Sanitize()
	_, _, err = repo.Add(kafkaRule, []Endpoint{})
	c.Assert(err, IsNil)

	httpRule := api.Rule{
		EndpointSelector: selFoo,
		Egress: []api.EgressRule{
			{
				ToEndpoints: []api.EndpointSelector{selBar2},
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
	_, _, err = repo.Add(httpRule, []Endpoint{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(*policy), Equals, 3)
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	c.Assert(len((*policy)["80/TCP"].CachedSelectors), Equals, 2)
	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(selWorld)
	c.Assert(cachedSelectorWorld, Not(IsNil))

	expectedPolicy := L4PolicyMap{
		"0/ANY": {
			Port:             0,
			Protocol:         "ANY",
			U8Proto:          0x0,
			allowsAllAtL3:    false,
			CachedSelectors:  CachedSelectorSlice{cachedSelectorWorld},
			L7Parser:         "",
			L7RulesPerEp:     L7DataMap{},
			Ingress:          false,
			DerivedFromRules: labels.LabelArrayList{labelsL3},
		},
		"9092/TCP": {
			Port:            9092,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorWorld},
			L7Parser:        ParserTypeKafka,
			Ingress:         false,
			L7RulesPerEp: L7DataMap{
				cachedSelectorWorld: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Egress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL3},
		},
		"80/TCP": {
			Port:            80,
			Protocol:        api.ProtoTCP,
			U8Proto:         0x6,
			CachedSelectors: CachedSelectorSlice{cachedSelectorBar2, cachedSelectorWorld},
			L7Parser:        ParserTypeHTTP,
			Ingress:         false,
			L7RulesPerEp: L7DataMap{
				cachedSelectorWorld: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				cachedSelectorBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL3},
		},
	}

	c.Assert((*policy), checker.Equals, expectedPolicy)
	policy.Detach(repo.GetSelectorCache())
}

func (ds *PolicyTestSuite) TestMinikubeGettingStarted(c *C) {
	repo := NewPolicyRepository()
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
				FromEndpoints: selectorFromApp2,
				ToPorts: []api.PortRule{{
					Ports: []api.PortProtocol{
						{Port: "80", Protocol: api.ProtoTCP},
					},
				}},
			},
		},
	}, []Endpoint{})
	c.Assert(err, IsNil)

	_, _, err = repo.Add(api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: selectorFromApp2,
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
	}, []Endpoint{})
	c.Assert(err, IsNil)

	_, _, err = repo.Add(api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		Ingress: []api.IngressRule{
			{
				FromEndpoints: selectorFromApp2,
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
	}, []Endpoint{})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	logBuffer := new(bytes.Buffer)
	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(fromApp2.WithLogger(logBuffer))
	c.Assert(err, IsNil)

	cachedSelectorApp2 := testSelectorCache.FindCachedIdentitySelector(selFromApp2)
	c.Assert(cachedSelectorApp2, Not(IsNil))

	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = &L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		CachedSelectors: CachedSelectorSlice{cachedSelectorApp2},
		L7Parser:        ParserTypeHTTP,
		L7RulesPerEp: L7DataMap{
			cachedSelectorApp2: api.L7Rules{
				HTTP: []api.PortRuleHTTP{{}},
			},
		},
		Ingress:          true,
		DerivedFromRules: []labels.LabelArray{nil, nil, nil, nil},
	}
	expected.Revision = repo.GetRevision()

	if equal, err := checker.Equal(*l4IngressPolicy, expected.Ingress); !equal {
		c.Logf("%s", logBuffer.String())
		c.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	l4IngressPolicy.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	// L4 from app3 has no rules
	expected = NewL4Policy()
	expected.Revision = repo.GetRevision()
	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(fromApp3)
	c.Assert(err, IsNil)
	c.Assert(len(*l4IngressPolicy), Equals, 0)
	c.Assert(*l4IngressPolicy, checker.Equals, expected.Ingress)
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
				FromEndpoints: []api.EndpointSelector{
					reservedES,
					fromES,
				},
				ToPorts: ports,
			},
		},
	}
}

func (repo *Repository) checkTrace(c *C, ctx *SearchContext, trace string,
	expectedVerdict api.Decision) {

	buffer := new(bytes.Buffer)
	ctx.Logging = logging.NewLogBackend(buffer, "", 0)

	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()

	expectedOut := "Tracing " + ctx.String() + "\n" + trace
	c.Assert(buffer.String(), checker.DeepEquals, expectedOut)
	c.Assert(verdict, Equals, expectedVerdict)
}

func (ds *PolicyTestSuite) TestPolicyTrace(c *C) {
	repo := NewPolicyRepository()
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
Ingress verdict: denied
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// bar=>foo:80 is also Denied by the same logic
	ctx = buildSearchCtx("bar", "foo", 80)
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Now, add extra rules to allow specifically baz=>bar on port 80
	l4rule := buildRule("baz", "bar", "80")
	_, _, err := repo.Add(l4rule, []Endpoint{})
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
Ingress verdict: denied
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Test that FromRequires "baz" drops "foo" traffic
	l3rule = api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []api.IngressRule{{
			FromRequires: []api.EndpointSelector{
				api.NewESFromLabels(labels.ParseSelectLabel("baz")),
			},
		}},
	}
	_, _, err = repo.Add(l3rule, []Endpoint{})
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
				FromEndpoints: []api.EndpointSelector{endpointSelectorC},
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
