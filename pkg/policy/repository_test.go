// Copyright 2016-2017 Authors of Cilium
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

	fooSelectLabel := labels.ParseSelectLabel("foo")
	fooLabelArray := labels.LabelArray{fooSelectLabel}
	fooIngressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule1", labels.LabelSourceAny)
	fooIngressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooIngressRule2", labels.LabelSourceAny)
	fooEgressRule1Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule1", labels.LabelSourceAny)
	fooEgressRule2Label := labels.NewLabel(k8sConst.PolicyLabelName, "fooEgressRule2", labels.LabelSourceAny)
	combinedLabel := labels.NewLabel(k8sConst.PolicyLabelName, "combined", labels.LabelSourceAny)

	initSelectLabel := labels.ParseSelectLabel("reserved:init")
	initLabelArray := labels.LabelArray{initSelectLabel}

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

	convertedFooIngressRule1 := &rule{Rule: fooIngressRule1}
	convertedFooIngressRule2 := &rule{Rule: fooIngressRule2}
	convertedFooEgressRule1 := &rule{Rule: fooEgressRule1}
	convertedFooEgressRule2 := &rule{Rule: fooEgressRule2}
	convertedCombinedRule := &rule{Rule: combinedRule}

	ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no rules are in repository"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err := repo.Add(fooIngressRule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{convertedFooIngressRule1}, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooIngressRule2, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{convertedFooIngressRule1, convertedFooIngressRule2}, Commentf("returned matching rules did not match"))

	_, numDeleted := repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressRule1Label}, map[uint16]*identity.Identity{}, map[uint16]struct{}{})
	c.Assert(numDeleted, Equals, 1)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no egress rules select"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{convertedFooIngressRule2}, Commentf("returned matching rules did not match"))

	_, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressRule2Label}, map[uint16]*identity.Identity{}, map[uint16]struct{}{})
	c.Assert(numDeleted, Equals, 1)

	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no rules are in repository"))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since no rules are in repository"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	_, _, err = repo.Add(fooEgressRule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no ingress rules select"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules select"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{convertedFooEgressRule1}, Commentf("returned matching rules did not match"))
	_, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule1Label}, map[uint16]*identity.Identity{}, map[uint16]struct{}{})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(fooEgressRule2, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since no ingress rules select"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules select"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{convertedFooEgressRule2}, Commentf("returned matching rules did not match"))

	_, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule2Label}, map[uint16]*identity.Identity{}, map[uint16]struct{}{})
	c.Assert(numDeleted, Equals, 1)

	_, _, err = repo.Add(combinedRule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules selects"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{convertedCombinedRule}, Commentf("returned matching rules did not match"))
	_, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{combinedLabel}, map[uint16]*identity.Identity{}, map[uint16]struct{}{})
	c.Assert(numDeleted, Equals, 1)

	SetPolicyEnabled(option.AlwaysEnforce)
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, true, Commentf("ingress policy enforcement should apply since ingress rule selects"))
	c.Assert(egr, Equals, true, Commentf("egress policy enforcement should apply since egress rules selects"))
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("returned matching rules did not match"))

	SetPolicyEnabled(option.NeverEnforce)
	_, _, err = repo.Add(combinedRule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil, Commentf("unable to add rule to policy repository"))
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooLabelArray)
	c.Assert(ing, Equals, false, Commentf("ingress policy enforcement should not apply since policy enforcement is disabled "))
	c.Assert(egr, Equals, false, Commentf("egress policy enforcement should not apply since policy enforcement is disabled"))
	c.Assert(matchingRules, IsNil, Commentf("no rules should be returned since policy enforcement is disabled"))

	// Test init identity.

	SetPolicyEnabled(option.DefaultEnforcement)
	// If the mode is "default", check that the policy is always enforced for
	// endpoints with the reserved:init label. If no policy rules match
	// reserved:init, this drops all ingress and egress traffic.
	ingress, egress, matchingRules := repo.computePolicyEnforcementAndRules(initLabelArray)
	c.Assert(ingress, Equals, true)
	c.Assert(egress, Equals, true)
	c.Assert(matchingRules, checker.DeepEquals, ruleSlice{}, Commentf("no rules should be returned since policy enforcement is disabled"))

	// Check that the "always" and "never" modes are not affected.
	SetPolicyEnabled(option.AlwaysEnforce)
	ingress, egress, _ = repo.computePolicyEnforcementAndRules(initLabelArray)
	c.Assert(ingress, Equals, true)
	c.Assert(egress, Equals, true)

	SetPolicyEnabled(option.NeverEnforce)
	ingress, egress, _ = repo.computePolicyEnforcementAndRules(initLabelArray)
	c.Assert(ingress, Equals, false)
	c.Assert(egress, Equals, false)

}

func (ds *PolicyTestSuite) TestAddSearchDelete(c *C) {
	repo := NewPolicyRepository()

	// cannot add empty rule
	rev, _, err := repo.Add(api.Rule{}, map[uint16]*identity.Identity{})
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
	rev, _, err = repo.Add(rule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++
	rev, _, err = repo.Add(rule2, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// rule3 should not be in there yet
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), checker.DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()

	// add rule3
	rev, _, err = repo.Add(rule3, map[uint16]*identity.Identity{})
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
			}, map[uint16]*identity.Identity{})
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

func (ds *PolicyTestSuite) TestContainsAllRLocked(c *C) {
	a := []labels.LabelArray{
		{
			labels.NewLabel("1", "1", "1"),
			labels.NewLabel("2", "2", "1"),
			labels.NewLabel("3", "3", "1"),
		},
		{
			labels.NewLabel("4", "4", "1"),
			labels.NewLabel("5", "5", "1"),
			labels.NewLabel("6", "6", "1"),
		},
		{
			labels.NewLabel("7", "7", "1"),
			labels.NewLabel("8", "8", "1"),
			labels.NewLabel("9", "9", "1"),
		},
	}
	rule1 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Labels:           a[0],
	}
	rule2 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           a[1],
	}
	rule3 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           a[2],
	}
	repoA := NewPolicyRepository()
	_, _, err := repoA.Add(rule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repoA.Add(rule2, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repoA.Add(rule3, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	b := []labels.LabelArray{
		{
			labels.NewLabel("1", "1", "1"),
			labels.NewLabel("2", "2", "1"),
			labels.NewLabel("3", "3", "1"),
		},
		{
			labels.NewLabel("4", "4", "1"),
			labels.NewLabel("5", "5", "1"),
			labels.NewLabel("6", "6", "1"),
		},
	}
	rule4 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Labels:           b[0],
	}
	rule5 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           b[1],
	}
	repoB := NewPolicyRepository()
	_, _, err = repoB.Add(rule4, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repoB.Add(rule5, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	var empty []labels.LabelArray
	rule6 := api.Rule{
		EndpointSelector: api.NewESFromLabels(labels.ParseSelectLabel("bar")),
	}
	repoEmpty := NewPolicyRepository()
	_, _, err = repoEmpty.Add(rule6, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	c.Assert(repoA.ContainsAllRLocked(b), Equals, true)         // b is in a
	c.Assert(repoB.ContainsAllRLocked(a), Equals, false)        // a is NOT in b
	c.Assert(repoA.ContainsAllRLocked(empty), Equals, true)     // empty is in a
	c.Assert(repoEmpty.ContainsAllRLocked(empty), Equals, true) // empty is in b
	c.Assert(repoEmpty.ContainsAllRLocked(a), Equals, false)    // a is NOT in empty
}

func (ds *PolicyTestSuite) TestCanReachIngress(c *C) {
	repo := NewPolicyRepository()

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: CanReach => undecided
	c.Assert(repo.CanReachIngressRLocked(fooToBar), Equals, api.Undecided)
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

	_, _, err := repo.Add(rule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule2, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule3, map[uint16]*identity.Identity{})
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

func (ds *PolicyTestSuite) TestCanReachEgress(c *C) {
	repo := NewPolicyRepository()

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: CanReach => undecided
	c.Assert(repo.CanReachEgressRLocked(fooToBar), Equals, api.Undecided)
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
	_, _, err := repo.Add(rule1, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule2, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)
	_, _, err = repo.Add(rule3, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	// foo=>bar is OK
	c.Assert(repo.AllowsEgressRLocked(fooToBar), Equals, api.Allowed)

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

	selFoo := api.NewESFromLabels(labels.ParseSelectLabel("id=foo"))
	selBar1 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar1"))
	selBar2 := api.NewESFromLabels(labels.ParseSelectLabel("id=bar2"))

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
	_, _, err := repo.Add(l3Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(kafkaRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(httpRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(l7Rule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedPolicy := L4PolicyMap{
		"9092/TCP": {
			Port:      9092,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selBar1},
			L7Parser:  ParserTypeKafka,
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
				},
				selBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL3},
		},
		"80/TCP": {
			Port:      80,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selBar1},
			L7Parser:  ParserTypeHTTP,
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
				},
				selBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL3},
		},
		"9090/TCP": {
			Port:      9090,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selBar1},
			L7Parser:  L7ParserType("tester"),
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selBar2: api.L7Rules{
					L7Proto: "tester",
					L7:      []api.PortRuleL7{l7Rule.Ingress[0].ToPorts[0].Rules.L7[0]},
				},
				selBar1: api.L7Rules{
					L7Proto: "tester",
					L7:      []api.PortRuleL7{},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL7, labelsL3},
		},
	}
	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestWildcardL4RulesIngress(c *C) {
	repo := NewPolicyRepository()

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
	_, _, err := repo.Add(l49092Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(kafkaRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(l480Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(httpRule, map[uint16]*identity.Identity{})
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
			Port:      80,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar1, selBar2, selBar1},
			L7Parser:  ParserTypeHTTP,
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				selBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL4, labelsHTTP, labelsL4},
		},
		"9092/TCP": {
			Port:      9092,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar1, selBar2, selBar1},
			L7Parser:  ParserTypeKafka,
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				selBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL4, labelsKafka, labelsL4},
		},
	}
	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestL3DependentL4IngressFromRequires(c *C) {
	repo := NewPolicyRepository()

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
	_, _, err := repo.Add(l480Rule, map[uint16]*identity.Identity{})
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

	expectedPolicy := L4PolicyMap{
		"80/TCP": L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Endpoints: api.EndpointSelectorSlice{
				expectedSelector,
			},
			L7RulesPerEp:     L7DataMap{},
			Ingress:          true,
			DerivedFromRules: labels.LabelArrayList{nil},
		},
	}
	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestL3DependentL4EgressFromRequires(c *C) {
	repo := NewPolicyRepository()

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
				ToRequires: []api.EndpointSelector{selBar2},
			},
		},
	}
	l480Rule.Sanitize()
	_, _, err := repo.Add(l480Rule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)

	expectedSelector := api.NewESFromMatchRequirements(map[string]string{"any.id": "bar1"}, []v1.LabelSelectorRequirement{
		{
			Key:      "any.id",
			Operator: v1.LabelSelectorOpIn,
			Values:   []string{"bar2"},
		},
	})

	expectedPolicy := L4PolicyMap{
		"80/TCP": L4Filter{
			Port:     80,
			Protocol: api.ProtoTCP,
			U8Proto:  0x6,
			Endpoints: api.EndpointSelectorSlice{
				expectedSelector,
			},
			L7RulesPerEp:     L7DataMap{},
			DerivedFromRules: labels.LabelArrayList{nil},
		},
	}
	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgress(c *C) {
	repo := NewPolicyRepository()

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
	_, _, err := repo.Add(l3Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(kafkaRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(httpRule, map[uint16]*identity.Identity{})
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
			Port:      9092,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selBar1},
			L7Parser:  ParserTypeKafka,
			Ingress:   false,
			L7RulesPerEp: L7DataMap{
				selBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				selBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Egress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL4},
		},
		"80/TCP": {
			Port:      80,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selBar1},
			L7Parser:  ParserTypeHTTP,
			Ingress:   false,
			L7RulesPerEp: L7DataMap{
				selBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				selBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL4},
		},
	}
	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestWildcardL4RulesEgress(c *C) {
	repo := NewPolicyRepository()

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
	_, _, err := repo.Add(l49092Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(kafkaRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(l480Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(httpRule, map[uint16]*identity.Identity{})
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
			Port:      80,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar1, selBar2, selBar1},
			L7Parser:  ParserTypeHTTP,
			Ingress:   false,
			L7RulesPerEp: L7DataMap{
				selBar1: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				selBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL3, labelsHTTP, labelsL3},
		},
		"9092/TCP": {
			Port:      9092,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar1, selBar2, selBar1},
			L7Parser:  ParserTypeKafka,
			Ingress:   false,
			L7RulesPerEp: L7DataMap{
				selBar1: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				selBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Egress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsL3, labelsKafka, labelsL3},
		},
	}
	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestWildcardL3RulesIngressFromEntities(c *C) {
	repo := NewPolicyRepository()

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
	_, _, err := repo.Add(l3Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(kafkaRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(httpRule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(*policy), Equals, 2)
	c.Assert(len((*policy)["80/TCP"].Endpoints), Equals, 2)
	selWorld := (*policy)["80/TCP"].Endpoints[1]
	c.Assert(api.EndpointSelectorSlice{selWorld}, checker.DeepEquals, api.EntitySelectorMapping[api.EntityWorld])

	expectedPolicy := L4PolicyMap{
		"9092/TCP": {
			Port:      9092,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selWorld},
			L7Parser:  ParserTypeKafka,
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selWorld: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				selBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Ingress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL3},
		},
		"80/TCP": {
			Port:      80,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selWorld},
			L7Parser:  ParserTypeHTTP,
			Ingress:   true,
			L7RulesPerEp: L7DataMap{
				selWorld: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				selBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Ingress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL3},
		},
	}

	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestWildcardL3RulesEgressToEntities(c *C) {
	repo := NewPolicyRepository()

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
	_, _, err := repo.Add(l3Rule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(kafkaRule, map[uint16]*identity.Identity{})
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
	_, _, err = repo.Add(httpRule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	c.Assert(err, IsNil)
	c.Assert(len(*policy), Equals, 2)
	c.Assert(len((*policy)["80/TCP"].Endpoints), Equals, 2)
	selWorld := (*policy)["80/TCP"].Endpoints[1]
	c.Assert(api.EndpointSelectorSlice{selWorld}, checker.DeepEquals, api.EntitySelectorMapping[api.EntityWorld])

	expectedPolicy := L4PolicyMap{
		"9092/TCP": {
			Port:      9092,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selWorld},
			L7Parser:  ParserTypeKafka,
			Ingress:   false,
			L7RulesPerEp: L7DataMap{
				selWorld: api.L7Rules{
					Kafka: []api.PortRuleKafka{{}},
				},
				selBar2: api.L7Rules{
					Kafka: []api.PortRuleKafka{kafkaRule.Egress[0].ToPorts[0].Rules.Kafka[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsKafka, labelsL3},
		},
		"80/TCP": {
			Port:      80,
			Protocol:  api.ProtoTCP,
			U8Proto:   0x6,
			Endpoints: []api.EndpointSelector{selBar2, selWorld},
			L7Parser:  ParserTypeHTTP,
			Ingress:   false,
			L7RulesPerEp: L7DataMap{
				selWorld: api.L7Rules{
					HTTP: []api.PortRuleHTTP{{}},
				},
				selBar2: api.L7Rules{
					HTTP: []api.PortRuleHTTP{httpRule.Egress[0].ToPorts[0].Rules.HTTP[0]},
				},
			},
			DerivedFromRules: labels.LabelArrayList{labelsHTTP, labelsL3},
		},
	}

	c.Assert((*policy), checker.DeepEquals, expectedPolicy)
}

func (ds *PolicyTestSuite) TestMinikubeGettingStarted(c *C) {
	repo := NewPolicyRepository()

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
	// no rules loaded: CanReach => undecided
	c.Assert(repo.CanReachIngressRLocked(fromApp2), Equals, api.Undecided)
	c.Assert(repo.CanReachIngressRLocked(fromApp3), Equals, api.Undecided)

	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsIngressLabelAccess(fromApp2), Equals, api.Denied)
	c.Assert(repo.AllowsIngressLabelAccess(fromApp3), Equals, api.Denied)
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
	}, map[uint16]*identity.Identity{})
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
	}, map[uint16]*identity.Identity{})
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
	}, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(fromApp2)
	c.Assert(err, IsNil)

	// Due to the lack of a set structure for L4Filter.FromEndpoints,
	// merging multiple L3-dependent rules together will result in multiple
	// instances of the EndpointSelector. We duplicate them in the expected
	// output here just to get the tests passing.
	selectorFromApp2DupList := []api.EndpointSelector{
		api.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
		api.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
		api.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
		api.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
	}

	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP, U8Proto: 6,
		Endpoints: selectorFromApp2DupList,
		L7Parser:  ParserTypeHTTP,
		L7RulesPerEp: L7DataMap{
			selFromApp2: api.L7Rules{
				HTTP: []api.PortRuleHTTP{{}},
			},
		},
		Ingress:          true,
		DerivedFromRules: []labels.LabelArray{nil, nil, nil, nil},
	}
	expected.Revision = repo.GetRevision()

	c.Assert(len(*l4IngressPolicy), Equals, 1)
	c.Assert(*l4IngressPolicy, checker.DeepEquals, expected.Ingress)

	// L4 from app3 has no rules
	expected = NewL4Policy()
	expected.Revision = repo.GetRevision()
	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(fromApp3)
	c.Assert(err, IsNil)
	c.Assert(len(*l4IngressPolicy), Equals, 0)
	c.Assert(*l4IngressPolicy, checker.DeepEquals, expected.Ingress)
}

func buildSearchCtx(from, to string, port uint16) *SearchContext {
	var ports []*models.Port
	if port != 0 {
		ports = []*models.Port{{Port: port}}
	}
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
	c.Assert(verdict, Equals, expectedVerdict)

	expectedOut := "Tracing " + ctx.String() + trace
	c.Assert(buffer.String(), checker.DeepEquals, expectedOut)
}

func (ds *PolicyTestSuite) TestPolicyTrace(c *C) {
	repo := NewPolicyRepository()

	// Add rules to allow foo=>bar
	l3rule := buildRule("foo", "bar", "")
	rules := api.Rules{&l3rule}
	_ = repo.AddList(rules)

	// foo=>bar is OK
	expectedOut := `
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:foo] not found
    Allows from labels {"matchLabels":{"any:foo":""}}
      Found all required labels
+       No L4 restrictions
1/1 rules selected
Found allow rule
Label verdict: allowed
L4 ingress policies skipped
`
	ctx := buildSearchCtx("foo", "bar", 0)
	repo.checkTrace(c, ctx, expectedOut, api.Allowed)

	// foo=>bar:80 is OK
	ctx = buildSearchCtx("foo", "bar", 80)
	repo.checkTrace(c, ctx, expectedOut, api.Allowed)

	// bar=>foo is Denied
	ctx = buildSearchCtx("bar", "foo", 0)
	expectedOut = `
0/1 rules selected
Found no allow rule
Label verdict: undecided
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// bar=>foo:80 is Denied, also checks L4 policy
	ctx = buildSearchCtx("bar", "foo", 80)
	expectedOut += `
Resolving ingress port policy for [any:foo]
0/1 rules selected
Found no allow rule
L4 ingress verdict: undecided
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Now, add extra rules to allow specifically baz=>bar on port 80
	l4rule := buildRule("baz", "bar", "80")
	_, _, err := repo.Add(l4rule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	// baz=>bar:80 is OK
	ctx = buildSearchCtx("baz", "bar", 80)
	expectedOut = `
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:baz] not found
    Allows from labels {"matchLabels":{"any:foo":""}}
      Labels [any:baz] not found
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:baz] not found
    Allows from labels {"matchLabels":{"any:baz":""}}
      Found all required labels
        Rule restricts traffic to specific L4 destinations; deferring policy decision to L4 policy stage
2/2 rules selected
Found no allow rule
Label verdict: undecided

Resolving ingress port policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 Ingress rules
* Rule {"matchLabels":{"any:bar":""}}: selected
    Found all required labels
    Allows Ingress port [{80 ANY}] from endpoints [{"matchLabels":{"reserved:host":""}} {"matchLabels":{"any:baz":""}}]
2/2 rules selected
Found allow rule
L4 ingress verdict: allowed
`
	repo.checkTrace(c, ctx, expectedOut, api.Allowed)

	// bar=>bar:80 is Denied
	ctx = buildSearchCtx("bar", "bar", 80)
	expectedOut = `
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:bar] not found
    Allows from labels {"matchLabels":{"any:foo":""}}
      Labels [any:bar] not found
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:bar] not found
    Allows from labels {"matchLabels":{"any:baz":""}}
      Labels [any:bar] not found
2/2 rules selected
Found no allow rule
Label verdict: undecided

Resolving ingress port policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 Ingress rules
* Rule {"matchLabels":{"any:bar":""}}: selected
    Labels [any:bar] not found
2/2 rules selected
Found no allow rule
L4 ingress verdict: undecided
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
	_, _, err = repo.Add(l3rule, map[uint16]*identity.Identity{})
	c.Assert(err, IsNil)

	// foo=>bar is now denied due to the FromRequires
	ctx = buildSearchCtx("foo", "bar", 0)
	expectedOut = `
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:foo] not found
    Allows from labels {"matchLabels":{"any:foo":""}}
      Found all required labels
+       No L4 restrictions
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:foo] not found
    Allows from labels {"matchLabels":{"any:baz":""}}
      Labels [any:foo] not found
* Rule {"matchLabels":{"any:bar":""}}: selected
    Requires from labels {"matchLabels":{"any:baz":""}}
-     Labels [any:foo] not found
3/3 rules selected
Found unsatisfied FromRequires constraint
Label verdict: denied
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// baz=>bar is only denied because of the L4 policy
	ctx = buildSearchCtx("baz", "bar", 0)
	expectedOut = `
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:baz] not found
    Allows from labels {"matchLabels":{"any:foo":""}}
      Labels [any:baz] not found
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows from labels {"matchLabels":{"reserved:host":""}}
      Labels [any:baz] not found
    Allows from labels {"matchLabels":{"any:baz":""}}
      Found all required labels
        Rule restricts traffic to specific L4 destinations; deferring policy decision to L4 policy stage
* Rule {"matchLabels":{"any:bar":""}}: selected
    Requires from labels {"matchLabels":{"any:baz":""}}
+     Found all required labels
3/3 rules selected
Found no allow rule
Label verdict: undecided
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Should still be allowed with the new FromRequires constraint
	ctx = buildSearchCtx("baz", "bar", 80)
	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()
	c.Assert(verdict, Equals, api.Allowed)
}
