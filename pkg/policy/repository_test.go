// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package policy

import (
	"bytes"
	"fmt"
	stdlog "log"
	"testing"

	"github.com/cilium/proxy/pkg/policy/api/kafka"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/util/intstr"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/identity"
	k8sConst "github.com/cilium/cilium/pkg/k8s/apis/cilium.io"
	slim_metav1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/apis/meta/v1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy/api"
)

func TestComputePolicyEnforcementAndRules(t *testing.T) {

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
	require.Equal(t, false, ing, "ingress policy enforcement should not apply since no rules are in repository")
	require.Equal(t, false, egr, "egress policy enforcement should not apply since no rules are in repository")
	require.EqualValues(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err := repo.Add(fooIngressRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, true, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.Equal(t, false, egr, "egress policy enforcement should not apply since no egress rules select")
	require.EqualValues(t, fooIngressRule1, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, err = repo.Add(fooIngressRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, true, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.Equal(t, false, egr, "egress policy enforcement should not apply since no egress rules select")
	require.EqualValues(t, fooIngressRule1, matchingRules[0].Rule, "returned matching rules did not match")
	require.EqualValues(t, fooIngressRule2, matchingRules[1].Rule, "returned matching rules did not match")

	_, _, numDeleted := repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressRule1Label})
	require.Equal(t, 1, numDeleted)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, true, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.Equal(t, false, egr, "egress policy enforcement should not apply since no egress rules select")
	require.EqualValues(t, fooIngressRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooIngressRule2Label})
	require.Equal(t, 1, numDeleted)

	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, false, ing, "ingress policy enforcement should not apply since no rules are in repository")
	require.Equal(t, false, egr, "egress policy enforcement should not apply since no rules are in repository")
	require.EqualValues(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	_, _, err = repo.Add(fooEgressRule1)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, false, ing, "ingress policy enforcement should not apply since no ingress rules select")
	require.Equal(t, true, egr, "egress policy enforcement should apply since egress rules select")
	require.EqualValues(t, fooEgressRule1, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule1Label})
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.Add(fooEgressRule2)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, false, ing, "ingress policy enforcement should not apply since no ingress rules select")
	require.Equal(t, true, egr, "egress policy enforcement should apply since egress rules select")
	require.EqualValues(t, fooEgressRule2, matchingRules[0].Rule, "returned matching rules did not match")

	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{fooEgressRule2Label})
	require.Equal(t, 1, numDeleted)

	_, _, err = repo.Add(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, true, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.Equal(t, true, egr, "egress policy enforcement should apply since egress rules selects")
	require.EqualValues(t, combinedRule, matchingRules[0].Rule, "returned matching rules did not match")
	_, _, numDeleted = repo.DeleteByLabelsLocked(labels.LabelArray{combinedLabel})
	require.Equal(t, 1, numDeleted)

	SetPolicyEnabled(option.AlwaysEnforce)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, true, ing, "ingress policy enforcement should apply since ingress rule selects")
	require.Equal(t, true, egr, "egress policy enforcement should apply since egress rules selects")
	require.EqualValues(t, ruleSlice{}, matchingRules, "returned matching rules did not match")

	SetPolicyEnabled(option.NeverEnforce)
	_, _, err = repo.Add(combinedRule)
	require.NoError(t, err, "unable to add rule to policy repository")
	ing, egr, matchingRules = repo.computePolicyEnforcementAndRules(fooIdentity)
	require.Equal(t, false, ing, "ingress policy enforcement should not apply since policy enforcement is disabled ")
	require.Equal(t, false, egr, "egress policy enforcement should not apply since policy enforcement is disabled")
	require.Nil(t, matchingRules, "no rules should be returned since policy enforcement is disabled")

	// Test init identity.

	SetPolicyEnabled(option.DefaultEnforcement)
	// If the mode is "default", check that the policy is always enforced for
	// endpoints with the reserved:init label. If no policy rules match
	// reserved:init, this drops all ingress and egress traffic.
	ingress, egress, matchingRules := repo.computePolicyEnforcementAndRules(initIdentity)
	require.Equal(t, true, ingress)
	require.Equal(t, true, egress)
	require.EqualValues(t, ruleSlice{}, matchingRules, "no rules should be returned since policy enforcement is disabled")

	// Check that the "always" and "never" modes are not affected.
	SetPolicyEnabled(option.AlwaysEnforce)
	ingress, egress, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	require.Equal(t, true, ingress)
	require.Equal(t, true, egress)

	SetPolicyEnabled(option.NeverEnforce)
	ingress, egress, _ = repo.computePolicyEnforcementAndRules(initIdentity)
	require.Equal(t, false, ingress)
	require.Equal(t, false, egress)

}

func TestAddSearchDelete(t *testing.T) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	// cannot add empty rule
	rev, _, err := repo.Add(api.Rule{})
	require.NotNil(t, err)
	require.Equal(t, uint64(1), rev)

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

	require.Equal(t, nextRevision, repo.GetRevision())
	nextRevision++

	// add rule1,rule2
	rev, _, err = repo.Add(rule1)
	require.Nil(t, err)
	require.Equal(t, nextRevision, rev)
	nextRevision++
	rev, _, err = repo.Add(rule2)
	require.Nil(t, err)
	require.Equal(t, nextRevision, rev)
	nextRevision++

	// rule3 should not be in there yet
	repo.Mutex.RLock()
	require.EqualValues(t, api.Rules{}, repo.SearchRLocked(lbls2))
	repo.Mutex.RUnlock()

	// add rule3
	rev, _, err = repo.Add(rule3)
	require.Nil(t, err)
	require.Equal(t, nextRevision, rev)
	nextRevision++

	// search rule1,rule2
	repo.Mutex.RLock()
	require.EqualValues(t, api.Rules{&rule1, &rule2}, repo.SearchRLocked(lbls1))
	require.EqualValues(t, api.Rules{&rule3}, repo.SearchRLocked(lbls2))
	repo.Mutex.RUnlock()

	// delete rule1, rule2
	rev, n := repo.DeleteByLabels(lbls1)
	require.Equal(t, 2, n)
	require.Equal(t, nextRevision, rev)
	nextRevision++

	// delete rule1, rule2 again has no effect
	rev, n = repo.DeleteByLabels(lbls1)
	require.Equal(t, 0, n)
	require.Equal(t, nextRevision-1, rev)

	// rule3 can still be found
	repo.Mutex.RLock()
	require.EqualValues(t, api.Rules{&rule3}, repo.SearchRLocked(lbls2))
	repo.Mutex.RUnlock()

	// delete rule3
	rev, n = repo.DeleteByLabels(lbls2)
	require.Equal(t, 1, n)
	require.Equal(t, nextRevision, rev)

	// rule1 is gone
	repo.Mutex.RLock()
	require.EqualValues(t, api.Rules{}, repo.SearchRLocked(lbls2))
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

func TestAllowsIngress(t *testing.T) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: Allows() => denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fooToBar))
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
	require.Nil(t, err)
	_, _, err = repo.Add(rule2)
	require.Nil(t, err)
	_, _, err = repo.Add(rule3)
	require.Nil(t, err)

	// foo=>bar is OK
	require.Equal(t, api.Allowed, repo.AllowsIngressRLocked(fooToBar))

	// foo=>bar2 is OK
	require.Equal(t, api.Allowed, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}))

	// foo=>bar inside groupA is OK
	require.Equal(t, api.Allowed, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}))

	// groupB can't talk to groupA => Denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}))

	// no restriction on groupB, unused label => OK
	require.Equal(t, api.Allowed, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}))

	// foo=>bar3, no rule => Denied
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}))
}

func TestAllowsEgress(t *testing.T) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: Allows() => denied
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(fooToBar))
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
	require.Nil(t, err)
	_, _, err = repo.Add(rule2)
	require.Nil(t, err)
	_, _, err = repo.Add(rule3)
	require.Nil(t, err)

	// foo=>bar is OK
	logBuffer := new(bytes.Buffer)
	result := repo.AllowsEgressRLocked(fooToBar.WithLogger(logBuffer))
	if !assert.EqualValues(t, api.Allowed, result) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected: \n%s", err)
	}

	// foo=>bar2 is OK
	require.Equal(t, api.Allowed, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}))

	// foo=>bar inside groupA is OK
	require.Equal(t, api.Allowed, repo.AllowsEgressRLocked(&SearchContext{
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

	// no restriction on groupB, unused label => OK
	require.Equal(t, api.Allowed, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}))

	// foo=>bar3, no rule => Denied
	require.Equal(t, api.Denied, repo.AllowsEgressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}))
}

func TestWildcardL3RulesIngress(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	icmpV4Type := intstr.FromInt(8)
	icmpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(icmpRule)
	require.Nil(t, err)

	icmpV6Type := intstr.FromInt(128)
	icmpV6Rule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(icmpV6Rule)
	require.Nil(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	require.Nil(t, err)

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
	require.EqualValues(t, expectedPolicy, policy)
	policy.Detach(repo.GetSelectorCache())
}

func TestWildcardL4RulesIngress(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	require.Nil(t, err)

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
	require.EqualValues(t, expectedPolicy, policy)
	policy.Detach(repo.GetSelectorCache())
}

func TestL3DependentL4IngressFromRequires(t *testing.T) {
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
	require.Nil(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	require.Nil(t, err)

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
	require.Equal(t, expectedPolicy, policy)
	policy.Detach(repo.GetSelectorCache())
}

func TestL3DependentL4EgressFromRequires(t *testing.T) {
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
	require.Nil(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.Nil(t, err)

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
	if !assert.Equal(t, expectedPolicy, policy) {
		t.Errorf("Policy doesn't match expected:\n%s", logBuffer.String())
	}
	policy.Detach(repo.GetSelectorCache())
}

func TestWildcardL3RulesEgress(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	icmpV4Type := intstr.FromInt(8)
	icmpRule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(icmpRule)
	require.Nil(t, err)

	icmpV6Type := intstr.FromInt(128)
	icmpV6Rule := api.Rule{
		EndpointSelector: selFoo,
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
	_, _, err = repo.Add(icmpV6Rule)
	require.Nil(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.Nil(t, err)

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
	if !assert.Equal(t, expectedPolicy, policy) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected: \n%s", err)
	}
	policy.Detach(repo.GetSelectorCache())
}

func TestWildcardL4RulesEgress(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.Nil(t, err)

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
	if !assert.EqualValues(t, expectedPolicy, policy) {
		t.Logf("%s", logBuffer.String())
		t.Error("Resolved policy did not match expected")
	}
	policy.Detach(repo.GetSelectorCache())
}

func TestWildcardCIDRRulesEgress(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	logBuffer := new(bytes.Buffer)
	policy, err := repo.ResolveL4EgressPolicy(ctx.WithLogger(logBuffer))
	require.Nil(t, err)

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
	if !assert.EqualValues(t, expectedPolicy, policy) {
		t.Logf("%s", logBuffer.String())
		t.Error("Resolved policy did not match expected")
	}
	policy.Detach(repo.GetSelectorCache())
}

func TestWildcardL3RulesIngressFromEntities(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	ctx := &SearchContext{
		To: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4IngressPolicy(ctx)
	require.Nil(t, err)
	require.Equal(t, 3, len(policy))
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	require.Equal(t, 1, len(policy["80/TCP"].PerSelectorPolicies))
	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(selWorld)
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

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

	require.EqualValues(t, expectedPolicy, policy)
	policy.Detach(repo.GetSelectorCache())
}

func TestWildcardL3RulesEgressToEntities(t *testing.T) {
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	ctx := &SearchContext{
		From: labels.ParseSelectLabelArray("id=foo"),
	}

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	policy, err := repo.ResolveL4EgressPolicy(ctx)
	require.Nil(t, err)
	require.Equal(t, 3, len(policy))
	selWorld := api.EntitySelectorMapping[api.EntityWorld][0]
	require.Equal(t, 1, len(policy["80/TCP"].PerSelectorPolicies))
	cachedSelectorWorld := testSelectorCache.FindCachedIdentitySelector(selWorld)
	require.NotNil(t, cachedSelectorWorld)

	cachedSelectorWorldV4 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv4])
	require.NotNil(t, cachedSelectorWorldV4)

	cachedSelectorWorldV6 := testSelectorCache.FindCachedIdentitySelector(api.ReservedEndpointSelectors[labels.IDNameWorldIPv6])
	require.NotNil(t, cachedSelectorWorldV6)

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

	require.EqualValues(t, expectedPolicy, policy)
	policy.Detach(repo.GetSelectorCache())
}

func TestMinikubeGettingStarted(t *testing.T) {
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
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fromApp2))
	require.Equal(t, api.Denied, repo.AllowsIngressRLocked(fromApp3))
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
	require.Nil(t, err)

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
	require.Nil(t, err)

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
	require.Nil(t, err)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	logBuffer := new(bytes.Buffer)
	l4IngressPolicy, err := repo.ResolveL4IngressPolicy(fromApp2.WithLogger(logBuffer))
	require.Nil(t, err)

	cachedSelectorApp2 := testSelectorCache.FindCachedIdentitySelector(selFromApp2)
	require.NotNil(t, cachedSelectorApp2)

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

	if !assert.EqualValues(t, expected.Ingress.PortRules, l4IngressPolicy) {
		t.Logf("%s", logBuffer.String())
		t.Errorf("Resolved policy did not match expected")
	}
	l4IngressPolicy.Detach(testSelectorCache)
	expected.Detach(testSelectorCache)

	// L4 from app3 has no rules
	expected = NewL4Policy(repo.GetRevision())
	l4IngressPolicy, err = repo.ResolveL4IngressPolicy(fromApp3)
	require.Nil(t, err)
	require.Equal(t, 0, len(l4IngressPolicy))
	require.Equal(t, expected.Ingress.PortRules, l4IngressPolicy)
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

func (repo *Repository) checkTrace(t *testing.T, ctx *SearchContext, trace string,
	expectedVerdict api.Decision) {

	buffer := new(bytes.Buffer)
	ctx.Logging = stdlog.New(buffer, "", 0)

	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()

	expectedOut := "Tracing " + ctx.String() + "\n" + trace
	require.EqualValues(t, expectedOut, buffer.String())
	require.Equal(t, expectedVerdict, verdict)
}

func TestPolicyTrace(t *testing.T) {
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
	repo.checkTrace(t, ctx, expectedOut, api.Allowed)

	// foo=>bar:80 is OK
	ctx = buildSearchCtx("foo", "bar", 80)
	repo.checkTrace(t, ctx, expectedOut, api.Allowed)

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
	l4rule := buildRule("baz", "bar", "80")
	_, _, err := repo.Add(l4rule)
	require.Nil(t, err)

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
	repo.checkTrace(t, ctx, expectedOut, api.Allowed)

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
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

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
	require.Nil(t, err)

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
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

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
	repo.checkTrace(t, ctx, expectedOut, api.Denied)

	// Should still be allowed with the new FromRequires constraint
	ctx = buildSearchCtx("baz", "bar", 80)
	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()
	require.Equal(t, api.Allowed, verdict)
}

func TestRemoveIdentityFromRuleCaches(t *testing.T) {

	testRepo := parseAndAddRules(t, api.Rules{&api.Rule{
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
	require.Equal(t, true, addedRule.matches(selectedIdentity))
	require.EqualValues(t, map[identity.NumericIdentity]bool{selectedIdentity.ID: true}, addedRule.metadata.IdentitySelected)

	wg := testRepo.removeIdentityFromRuleCaches(selectedIdentity)
	wg.Wait()

	require.EqualValues(t, map[identity.NumericIdentity]bool{}, addedRule.metadata.IdentitySelected)

	require.Equal(t, false, addedRule.matches(notSelectedIdentity))
	require.EqualValues(t, map[identity.NumericIdentity]bool{notSelectedIdentity.ID: false}, addedRule.metadata.IdentitySelected)

	wg = testRepo.removeIdentityFromRuleCaches(notSelectedIdentity)
	wg.Wait()

	require.EqualValues(t, map[identity.NumericIdentity]bool{}, addedRule.metadata.IdentitySelected)
}

func TestIterate(t *testing.T) {
	repo := NewPolicyRepository(nil, nil, nil, nil)
	repo.selectorCache = testSelectorCache

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
		require.Nil(t, err)
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

	repo.Mutex.Lock()
	_, _, numDeleted := repo.DeleteByLabelsLocked(labels.LabelArray{lbls[0]})
	repo.Mutex.Unlock()
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
		require.Nil(t, r.Sanitize())
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
			require.NoError(t, err, "unable to add rule to policy repository")
		}

		ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
		require.Equal(t, tc.ingress, ing, "case %d: ingress should match", i)
		require.Equal(t, tc.egress, egr, "case %d: egress should match", i)
		require.Equal(t, tc.ruleC, len(matchingRules), "case %d: rule count should match", i)
	}

	for i, tc := range egressCases {
		repo := NewPolicyRepository(nil, nil, nil, nil)
		repo.selectorCache = testSelectorCache

		for _, rule := range tc.rules {
			_, _, err := repo.Add(rule)
			require.NoError(t, err, "unable to add rule to policy repository")
		}

		ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
		require.Equal(t, tc.ingress, ing, "case %d: ingress should match", i)
		require.Equal(t, tc.egress, egr, "case %d: egress should match", i)
		require.Equal(t, tc.ruleC, len(matchingRules), "case %d: rule count should match", i)
	}

	// test all combinations of ingress + egress cases
	for e, etc := range egressCases {
		for i, itc := range ingressCases {
			repo := NewPolicyRepository(nil, nil, nil, nil)
			repo.selectorCache = testSelectorCache

			for _, rule := range etc.rules {
				_, _, err := repo.Add(rule)
				require.NoError(t, err, "unable to add rule to policy repository")
			}

			for _, rule := range itc.rules {
				_, _, err := repo.Add(rule)
				require.NoError(t, err, "unable to add rule to policy repository")
			}

			ing, egr, matchingRules := repo.computePolicyEnforcementAndRules(fooIdentity)
			require.Equal(t, itc.ingress, ing, "case ingress %d + egress %d: ingress should match", i, e)
			require.Equal(t, etc.egress, egr, "case ingress %d + egress %d: egress should match", i, e)
			require.Equal(t, itc.ruleC+etc.ruleC, len(matchingRules), "case ingress %d + egress %d: rule count should match", i, e)
		}
	}
}
