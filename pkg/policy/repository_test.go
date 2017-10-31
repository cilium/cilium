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

package policy

import (
	"bytes"

	"github.com/cilium/cilium/api/v1/models"
	"github.com/cilium/cilium/pkg/comparator"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	"github.com/op/go-logging"
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestAddSearchDelete(c *C) {
	repo := NewPolicyRepository()

	// cannot add empty rule
	rev, err := repo.Add(api.Rule{})
	c.Assert(err, Not(IsNil))
	c.Assert(rev, Equals, uint64(0))

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

	nextRevision := uint64(0)

	c.Assert(repo.GetRevision(), Equals, nextRevision)
	nextRevision++

	// add rule1,rule2
	rev, err = repo.Add(rule1)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++
	rev, err = repo.Add(rule2)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// rule3 should not be in there yet
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()

	// add rule3
	rev, err = repo.Add(rule3)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// search rule1,rule2
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls1), comparator.DeepEquals, api.Rules{&rule1, &rule2})
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, api.Rules{&rule3})
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
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, api.Rules{&rule3})
	repo.Mutex.RUnlock()

	// delete rule3
	rev, n = repo.DeleteByLabels(lbls2)
	c.Assert(n, Equals, 1)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// rule1 is gone
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, api.Rules{})
	repo.Mutex.RUnlock()
}

func (ds *PolicyTestSuite) TestCanReach(c *C) {
	repo := NewPolicyRepository()

	fooToBar := &SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar"),
	}

	repo.Mutex.RLock()
	// no rules loaded: CanReach => undecided
	c.Assert(repo.CanReachRLocked(fooToBar), Equals, api.Undecided)
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsRLocked(fooToBar), Equals, api.Denied)
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

	_, err := repo.Add(rule1)
	c.Assert(err, IsNil)
	_, err = repo.Add(rule2)
	c.Assert(err, IsNil)
	_, err = repo.Add(rule3)
	c.Assert(err, IsNil)

	// foo=>bar is OK
	c.Assert(repo.AllowsRLocked(fooToBar), Equals, api.Allowed)

	// foo=>bar2 is OK
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, api.Allowed)

	// foo=>bar inside groupA is OK
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Allowed)

	// groupB can't talk to groupA => Denied
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, api.Denied)

	// no restriction on groupB, unused label => OK
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, api.Allowed)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, api.Denied)
}

func (ds *PolicyTestSuite) TestMinikubeGettingStarted(c *C) {
	repo := NewPolicyRepository()

	fromApp2 := &SearchContext{
		From:  labels.ParseSelectLabelArray("id=app2"),
		To:    labels.ParseSelectLabelArray("id=app1"),
		Trace: TRACE_VERBOSE,
	}

	fromApp3 := &SearchContext{
		From: labels.ParseSelectLabelArray("id=app3"),
		To:   labels.ParseSelectLabelArray("id=app1"),
	}

	repo.Mutex.RLock()
	// no rules loaded: CanReach => undecided
	c.Assert(repo.CanReachRLocked(fromApp2), Equals, api.Undecided)
	c.Assert(repo.CanReachRLocked(fromApp3), Equals, api.Undecided)

	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsLabelAccess(fromApp2), Equals, api.Denied)
	c.Assert(repo.AllowsLabelAccess(fromApp3), Equals, api.Denied)
	repo.Mutex.RUnlock()

	selectorFromApp2 := []api.EndpointSelector{
		api.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
	}

	_, err := repo.Add(api.Rule{
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
	})
	c.Assert(err, IsNil)

	_, err = repo.Add(api.Rule{
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
	})
	c.Assert(err, IsNil)

	_, err = repo.Add(api.Rule{
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
	})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	l4policy, err := repo.ResolveL4Policy(fromApp2)
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
	}

	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: api.ProtoTCP,
		FromEndpoints: selectorFromApp2DupList,
		L7Parser:      "http",
		L7RulesPerEp: L7DataMap{
			selectorFromApp2[0]: api.L7Rules{
				HTTP: []api.PortRuleHTTP{{Path: "/", Method: "GET"}},
			},
		},
		Ingress: true,
	}

	c.Assert(len(l4policy.Ingress), Equals, 1)
	c.Assert(*l4policy, comparator.DeepEquals, *expected)

	// L4 from app3 has no rules
	expected = NewL4Policy()
	l4policy, err = repo.ResolveL4Policy(fromApp3)
	c.Assert(len(l4policy.Ingress), Equals, 0)
	c.Assert(*l4policy, comparator.DeepEquals, *expected)
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
	verdict := repo.AllowsRLocked(ctx)
	repo.Mutex.RUnlock()
	c.Assert(verdict, Equals, expectedVerdict)

	expectedOut := "Tracing " + ctx.String() + trace
	c.Assert(buffer.String(), comparator.DeepEquals, expectedOut)
}

func (ds *PolicyTestSuite) TestPolicyTrace(c *C) {
	repo := NewPolicyRepository()

	// Add rules to allow foo=>bar
	l3rule := buildRule("foo", "bar", "")
	rules := api.Rules{&l3rule}
	_, err := repo.AddList(rules)
	c.Assert(err, IsNil)

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
L4 ingress & egress policies skipped
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
Resolving egress port policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 rules
1/1 rules selected
Found no allow rule
L4 egress verdict: undecided

Resolving ingress port policy for [any:foo]
0/1 rules selected
Found no allow rule
L4 ingress verdict: undecided
`
	repo.checkTrace(c, ctx, expectedOut, api.Denied)

	// Now, add extra rules to allow specifically baz=>bar on port 80
	l4rule := buildRule("baz", "bar", "80")
	_, err = repo.Add(l4rule)
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

Resolving egress port policy for [any:baz]
0/2 rules selected
Found no allow rule
L4 egress verdict: undecided

Resolving ingress port policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 rules
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows Ingress port [{80 ANY}] from endpoints [{"matchLabels":{"reserved:host":""}} {"matchLabels":{"any:baz":""}}]
      Found all required labels
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

Resolving egress port policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 rules
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 rules
2/2 rules selected
Found no allow rule
L4 egress verdict: undecided

Resolving ingress port policy for [any:bar]
* Rule {"matchLabels":{"any:bar":""}}: selected
    No L4 rules
* Rule {"matchLabels":{"any:bar":""}}: selected
    Allows Ingress port [{80 ANY}] from endpoints [{"matchLabels":{"reserved:host":""}} {"matchLabels":{"any:baz":""}}]
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
	_, err = repo.Add(l3rule)
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
	verdict := repo.AllowsRLocked(ctx)
	repo.Mutex.RUnlock()
	c.Assert(verdict, Equals, api.Allowed)
}
