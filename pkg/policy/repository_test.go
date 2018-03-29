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
	"github.com/cilium/cilium/pkg/policy/api/v3"

	"github.com/op/go-logging"
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestAddSearchDelete(c *C) {
	repo := NewPolicyRepository()

	// cannot add empty rule
	rev, err := repo.Add(v3.Rule{})
	c.Assert(err, Not(IsNil))
	c.Assert(rev, Equals, uint64(0))

	lbls1 := labels.LabelArray{
		labels.ParseLabel("tag1"),
		labels.ParseLabel("tag2"),
	}
	rule1 := v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("foo")),
		Labels:           lbls1,
	}
	rule2 := v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Labels:           lbls1,
	}
	lbls2 := labels.LabelArray{labels.ParseSelectLabel("tag3")}
	rule3 := v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("bar")),
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
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, v3.Rules{})
	repo.Mutex.RUnlock()

	// add rule3
	rev, err = repo.Add(rule3)
	c.Assert(err, IsNil)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// search rule1,rule2
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls1), comparator.DeepEquals, v3.Rules{&rule1, &rule2})
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, v3.Rules{&rule3})
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
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, v3.Rules{&rule3})
	repo.Mutex.RUnlock()

	// delete rule3
	rev, n = repo.DeleteByLabels(lbls2)
	c.Assert(n, Equals, 1)
	c.Assert(rev, Equals, nextRevision)
	nextRevision++

	// rule1 is gone
	repo.Mutex.RLock()
	c.Assert(repo.SearchRLocked(lbls2), comparator.DeepEquals, v3.Rules{})
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
	c.Assert(repo.CanReachIngressRLocked(fooToBar), Equals, v3.Undecided)
	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsIngressRLocked(fooToBar), Equals, v3.Denied)
	repo.Mutex.RUnlock()

	tag1 := labels.LabelArray{labels.ParseLabel("tag1")}
	rule1 := v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("foo")),
				},
			},
		},
		Labels: tag1,
	}

	// selector: groupA
	// require: groupA
	rule2 := v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("groupA")),
		Ingress: []v3.IngressRule{
			{
				FromRequires: &v3.IdentityRequirement{
					IdentitySelector: []v3.IdentitySelector{
						v3.NewESFromLabels(labels.ParseSelectLabel("groupA")),
					},
				},
			},
		},
		Labels: tag1,
	}
	rule3 := v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("bar2")),
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("foo")),
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
	c.Assert(repo.AllowsIngressRLocked(fooToBar), Equals, v3.Allowed)

	// foo=>bar2 is OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar2"),
	}), Equals, v3.Allowed)

	// foo=>bar inside groupA is OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupA"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, v3.Allowed)

	// groupB can't talk to groupA => Denied
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupA"),
	}), Equals, v3.Denied)

	// no restriction on groupB, unused label => OK
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo", "groupB"),
		To:   labels.ParseSelectLabelArray("bar", "groupB"),
	}), Equals, v3.Allowed)

	// foo=>bar3, no rule => Denied
	c.Assert(repo.AllowsIngressRLocked(&SearchContext{
		From: labels.ParseSelectLabelArray("foo"),
		To:   labels.ParseSelectLabelArray("bar3"),
	}), Equals, v3.Denied)
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
	c.Assert(repo.CanReachIngressRLocked(fromApp2), Equals, v3.Undecided)
	c.Assert(repo.CanReachIngressRLocked(fromApp3), Equals, v3.Undecided)

	// no rules loaded: Allows() => denied
	c.Assert(repo.AllowsIngressLabelAccess(fromApp2), Equals, v3.Denied)
	c.Assert(repo.AllowsIngressLabelAccess(fromApp3), Equals, v3.Denied)
	repo.Mutex.RUnlock()

	selectorFromApp2 := v3.NewESFromLabels(labels.ParseSelectLabel("id=app2"))

	_, err := repo.Add(v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: selectorFromApp2,
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{
							{Port: "80", Protocol: v3.ProtoTCP},
						},
					},
				},
			},
		},
	})
	c.Assert(err, IsNil)

	_, err = repo.Add(v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: selectorFromApp2,
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{
							{Port: "80", Protocol: v3.ProtoTCP},
						},
						Rules: &v3.L7Rules{
							HTTP: []v3.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					},
				},
			},
		},
	})
	c.Assert(err, IsNil)

	_, err = repo.Add(v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("id=app1")),
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: selectorFromApp2,
					ToPorts: &v3.PortRule{
						Ports: []v3.PortProtocol{
							{Port: "80", Protocol: v3.ProtoTCP},
						},
						Rules: &v3.L7Rules{
							HTTP: []v3.PortRuleHTTP{
								{Method: "GET", Path: "/"},
							},
						},
					},
				},
			},
		},
	})
	c.Assert(err, IsNil)

	repo.Mutex.RLock()
	defer repo.Mutex.RUnlock()

	// L4 from app2 is restricted
	l4policy, err := repo.ResolveL4Policy(fromApp2)
	c.Assert(err, IsNil)

	// Due to the lack of a set structure for L4Filter.FromRequires,
	// merging multiple L3-dependent rules together will result in multiple
	// instances of the IdentitySelector. We duplicate them in the expected
	// output here just to get the tests passing.
	selectorFromApp2DupList := []v3.IdentitySelector{
		v3.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
		v3.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
		v3.NewESFromLabels(
			labels.ParseSelectLabel("id=app2"),
		),
	}

	expected := NewL4Policy()
	expected.Ingress["80/TCP"] = L4Filter{
		Port: 80, Protocol: v3.ProtoTCP, U8Proto: 6,
		FromEndpoints: selectorFromApp2DupList,
		L7Parser:      "http",
		L7RulesPerEp: L7DataMap{
			selectorFromApp2: v3.L7Rules{
				HTTP: []v3.PortRuleHTTP{{Path: "/", Method: "GET"}},
			},
		},
		Ingress:          true,
		DerivedFromRules: []labels.LabelArray{nil, nil, nil},
	}
	expected.Revision = repo.GetRevision()

	c.Assert(len(l4policy.Ingress), Equals, 1)
	c.Assert(*l4policy, comparator.DeepEquals, *expected)

	// L4 from app3 has no rules
	expected = NewL4Policy()
	expected.Revision = repo.GetRevision()
	l4policy, err = repo.ResolveL4Policy(fromApp3)
	c.Assert(err, IsNil)
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

func buildRule(from, to, port string) v3.Rule {
	reservedES := v3.NewESFromLabels(labels.ParseSelectLabel("reserved:host"))
	fromES := v3.NewESFromLabels(labels.ParseSelectLabel(from))
	toES := v3.NewESFromLabels(labels.ParseSelectLabel(to))

	ports := &v3.PortRule{}
	if port != "" {
		ports = &v3.PortRule{
			Ports: []v3.PortProtocol{{Port: port}},
		}
	}
	return v3.Rule{
		IdentitySelector: toES,
		Ingress: []v3.IngressRule{
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: reservedES,
					ToPorts:          ports,
				},
			},
			{
				FromIdentities: &v3.IdentityRule{
					IdentitySelector: fromES,
					ToPorts:          ports,
				},
			},
		},
	}
}

func (repo *Repository) checkTrace(c *C, ctx *SearchContext, expectedVerdict v3.Decision) {

	buffer := new(bytes.Buffer)
	ctx.Logging = logging.NewLogBackend(buffer, "", 0)

	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()
	c.Log(buffer)
	c.Assert(verdict, Equals, expectedVerdict)
}

func (ds *PolicyTestSuite) TestPolicyTrace(c *C) {
	repo := NewPolicyRepository()

	// Add rules to allow foo=>bar
	l3rule := buildRule("foo", "bar", "")
	rules := v3.Rules{&l3rule}
	_, err := repo.AddList(rules)
	c.Assert(err, IsNil)

	// foo=>bar is OK
	ctx := buildSearchCtx("foo", "bar", 0)
	repo.checkTrace(c, ctx, v3.Allowed)

	// foo=>bar:80 is OK
	ctx = buildSearchCtx("foo", "bar", 80)
	repo.checkTrace(c, ctx, v3.Allowed)

	// bar=>foo is Denied
	ctx = buildSearchCtx("bar", "foo", 0)
	repo.checkTrace(c, ctx, v3.Denied)

	// bar=>foo:80 is Denied, also checks L4 policy
	ctx = buildSearchCtx("bar", "foo", 80)
	repo.checkTrace(c, ctx, v3.Denied)

	// Now, add extra rules to allow specifically baz=>bar on port 80
	l4rule := buildRule("baz", "bar", "80")
	_, err = repo.Add(l4rule)
	c.Assert(err, IsNil)

	// baz=>bar:80 is OK
	ctx = buildSearchCtx("baz", "bar", 80)
	repo.checkTrace(c, ctx, v3.Allowed)

	// bar=>bar:80 is Denied
	ctx = buildSearchCtx("bar", "bar", 80)
	repo.checkTrace(c, ctx, v3.Denied)

	// Test that FromRequires "baz" drops "foo" traffic
	l3rule = v3.Rule{
		IdentitySelector: v3.NewESFromLabels(labels.ParseSelectLabel("bar")),
		Ingress: []v3.IngressRule{{
			FromRequires: &v3.IdentityRequirement{
				IdentitySelector: []v3.IdentitySelector{v3.NewESFromLabels(labels.ParseSelectLabel("baz"))},
			},
		}},
	}
	_, err = repo.Add(l3rule)
	c.Assert(err, IsNil)

	// foo=>bar is now denied due to the FromRequires
	ctx = buildSearchCtx("foo", "bar", 0)
	repo.checkTrace(c, ctx, v3.Denied)

	// baz=>bar is only denied because of the L4 policy
	ctx = buildSearchCtx("baz", "bar", 0)
	repo.checkTrace(c, ctx, v3.Denied)

	// Should still be allowed with the new FromRequires constraint
	ctx = buildSearchCtx("baz", "bar", 80)
	repo.Mutex.RLock()
	verdict := repo.AllowsIngressRLocked(ctx)
	repo.Mutex.RUnlock()
	c.Assert(verdict, Equals, v3.Allowed)
}
