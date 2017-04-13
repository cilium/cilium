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
	"encoding/json"
	"testing"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type PolicyTestSuite struct{}

var _ = Suite(&PolicyTestSuite{})

func (s *PolicyTestSuite) TestUnmarshalAllowRule(c *C) {
	var rule AllowRule

	longLabel := `{"source": "kubernetes", "key": "!io.kubernetes.pod.name", "value": "foo"}`
	invLabel := `{"source": "kubernetes", "value": "foo"}`
	shortLabel := `"web"`
	invertedLabel := `"!web"`

	err := json.Unmarshal([]byte(longLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, api.DENY)
	c.Assert(rule.Labels[0].Source, Equals, "kubernetes")
	c.Assert(rule.Labels[0].AbsoluteKey(), Equals, "root.io.kubernetes.pod.name")
	c.Assert(rule.Labels[0].Value, Equals, "foo")

	err = json.Unmarshal([]byte(invLabel), &rule)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, api.ACCEPT)
	c.Assert(rule.Labels[0].Source, Equals, common.CiliumLabelSource)
	c.Assert(rule.Labels[0].AbsoluteKey(), Equals, "root.web")
	c.Assert(rule.Labels[0].Value, Equals, "")

	err = json.Unmarshal([]byte(invertedLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, api.DENY)
	c.Assert(rule.Labels[0].Source, Equals, common.CiliumLabelSource)
	c.Assert(rule.Labels[0].AbsoluteKey(), Equals, "root.web")
	c.Assert(rule.Labels[0].Value, Equals, "")

	err = json.Unmarshal([]byte(""), &rule)
	c.Assert(err, Not(Equals), nil)
}

func (s *PolicyTestSuite) TestNodeCovers(c *C) {
	root := Node{
		Name: RootNodeName,
		Children: map[string]*Node{
			"foo": {},
			"bar": {},
		},
	}

	err := root.ResolveTree()
	c.Assert(err, Equals, nil)

	lblFoo := labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	ctx := SearchContext{To: []*labels.Label{lblFoo}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, true)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)

	lblFoo = labels.NewLabel("root.foo2", "", common.CiliumLabelSource)
	ctx = SearchContext{To: []*labels.Label{lblFoo}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, false)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)

	lblRoot := labels.NewLabel("root", "", common.CiliumLabelSource)
	ctx = SearchContext{To: []*labels.Label{lblRoot}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, false)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)
}

func (s *PolicyTestSuite) TestAllowRule(c *C) {
	lblFoo := labels.LabelArray{labels.NewLabel("foo", "", common.CiliumLabelSource)}
	lblBar := labels.LabelArray{labels.NewLabel("bar", "", common.CiliumLabelSource)}
	lblBaz := labels.LabelArray{labels.NewLabel("baz", "", common.CiliumLabelSource)}
	lblAll := labels.LabelArray{labels.NewLabel(labels.IDNameAll, "", common.ReservedLabelSource)}
	allow := &AllowRule{Action: api.ACCEPT, Labels: lblFoo}
	deny := &AllowRule{Action: api.DENY, Labels: lblFoo}
	allowAll := &AllowRule{Action: api.ACCEPT, Labels: lblAll}

	ctx := SearchContext{
		From: lblFoo,
		To:   lblBar,
	}
	ctx2 := SearchContext{
		From: lblBaz,
		To:   lblBar,
	}

	c.Assert(allow.Allows(&ctx), Equals, api.ACCEPT)
	c.Assert(deny.Allows(&ctx), Equals, api.DENY)
	c.Assert(allowAll.Allows(&ctx), Equals, api.ACCEPT)
	c.Assert(allow.Allows(&ctx2), Equals, api.UNDECIDED)
	c.Assert(deny.Allows(&ctx2), Equals, api.UNDECIDED)
	c.Assert(allowAll.Allows(&ctx2), Equals, api.ACCEPT)
}

func (s *PolicyTestSuite) TestTargetCoveredBy(c *C) {
	lblFoo := labels.NewLabel("foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("bar", "", common.CiliumLabelSource)
	lblBaz := labels.NewLabel("baz", "", common.CiliumLabelSource)
	lblJoe := labels.NewLabel("user", "joe", "kubernetes")
	lblAll := labels.NewLabel(labels.IDNameAll, "", common.ReservedLabelSource)

	list1 := []*labels.Label{lblFoo}
	list2 := []*labels.Label{lblBar, lblBaz}
	list3 := []*labels.Label{lblFoo, lblJoe}
	list4 := []*labels.Label{lblAll}

	// any -> .bar
	ctx := SearchContext{To: []*labels.Label{lblBar}}
	c.Assert(ctx.TargetCoveredBy(list1), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list2), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list3), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list4), Equals, true)

	// any -> kubernetes:.baz
	ctx = SearchContext{To: []*labels.Label{lblBaz}}
	c.Assert(ctx.TargetCoveredBy(list1), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list2), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list3), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list4), Equals, true)

	// any -> [kubernetes:.user=joe, .foo]
	ctx = SearchContext{To: []*labels.Label{lblJoe, lblFoo}}
	c.Assert(ctx.TargetCoveredBy(list1), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list2), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list3), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list4), Equals, true)
}

func (s *PolicyTestSuite) TestAllowConsumer(c *C) {
	lblTeamA := labels.NewLabel("teamA", "", common.CiliumLabelSource)
	lblTeamB := labels.NewLabel("teamB", "", common.CiliumLabelSource)
	lblFoo := labels.NewLabel("foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("bar", "", common.CiliumLabelSource)
	lblBaz := labels.NewLabel("baz", "", common.CiliumLabelSource)

	// [Foo,TeamA] -> Bar
	aFooToBar := SearchContext{
		From: []*labels.Label{lblTeamA, lblFoo},
		To:   []*labels.Label{lblBar},
	}

	// [Baz, TeamA] -> Bar
	aBazToBar := SearchContext{
		From: labels.LabelArray{lblTeamA, lblBaz},
		To:   labels.LabelArray{lblBar},
	}

	// [Foo,TeamB] -> Bar
	bFooToBar := SearchContext{
		From: labels.LabelArray{lblTeamB, lblFoo},
		To:   labels.LabelArray{lblBar},
	}

	// [Baz, TeamB] -> Bar
	bBazToBar := SearchContext{
		From: labels.LabelArray{lblTeamB, lblBaz},
		To:   labels.LabelArray{lblBar},
	}

	allowFoo := &AllowRule{Action: api.ACCEPT, Labels: labels.LabelArray{lblFoo}}
	dontAllowFoo := &AllowRule{Action: api.DENY, Labels: labels.LabelArray{lblFoo}}
	allowTeamA := &AllowRule{Action: api.ACCEPT, Labels: labels.LabelArray{lblTeamA}}
	dontAllowBaz := &AllowRule{Action: api.DENY, Labels: labels.LabelArray{lblBaz}}
	alwaysAllowFoo := &AllowRule{Action: api.ALWAYS_ACCEPT, Labels: labels.LabelArray{lblFoo}}

	// Allow: foo, !foo
	consumers := RuleConsumers{
		Coverage: []*labels.Label{lblBar},
		Allow:    []*AllowRule{allowFoo, dontAllowFoo},
	}

	// NOTE: We are testing on single consumer rule leve, there is
	// no default deny policy enforced. No match equals UNDECIDED

	c.Assert(consumers.Allows(&aFooToBar), Equals, api.DENY)
	c.Assert(consumers.Allows(&bFooToBar), Equals, api.DENY)
	c.Assert(consumers.Allows(&aBazToBar), Equals, api.UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, api.UNDECIDED)

	// Always-Allow: foo, !foo
	consumers = RuleConsumers{
		Coverage: []*labels.Label{lblBar},
		Allow:    []*AllowRule{alwaysAllowFoo, dontAllowFoo},
	}

	c.Assert(consumers.Allows(&aFooToBar), Equals, api.ALWAYS_ACCEPT)
	c.Assert(consumers.Allows(&bFooToBar), Equals, api.ALWAYS_ACCEPT)
	c.Assert(consumers.Allows(&aBazToBar), Equals, api.UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, api.UNDECIDED)

	// Allow: TeamA, !baz
	consumers = RuleConsumers{
		Coverage: []*labels.Label{lblBar},
		Allow:    []*AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&aFooToBar), Equals, api.ACCEPT)
	c.Assert(consumers.Allows(&aBazToBar), Equals, api.DENY)
	c.Assert(consumers.Allows(&bFooToBar), Equals, api.UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, api.DENY)

	// Allow: TeamA, !baz
	consumers = RuleConsumers{
		Coverage: []*labels.Label{lblFoo},
		Allow:    []*AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&aFooToBar), Equals, api.UNDECIDED)
	c.Assert(consumers.Allows(&aBazToBar), Equals, api.UNDECIDED)
	c.Assert(consumers.Allows(&bFooToBar), Equals, api.UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, api.UNDECIDED)
}

func (s *PolicyTestSuite) TestBuildPath(c *C) {
	rootNode := Node{Name: RootNodeName}
	p, err := rootNode.buildPath()
	c.Assert(p, Equals, RootNodeName)
	c.Assert(err, Equals, nil)

	// missing parent assignment
	fooNode := Node{Name: "foo"}
	p, err = fooNode.buildPath()
	c.Assert(p, Equals, "")
	c.Assert(err, Not(Equals), nil)

	rootNode.Children = map[string]*Node{"foo": &fooNode}
	fooNode.Parent = &rootNode
	p, err = fooNode.buildPath()
	c.Assert(p, Equals, "root.foo")
	c.Assert(err, Equals, nil)

	err = rootNode.ResolveTree()
	c.Assert(err, Equals, nil)
	c.Assert(rootNode.path, Equals, RootNodeName)
	c.Assert(fooNode.path, Equals, "root.foo")

}

func (s *PolicyTestSuite) TestValidateCoverage(c *C) {
	rootNode := Node{Name: RootNodeName}
	node := Node{
		Name:   "foo",
		Parent: &rootNode,
	}

	lblBar := labels.NewLabel("root.bar", "", common.CiliumLabelSource)
	consumer := RuleConsumers{Coverage: []*labels.Label{lblBar}}
	c.Assert(consumer.Resolve(&node), Not(Equals), nil)

	consumer2 := RuleRequires{Coverage: []*labels.Label{lblBar}}
	c.Assert(consumer2.Resolve(&node), Not(IsNil))

	lblFoo := labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	consumer = RuleConsumers{Coverage: []*labels.Label{lblFoo}}
	c.Assert(consumer.Resolve(&node), IsNil)

	lblFoo = labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	consumer = RuleConsumers{Coverage: []*labels.Label{lblFoo}}
	c.Assert(consumer.Resolve(&node), IsNil)
}

func (s *PolicyTestSuite) TestRequires(c *C) {
	lblFoo := labels.NewLabel("foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("bar", "", common.CiliumLabelSource)
	lblBaz := labels.NewLabel("baz", "", common.CiliumLabelSource)

	// Foo -> Bar
	aFooToBar := SearchContext{
		From: []*labels.Label{lblFoo},
		To:   []*labels.Label{lblBar},
	}

	// Baz -> Bar
	aBazToBar := SearchContext{
		From: []*labels.Label{lblBaz},
		To:   []*labels.Label{lblBar},
	}

	// Bar -> Baz
	aBarToBaz := SearchContext{
		From: []*labels.Label{lblBar},
		To:   []*labels.Label{lblBaz},
	}

	// coverage: bar
	// Require: foo
	requires := RuleRequires{
		Coverage: []*labels.Label{lblBar},
		Requires: []*labels.Label{lblFoo},
	}

	c.Assert(requires.Allows(&aFooToBar), Equals, api.UNDECIDED)
	c.Assert(requires.Allows(&aBazToBar), Equals, api.DENY)
	c.Assert(requires.Allows(&aBarToBaz), Equals, api.UNDECIDED)
}

func (s *PolicyTestSuite) TestNodeAllows(c *C) {
	lblProd := labels.NewLabel("root.Prod", "", common.CiliumLabelSource)
	lblQA := labels.NewLabel("root.QA", "", common.CiliumLabelSource)
	lblFoo := labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("root.bar", "", common.CiliumLabelSource)
	lblBaz := labels.NewLabel("root.baz", "", common.CiliumLabelSource)
	lblJoe := labels.NewLabel("root.user", "joe", "kubernetes")
	lblPete := labels.NewLabel("root.user", "pete", "kubernetes")

	// [Foo,QA] -> [Bar,QA]
	qaFooToQaBar := SearchContext{
		From: labels.LabelArray{lblQA, lblFoo},
		To:   labels.LabelArray{lblBar, lblQA},
	}

	// [Foo, Prod] -> [Bar,Prod]
	prodFooToProdBar := SearchContext{
		From: labels.LabelArray{lblProd, lblFoo},
		To:   labels.LabelArray{lblBar},
	}

	// [Foo,QA] -> [Bar,prod]
	qaFooToProdBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo},
		To:   []*labels.Label{lblBar, lblProd},
	}

	// [Foo,QA, Joe] -> [Bar,prod]
	qaJoeFooToProdBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo, lblJoe},
		To:   []*labels.Label{lblBar, lblProd},
	}

	// [Foo,QA, Pete] -> [Bar,Prod]
	qaPeteFooToProdBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo, lblPete},
		To:   []*labels.Label{lblBar, lblProd},
	}

	// [Baz, QA] -> Bar
	qaBazToQaBar := SearchContext{
		From: []*labels.Label{lblQA, lblBaz},
		To:   []*labels.Label{lblQA, lblBar},
	}

	rootNode := Node{
		Name: RootNodeName,
		Rules: []PolicyRule{
			&RuleConsumers{
				Coverage: []*labels.Label{lblBar},
				Allow: []*AllowRule{
					{ // always-allow:  user=joe
						Action: api.ALWAYS_ACCEPT,
						Labels: labels.LabelArray{lblJoe},
					},
					{ // allow:  user=pete
						Action: api.ACCEPT,
						Labels: labels.LabelArray{lblPete},
					},
				},
			},
			&RuleRequires{ // coverage qa, requires qa
				Coverage: []*labels.Label{lblQA},
				Requires: []*labels.Label{lblQA},
			},
			&RuleRequires{ // coverage prod, requires: prod
				Coverage: []*labels.Label{lblProd},
				Requires: []*labels.Label{lblProd},
			},
			&RuleConsumers{
				Coverage: []*labels.Label{lblBar},
				Allow: []*AllowRule{
					{ // allow: foo
						Action: api.ACCEPT,
						Labels: labels.LabelArray{lblFoo},
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)

	c.Assert(rootNode.Allows(&qaFooToQaBar), Equals, api.ACCEPT)
	c.Assert(rootNode.Allows(&prodFooToProdBar), Equals, api.ACCEPT)
	c.Assert(rootNode.Allows(&qaFooToProdBar), Equals, api.DENY)
	c.Assert(rootNode.Allows(&qaJoeFooToProdBar), Equals, api.ALWAYS_ACCEPT)
	c.Assert(rootNode.Allows(&qaPeteFooToProdBar), Equals, api.DENY)
	c.Assert(rootNode.Allows(&qaBazToQaBar), Equals, api.UNDECIDED)
}

func (s *PolicyTestSuite) TestResolveTree(c *C) {
	rootNode := Node{
		Name: RootNodeName,
		Children: map[string]*Node{
			"foo": {Rules: []PolicyRule{&RuleConsumers{}}},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)
	c.Assert(rootNode.Children["foo"].Name, Equals, "foo")
}

func (s *PolicyTestSuite) TestpolicyAllows(c *C) {
	lblProd := labels.NewLabel("Prod", "", common.CiliumLabelSource)
	lblQA := labels.NewLabel("QA", "", common.CiliumLabelSource)
	lblFoo := labels.NewLabel("root.foo", "", common.CiliumLabelSource)
	lblBar := labels.NewLabel("root.bar", "", common.CiliumLabelSource)
	lblBaz := labels.NewLabel("root.baz", "", common.CiliumLabelSource)
	lblJoe := labels.NewLabel("root.user", "joe", "kubernetes")
	lblPete := labels.NewLabel("root.user", "pete", "kubernetes")

	// [Foo,QA] -> [Bar,QA]
	qaFooToQaBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo},
		To:   []*labels.Label{lblQA, lblBar},
	}

	// [Foo, Prod] -> [Bar,Prod]
	prodFooToProdBar := SearchContext{
		From: []*labels.Label{lblProd, lblFoo},
		To:   []*labels.Label{lblBar},
	}

	// [Foo,QA] -> [Bar,Prod]
	qaFooToProdBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo},
		To:   []*labels.Label{lblBar, lblProd},
	}

	// [Foo,QA, Joe] -> [Bar,prod]
	qaJoeFooToProdBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo, lblJoe},
		To:   []*labels.Label{lblBar, lblProd},
	}

	// [Foo,QA, Pete] -> [Bar,Prod]
	qaPeteFooToProdBar := SearchContext{
		From: []*labels.Label{lblQA, lblFoo, lblPete},
		To:   []*labels.Label{lblBar, lblProd},
	}

	// [Baz, QA] -> Bar
	qaBazToQaBar := SearchContext{
		From: []*labels.Label{lblQA, lblBaz},
		To:   []*labels.Label{lblQA, lblBar},
	}

	rootNode := Node{
		Rules: []PolicyRule{
			&RuleConsumers{
				Coverage: []*labels.Label{lblBar},
				Allow: []*AllowRule{
					// always-allow: user=joe
					{
						Action: api.ALWAYS_ACCEPT,
						Labels: labels.LabelArray{lblJoe},
					},
					// allow:  user=pete
					{
						Action: api.ACCEPT,
						Labels: labels.LabelArray{lblPete},
					},
				},
			},
			&RuleRequires{ // coverage qa, requires qa
				Coverage: []*labels.Label{lblQA},
				Requires: []*labels.Label{lblQA},
			},
			&RuleRequires{ // coverage prod, requires: prod
				Coverage: []*labels.Label{lblProd},
				Requires: []*labels.Label{lblProd},
			},
		},
		Children: map[string]*Node{
			"foo": {},
			"bar": {
				Rules: []PolicyRule{
					&RuleConsumers{
						Allow: []*AllowRule{
							{
								Action: api.ACCEPT,
								Labels: labels.LabelArray{lblFoo}},
							{
								Action: api.DENY,
								Labels: labels.LabelArray{lblJoe}},
							{
								Action: api.DENY,
								Labels: labels.LabelArray{lblPete},
							},
						},
					},
				},
			},
		},
	}

	root := NewTree()
	_, err := root.Add("root", &rootNode)
	c.Assert(err, IsNil)
	c.Assert(root.AllowsRLocked(&qaFooToQaBar), Equals, api.ACCEPT)
	c.Assert(root.AllowsRLocked(&prodFooToProdBar), Equals, api.ACCEPT)
	c.Assert(root.AllowsRLocked(&qaFooToProdBar), Equals, api.DENY)
	c.Assert(root.AllowsRLocked(&qaJoeFooToProdBar), Equals, api.ACCEPT)
	c.Assert(root.AllowsRLocked(&qaPeteFooToProdBar), Equals, api.DENY)
	c.Assert(root.AllowsRLocked(&qaBazToQaBar), Equals, api.DENY)

	_, err = json.MarshalIndent(rootNode, "", "    ")
	c.Assert(err, Equals, nil)
}

func (s *PolicyTestSuite) TestNodeMerge(c *C) {
	// Name mismatch
	aNode := Node{Name: "a"}
	bNode := Node{Name: "b"}
	modified, err := aNode.Merge(&bNode)
	c.Assert(err, Not(Equals), nil)
	c.Assert(modified, Equals, false)

	// Empty nodes
	aOrig := Node{Name: "a", mergeable: true}
	aNode = Node{Name: "a"}
	bNode = Node{Name: "a"}
	modified, err = aNode.Merge(&bNode)
	c.Assert(err, Equals, nil)
	c.Assert(modified, Equals, false)
	c.Assert(aNode, DeepEquals, aOrig)

	lblProd := labels.NewLabel(".Prod", "", common.CiliumLabelSource)
	lblQA := labels.NewLabel(".QA", "", common.CiliumLabelSource)
	lblFoo := labels.NewLabel(".foo", "", common.CiliumLabelSource)
	lblJoe := labels.NewLabel(".user", "joe", "kubernetes")
	lblPete := labels.NewLabel(".user", "pete", "kubernetes")

	aNode = Node{
		Name: RootNodeName,
		Rules: []PolicyRule{
			&RuleRequires{ // coverage qa, requires qa
				Coverage: []*labels.Label{lblQA},
				Requires: []*labels.Label{lblQA},
			},
		},
		Children: map[string]*Node{
			"bar": {
				Name: "bar",
				path: ".bar",
				Rules: []PolicyRule{
					&RuleConsumers{
						Allow: []*AllowRule{
							{
								Action: api.ACCEPT,
								Labels: labels.LabelArray{lblJoe},
							},
							{
								Action: api.ACCEPT,
								Labels: labels.LabelArray{lblPete},
							},
						},
					},
				},
			},
		},
	}

	bNode = Node{
		Name: RootNodeName,
		Rules: []PolicyRule{
			&RuleRequires{ // coverage prod, requires: prod
				Coverage: []*labels.Label{lblProd},
				Requires: []*labels.Label{lblProd},
			},
		},
		Children: map[string]*Node{
			"foo": {
				Name: "foo",
				path: ".foo",
			},
			"bar": {
				Name: "bar",
				path: ".bar",
				Rules: []PolicyRule{
					&RuleConsumers{
						Allow: []*AllowRule{
							{ // allow: foo
								Action: api.ACCEPT,
								Labels: labels.LabelArray{lblFoo},
							},
						},
					},
				},
			},
		},
	}

	aNode.Path()
	bNode.Path()

	modified, err = aNode.Merge(&bNode)
	c.Assert(err, Equals, nil)
	c.Assert(modified, Equals, true)

	unmergeableNode := Node{
		Name: RootNodeName,
		Rules: []PolicyRule{
			&RuleConsumers{
				Allow: []*AllowRule{
					{ // deny: foo
						Action: api.DENY,
						Labels: labels.LabelArray{lblFoo},
					},
				},
			},
		},
	}

	unmergeableNode.Path()

	c.Assert(aNode.IsMergeable(), Equals, true)
	c.Assert(unmergeableNode.IsMergeable(), Equals, false)
	c.Assert(aNode.CanMerge(&unmergeableNode), Not(Equals), nil)

	modified, err = aNode.Merge(&unmergeableNode)
	c.Assert(modified, Equals, false)
	c.Assert(err, Not(Equals), nil)
}

func (s *PolicyTestSuite) TestSearchContextReplyJSON(c *C) {
	scr := SearchContextReply{
		Logging:  []byte(`foo`),
		Decision: api.ConsumableDecision(0x1),
	}
	scrWanted := SearchContextReply{
		Logging:  []byte(`foo`),
		Decision: api.ConsumableDecision(0x1),
	}
	b, err := json.Marshal(scr)
	c.Assert(err, IsNil)
	c.Assert(b, DeepEquals, []byte(`{"Logging":"Zm9v","Decision":"accept"}`))

	var scrGot SearchContextReply
	err = json.Unmarshal(b, &scrGot)
	c.Assert(err, IsNil)
	c.Assert(scrGot, DeepEquals, scrWanted)
}

func (s *PolicyTestSuite) TestRuleMergeable(c *C) {
	deny := &AllowRule{Action: api.DENY}
	c.Assert(deny.IsMergeable(), Equals, false)

	allow := &AllowRule{Action: api.ACCEPT}
	c.Assert(allow.IsMergeable(), Equals, true)

	alwaysAllow := &AllowRule{Action: api.ALWAYS_ACCEPT}
	c.Assert(alwaysAllow.IsMergeable(), Equals, true)

	req := RuleRequires{}
	c.Assert(req.IsMergeable(), Equals, true)
}
