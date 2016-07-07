package types

import (
	"encoding/json"

	"github.com/noironetworks/cilium-net/common"

	. "gopkg.in/check.v1"
)

type CommonSuite struct{}

var _ = Suite(&CommonSuite{})

func (s *CommonSuite) TestReservedID(c *C) {
	i1 := GetID("host")
	c.Assert(i1, Equals, ID_HOST)
	c.Assert(i1.String(), Equals, "host")

	i2 := GetID("world")
	c.Assert(i2, Equals, ID_WORLD)
	c.Assert(i2.String(), Equals, "world")

	c.Assert(GetID("unknown"), Equals, ID_UNKNOWN)
	unknown := ReservedID(700)
	c.Assert(unknown.String(), Equals, "")
}

func (s *CommonSuite) TestUnmarshalAllowRule(c *C) {
	var rule AllowRule

	longLabel := `{"source": "kubernetes", "key": "!io.kubernetes.pod.name", "value": "foo"}`
	invLabel := `{"source": "kubernetes", "value": "foo"}`
	shortLabel := `"web"`
	invertedLabel := `"!web"`

	err := json.Unmarshal([]byte(longLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, DENY)
	c.Assert(rule.Label.Source, Equals, "kubernetes")
	c.Assert(rule.Label.AbsoluteKey(), Equals, "io.kubernetes.pod.name")
	c.Assert(rule.Label.Value, Equals, "foo")

	err = json.Unmarshal([]byte(invLabel), &rule)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, ACCEPT)
	c.Assert(rule.Label.Source, Equals, common.CiliumLabelSource)
	c.Assert(rule.Label.AbsoluteKey(), Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")

	err = json.Unmarshal([]byte(invertedLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, DENY)
	c.Assert(rule.Label.Source, Equals, common.CiliumLabelSource)
	c.Assert(rule.Label.AbsoluteKey(), Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")

	err = json.Unmarshal([]byte(""), &rule)
	c.Assert(err, Not(Equals), nil)
}

func (s *CommonSuite) TestPolicyNodeCovers(c *C) {
	root := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{},
			"bar": &PolicyNode{},
		},
	}

	err := root.ResolveTree()
	c.Assert(err, Equals, nil)

	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	ctx := SearchContext{To: []Label{*lblFoo}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, true)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)

	lblFoo = NewLabel("io.cilium.foo2", "", common.CiliumLabelSource)
	ctx = SearchContext{To: []Label{*lblFoo}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, false)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)

	lblRoot := NewLabel("io.cilium", "", common.CiliumLabelSource)
	ctx = SearchContext{To: []Label{*lblRoot}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, false)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)
}

func (s *CommonSuite) TestLabelCompare(c *C) {
	a1 := NewLabel("io.cilium", "", "")
	a2 := NewLabel("io.cilium", "", "")
	b1 := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	c1 := NewLabel("io.cilium.bar", "", "kubernetes")
	d1 := NewLabel("", "", "")

	c.Assert(a1.Equals(a2), Equals, true)
	c.Assert(a2.Equals(a1), Equals, true)
	c.Assert(a1.Equals(b1), Equals, false)
	c.Assert(a1.Equals(c1), Equals, false)
	c.Assert(a1.Equals(d1), Equals, false)
	c.Assert(b1.Equals(c1), Equals, false)
}

func (s *CommonSuite) TestAllowRule(c *C) {
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblBaz := NewLabel("io.cilium.baz", "", common.CiliumLabelSource)
	lblAll := NewLabel(ID_NAME_ALL, "", common.ReservedLabelSource)
	allow := AllowRule{Action: ACCEPT, Label: *lblFoo}
	deny := AllowRule{Action: DENY, Label: *lblFoo}
	allowAll := AllowRule{Action: ACCEPT, Label: *lblAll}

	ctx := SearchContext{
		From: []Label{*lblFoo},
		To:   []Label{*lblBar},
	}
	ctx2 := SearchContext{
		From: []Label{*lblBaz},
		To:   []Label{*lblBar},
	}

	c.Assert(allow.Allows(&ctx), Equals, ACCEPT)
	c.Assert(deny.Allows(&ctx), Equals, DENY)
	c.Assert(allowAll.Allows(&ctx), Equals, ACCEPT)
	c.Assert(allow.Allows(&ctx2), Equals, UNDECIDED)
	c.Assert(deny.Allows(&ctx2), Equals, UNDECIDED)
	c.Assert(allowAll.Allows(&ctx2), Equals, ACCEPT)
}

func (s *CommonSuite) TestTargetCoveredBy(c *C) {
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblBaz := NewLabel("io.cilium.baz", "", common.CiliumLabelSource)
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")
	lblAll := NewLabel(ID_NAME_ALL, "", common.ReservedLabelSource)

	list1 := []Label{*lblFoo}
	list2 := []Label{*lblBar, *lblBaz}
	list3 := []Label{*lblFoo, *lblJoe}
	list4 := []Label{*lblAll}

	// any -> io.cilium.bar
	ctx := SearchContext{To: []Label{*lblBar}}
	c.Assert(ctx.TargetCoveredBy(list1), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list2), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list3), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list4), Equals, true)

	// any -> kubernetes:io.cilium.baz
	ctx = SearchContext{To: []Label{*lblBaz}}
	c.Assert(ctx.TargetCoveredBy(list1), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list2), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list3), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list4), Equals, true)

	// any -> [kubernetes:io.cilium.user=joe, io.cilium.foo]
	ctx = SearchContext{To: []Label{*lblJoe, *lblFoo}}
	c.Assert(ctx.TargetCoveredBy(list1), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list2), Equals, false)
	c.Assert(ctx.TargetCoveredBy(list3), Equals, true)
	c.Assert(ctx.TargetCoveredBy(list4), Equals, true)
}

func (s *CommonSuite) TestAllowConsumer(c *C) {
	lblTeamA := NewLabel("io.cilium.teamA", "", common.CiliumLabelSource)
	lblTeamB := NewLabel("io.cilium.teamB", "", common.CiliumLabelSource)
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblBaz := NewLabel("io.cilium.baz", "", common.CiliumLabelSource)

	// [Foo,TeamA] -> Bar
	aFooToBar := SearchContext{
		From: []Label{*lblTeamA, *lblFoo},
		To:   []Label{*lblBar},
	}

	// [Baz, TeamA] -> Bar
	aBazToBar := SearchContext{
		From: []Label{*lblTeamA, *lblBaz},
		To:   []Label{*lblBar},
	}

	// [Foo,TeamB] -> Bar
	bFooToBar := SearchContext{
		From: []Label{*lblTeamB, *lblFoo},
		To:   []Label{*lblBar},
	}

	// [Baz, TeamB] -> Bar
	bBazToBar := SearchContext{
		From: []Label{*lblTeamB, *lblBaz},
		To:   []Label{*lblBar},
	}

	allowFoo := AllowRule{Action: ACCEPT, Label: *lblFoo}
	dontAllowFoo := AllowRule{Action: DENY, Label: *lblFoo}
	allowTeamA := AllowRule{Action: ACCEPT, Label: *lblTeamA}
	dontAllowBaz := AllowRule{Action: DENY, Label: *lblBaz}
	alwaysAllowFoo := AllowRule{Action: ALWAYS_ACCEPT, Label: *lblFoo}

	// Allow: foo, !foo
	consumers := PolicyRuleConsumers{
		Coverage: []Label{*lblBar},
		Allow:    []AllowRule{allowFoo, dontAllowFoo},
	}

	// NOTE: We are testing on single consumer rule leve, there is
	// no default deny policy enforced. No match equals UNDECIDED

	c.Assert(consumers.Allows(&aFooToBar), Equals, DENY)
	c.Assert(consumers.Allows(&bFooToBar), Equals, DENY)
	c.Assert(consumers.Allows(&aBazToBar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, UNDECIDED)

	// Always-Allow: foo, !foo
	consumers = PolicyRuleConsumers{
		Coverage: []Label{*lblBar},
		Allow:    []AllowRule{alwaysAllowFoo, dontAllowFoo},
	}

	c.Assert(consumers.Allows(&aFooToBar), Equals, ALWAYS_ACCEPT)
	c.Assert(consumers.Allows(&bFooToBar), Equals, ALWAYS_ACCEPT)
	c.Assert(consumers.Allows(&aBazToBar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, UNDECIDED)

	// Allow: TeamA, !baz
	consumers = PolicyRuleConsumers{
		Coverage: []Label{*lblBar},
		Allow:    []AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&aFooToBar), Equals, ACCEPT)
	c.Assert(consumers.Allows(&aBazToBar), Equals, DENY)
	c.Assert(consumers.Allows(&bFooToBar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, DENY)

	// Allow: TeamA, !baz
	consumers = PolicyRuleConsumers{
		Coverage: []Label{*lblFoo},
		Allow:    []AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&aFooToBar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&aBazToBar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&bFooToBar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&bBazToBar), Equals, UNDECIDED)
}

func (s *CommonSuite) TestBuildPath(c *C) {
	rootNode := PolicyNode{Name: common.GlobalLabelPrefix}
	p, err := rootNode.BuildPath()
	c.Assert(p, Equals, common.GlobalLabelPrefix)
	c.Assert(err, Equals, nil)

	// missing parent assignment
	fooNode := PolicyNode{Name: "foo"}
	p, err = fooNode.BuildPath()
	c.Assert(p, Equals, "")
	c.Assert(err, Not(Equals), nil)

	rootNode.Children = map[string]*PolicyNode{"foo": &fooNode}
	fooNode.Parent = &rootNode
	p, err = fooNode.BuildPath()
	c.Assert(p, Equals, common.GlobalLabelPrefix+".foo")
	c.Assert(err, Equals, nil)

	err = rootNode.ResolveTree()
	c.Assert(err, Equals, nil)
	c.Assert(rootNode.path, Equals, common.GlobalLabelPrefix)
	c.Assert(fooNode.path, Equals, common.GlobalLabelPrefix+".foo")

}

func (s *CommonSuite) TestValidateCoverage(c *C) {
	rootNode := PolicyNode{Name: common.GlobalLabelPrefix}
	node := PolicyNode{
		Name:   "foo",
		Parent: &rootNode,
	}

	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	consumer := PolicyRuleConsumers{Coverage: []Label{*lblBar}}
	c.Assert(consumer.Resolve(&node), Not(Equals), nil)

	consumer2 := PolicyRuleRequires{Coverage: []Label{*lblBar}}
	c.Assert(consumer2.Resolve(&node), Not(Equals), nil)

	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	consumer = PolicyRuleConsumers{Coverage: []Label{*lblFoo}}
	c.Assert(consumer.Resolve(&node), Equals, nil)

	lblFoo = NewLabel("foo", "", common.CiliumLabelSource)
	consumer = PolicyRuleConsumers{Coverage: []Label{*lblFoo}}
	c.Assert(consumer.Resolve(&node), Equals, nil)
}

func (s *CommonSuite) TestRequires(c *C) {
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblBaz := NewLabel("io.cilium.baz", "", common.CiliumLabelSource)

	// Foo -> Bar
	aFooToBar := SearchContext{
		From: []Label{*lblFoo},
		To:   []Label{*lblBar},
	}

	// Baz -> Bar
	aBazToBar := SearchContext{
		From: []Label{*lblBaz},
		To:   []Label{*lblBar},
	}

	// Bar -> Baz
	aBarToBaz := SearchContext{
		From: []Label{*lblBar},
		To:   []Label{*lblBaz},
	}

	// coverage: bar
	// Require: foo
	requires := PolicyRuleRequires{
		Coverage: []Label{*lblBar},
		Requires: []Label{*lblFoo},
	}

	c.Assert(requires.Allows(&aFooToBar), Equals, UNDECIDED)
	c.Assert(requires.Allows(&aBazToBar), Equals, DENY)
	c.Assert(requires.Allows(&aBarToBaz), Equals, UNDECIDED)
}

func (s *CommonSuite) TestPolicyNodeAllows(c *C) {
	lblProd := NewLabel("io.cilium.Prod", "", common.CiliumLabelSource)
	lblQA := NewLabel("io.cilium.QA", "", common.CiliumLabelSource)
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblBaz := NewLabel("io.cilium.baz", "", common.CiliumLabelSource)
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")
	lblPete := NewLabel("io.cilium.user", "pete", "kubernetes")

	// [Foo,QA] -> [Bar,QA]
	qaFooToQaBar := SearchContext{
		From: []Label{*lblQA, *lblFoo},
		To:   []Label{*lblBar, *lblQA},
	}

	// [Foo, Prod] -> [Bar,Prod]
	prodFooToProdBar := SearchContext{
		From: []Label{*lblProd, *lblFoo},
		To:   []Label{*lblBar},
	}

	// [Foo,QA] -> [Bar,prod]
	qaFooToProdBar := SearchContext{
		From: []Label{*lblQA, *lblFoo},
		To:   []Label{*lblBar, *lblProd},
	}

	// [Foo,QA, Joe] -> [Bar,prod]
	qaJoeFooToProdBar := SearchContext{
		From: []Label{*lblQA, *lblFoo, *lblJoe},
		To:   []Label{*lblBar, *lblProd},
	}

	// [Foo,QA, Pete] -> [Bar,Prod]
	qaPeteFooToProdBar := SearchContext{
		From: []Label{*lblQA, *lblFoo, *lblPete},
		To:   []Label{*lblBar, *lblProd},
	}

	// [Baz, QA] -> Bar
	qaBazToQaBar := SearchContext{
		From: []Label{*lblQA, *lblBaz},
		To:   []Label{*lblQA, *lblBar},
	}

	rootNode := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Rules: []PolicyRule{
			&PolicyRuleConsumers{
				Coverage: []Label{*lblBar},
				Allow: []AllowRule{
					AllowRule{ // always-allow:  user=joe
						Action: ALWAYS_ACCEPT,
						Label:  *lblJoe,
					},
					AllowRule{ // allow:  user=pete
						Action: ACCEPT,
						Label:  *lblPete,
					},
				},
			},
			&PolicyRuleRequires{ // coverage qa, requires qa
				Coverage: []Label{*lblQA},
				Requires: []Label{*lblQA},
			},
			&PolicyRuleRequires{ // coverage prod, requires: prod
				Coverage: []Label{*lblProd},
				Requires: []Label{*lblProd},
			},
			&PolicyRuleConsumers{
				Coverage: []Label{*lblBar},
				Allow: []AllowRule{
					AllowRule{ // allow: foo
						Action: ACCEPT,
						Label:  *lblFoo,
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)

	c.Assert(rootNode.Allows(&qaFooToQaBar), Equals, ACCEPT)
	c.Assert(rootNode.Allows(&prodFooToProdBar), Equals, ACCEPT)
	c.Assert(rootNode.Allows(&qaFooToProdBar), Equals, DENY)
	c.Assert(rootNode.Allows(&qaJoeFooToProdBar), Equals, ALWAYS_ACCEPT)
	c.Assert(rootNode.Allows(&qaPeteFooToProdBar), Equals, DENY)
	c.Assert(rootNode.Allows(&qaBazToQaBar), Equals, UNDECIDED)
}

func (s *CommonSuite) TestResolveTree(c *C) {
	rootNode := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{Rules: []PolicyRule{&PolicyRuleConsumers{}}},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)
	c.Assert(rootNode.Children["foo"].Name, Equals, "foo")
}

func (s *CommonSuite) TestPolicyTreeAllows(c *C) {
	lblProd := NewLabel("io.cilium.Prod", "", common.CiliumLabelSource)
	lblQA := NewLabel("io.cilium.QA", "", common.CiliumLabelSource)
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblBaz := NewLabel("io.cilium.baz", "", common.CiliumLabelSource)
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")
	lblPete := NewLabel("io.cilium.user", "pete", "kubernetes")

	// [Foo,QA] -> [Bar,QA]
	qaFooToQaBar := SearchContext{
		From: []Label{*lblQA, *lblFoo},
		To:   []Label{*lblQA, *lblBar},
	}

	// [Foo, Prod] -> [Bar,Prod]
	prodFooToProdBar := SearchContext{
		From: []Label{*lblProd, *lblFoo},
		To:   []Label{*lblBar},
	}

	// [Foo,QA] -> [Bar,Prod]
	qaFooToProdBar := SearchContext{
		From: []Label{*lblQA, *lblFoo},
		To:   []Label{*lblBar, *lblProd},
	}

	// [Foo,QA, Joe] -> [Bar,prod]
	qaJoeFooToProdBar := SearchContext{
		From: []Label{*lblQA, *lblFoo, *lblJoe},
		To:   []Label{*lblBar, *lblProd},
	}

	// [Foo,QA, Pete] -> [Bar,Prod]
	qaPeteFooToProdBar := SearchContext{
		From: []Label{*lblQA, *lblFoo, *lblPete},
		To:   []Label{*lblBar, *lblProd},
	}

	// [Baz, QA] -> Bar
	qaBazToQaBar := SearchContext{
		From: []Label{*lblQA, *lblBaz},
		To:   []Label{*lblQA, *lblBar},
	}

	rootNode := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Rules: []PolicyRule{
			&PolicyRuleConsumers{
				Coverage: []Label{*lblBar},
				Allow: []AllowRule{
					// always-allow: user=joe
					AllowRule{Action: ALWAYS_ACCEPT, Label: *lblJoe},
					// allow:  user=pete
					AllowRule{Action: ACCEPT, Label: *lblPete},
				},
			},
			&PolicyRuleRequires{ // coverage qa, requires qa
				Coverage: []Label{*lblQA},
				Requires: []Label{*lblQA},
			},
			&PolicyRuleRequires{ // coverage prod, requires: prod
				Coverage: []Label{*lblProd},
				Requires: []Label{*lblProd},
			},
		},
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{},
			"bar": &PolicyNode{
				Rules: []PolicyRule{
					&PolicyRuleConsumers{
						Allow: []AllowRule{
							AllowRule{ // allow: foo
								Action: ACCEPT,
								Label:  *lblFoo,
							},
							AllowRule{Action: DENY, Label: *lblJoe},
							AllowRule{Action: DENY, Label: *lblPete},
						},
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)

	root := PolicyTree{&rootNode}
	c.Assert(root.Allows(&qaFooToQaBar), Equals, ACCEPT)
	c.Assert(root.Allows(&prodFooToProdBar), Equals, ACCEPT)
	c.Assert(root.Allows(&qaFooToProdBar), Equals, DENY)
	c.Assert(root.Allows(&qaJoeFooToProdBar), Equals, ACCEPT)
	c.Assert(root.Allows(&qaPeteFooToProdBar), Equals, DENY)
	c.Assert(root.Allows(&qaBazToQaBar), Equals, DENY)

	_, err := json.MarshalIndent(rootNode, "", "    ")
	c.Assert(err, Equals, nil)
}

func (s *CommonSuite) TestPolicyNodeMerge(c *C) {
	// Name mismatch
	aNode := PolicyNode{Name: "a"}
	bNode := PolicyNode{Name: "b"}
	err := aNode.Merge(&bNode)
	c.Assert(err, Not(Equals), nil)

	// Empty nodes
	aOrig := PolicyNode{Name: "a"}
	aNode = PolicyNode{Name: "a"}
	bNode = PolicyNode{Name: "a"}
	err = aNode.Merge(&bNode)
	c.Assert(err, Equals, nil)
	c.Assert(aNode, DeepEquals, aOrig)

	lblProd := NewLabel("io.cilium.Prod", "", common.CiliumLabelSource)
	lblQA := NewLabel("io.cilium.QA", "", common.CiliumLabelSource)
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")
	lblPete := NewLabel("io.cilium.user", "pete", "kubernetes")

	aNode = PolicyNode{
		Name: common.GlobalLabelPrefix,
		Rules: []PolicyRule{
			&PolicyRuleRequires{ // coverage qa, requires qa
				Coverage: []Label{*lblQA},
				Requires: []Label{*lblQA},
			},
		},
		Children: map[string]*PolicyNode{
			"bar": &PolicyNode{
				Name: "bar",
				path: common.GlobalLabelPrefix + ".bar",
				Rules: []PolicyRule{
					&PolicyRuleConsumers{
						Allow: []AllowRule{
							AllowRule{Action: DENY, Label: *lblJoe},
							AllowRule{Action: DENY, Label: *lblPete},
						},
					},
				},
			},
		},
	}

	bNode = PolicyNode{
		Name: common.GlobalLabelPrefix,
		Rules: []PolicyRule{
			&PolicyRuleRequires{ // coverage prod, requires: prod
				Coverage: []Label{*lblProd},
				Requires: []Label{*lblProd},
			},
		},
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{
				Name: "foo",
				path: common.GlobalLabelPrefix + ".foo",
			},
			"bar": &PolicyNode{
				Name: "bar",
				path: common.GlobalLabelPrefix + ".bar",
				Rules: []PolicyRule{
					&PolicyRuleConsumers{
						Allow: []AllowRule{
							AllowRule{ // allow: foo
								Action: ACCEPT,
								Label:  *lblFoo,
							},
						},
					},
				},
			},
		},
	}

	aNode.Path()
	bNode.Path()

	err = aNode.Merge(&bNode)
	c.Assert(err, Equals, nil)
}

func (s *CommonSuite) TestSearchContextReplyJSON(c *C) {
	scr := SearchContextReply{
		Logging:  []byte(`foo`),
		Decision: ConsumableDecision(0x1),
	}
	scrWanted := SearchContextReply{
		Logging:  []byte(`foo`),
		Decision: ConsumableDecision(0x1),
	}
	b, err := json.Marshal(scr)
	c.Assert(err, IsNil)
	c.Assert(b, DeepEquals, []byte(`{"Logging":"Zm9v","Decision":"accept"}`))

	var scrGot SearchContextReply
	err = json.Unmarshal(b, &scrGot)
	c.Assert(err, IsNil)
	c.Assert(scrGot, DeepEquals, scrWanted)
}
