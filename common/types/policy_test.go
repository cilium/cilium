package types

import (
	"encoding/json"
	"os"

	"github.com/noironetworks/cilium-net/common"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

type CommonSuite struct{}

var _ = Suite(&CommonSuite{})

func (s *CommonSuite) TestLabel(c *C) {
	var label Label

	longLabel := `{"source": "kubernetes", "key": "io.kubernetes.pod.name", "value": "foo"}`
	invLabel := `{"source": "kubernetes", "value": "foo"}`
	shortLabel := `"web"`

	err := json.Unmarshal([]byte(longLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, "kubernetes")
	c.Assert(label.AbsoluteKey(), Equals, "io.kubernetes.pod.name")
	c.Assert(label.Value, Equals, "foo")

	err = json.Unmarshal([]byte(invLabel), &label)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, "cilium")
	c.Assert(label.AbsoluteKey(), Equals, "web")
	c.Assert(label.Value, Equals, "")

	err = json.Unmarshal([]byte(""), &label)
	c.Assert(err, Not(Equals), nil)
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
	c.Assert(rule.Label.Source, Equals, "cilium")
	c.Assert(rule.Label.AbsoluteKey(), Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")

	err = json.Unmarshal([]byte(invertedLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Action, Equals, DENY)
	c.Assert(rule.Label.Source, Equals, "cilium")
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

	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	ctx := SearchContext{To: []Label{lblFoo}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, true)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)

	lblRoot := NewLabel("io.cilium", "", "cilium")
	ctx = SearchContext{To: []Label{lblRoot}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(root.Children["foo"].Covers(&ctx), Equals, false)
	c.Assert(root.Children["bar"].Covers(&ctx), Equals, false)
}

func (s *CommonSuite) TestLabelCompare(c *C) {
	a_1 := NewLabel("io.cilium", "", "")
	a_2 := NewLabel("io.cilium", "", "")
	b_1 := NewLabel("io.cilium.bar", "", "cilium")
	c_1 := NewLabel("io.cilium.bar", "", "kubernetes")
	d_1 := NewLabel("", "", "")

	c.Assert(a_1.Compare(&a_2), Equals, true)
	c.Assert(a_2.Compare(&a_1), Equals, true)
	c.Assert(a_1.Compare(&b_1), Equals, false)
	c.Assert(a_1.Compare(&c_1), Equals, false)
	c.Assert(a_1.Compare(&d_1), Equals, false)
	c.Assert(b_1.Compare(&c_1), Equals, false)
}

func (s *CommonSuite) TestAllowRule(c *C) {
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblBaz := NewLabel("io.cilium.baz", "", "cilium")
	allow := AllowRule{Action: ACCEPT, Label: lblFoo}
	deny := AllowRule{Action: DENY, Label: lblFoo}

	ctx := SearchContext{
		From: []Label{lblFoo},
		To:   []Label{lblBar},
	}
	ctx2 := SearchContext{
		From: []Label{lblBaz},
		To:   []Label{lblBar},
	}

	c.Assert(allow.Allows(&ctx), Equals, ACCEPT)
	c.Assert(deny.Allows(&ctx), Equals, DENY)
	c.Assert(allow.Allows(&ctx2), Equals, UNDECIDED)
	c.Assert(deny.Allows(&ctx2), Equals, UNDECIDED)
}

func (s *CommonSuite) TestTargetCoveredBy(c *C) {
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblBaz := NewLabel("io.cilium.baz", "", "cilium")
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")

	list1 := []Label{lblFoo}
	list2 := []Label{lblBar, lblBaz}
	list3 := []Label{lblFoo, lblJoe}

	// any -> io.cilium.bar
	ctx := SearchContext{To: []Label{lblBar}}
	c.Assert(ctx.TargetCoveredBy(&list1), Equals, false)
	c.Assert(ctx.TargetCoveredBy(&list2), Equals, true)
	c.Assert(ctx.TargetCoveredBy(&list3), Equals, false)

	// any -> kubernetes:io.cilium.baz
	ctx = SearchContext{To: []Label{lblBaz}}
	c.Assert(ctx.TargetCoveredBy(&list1), Equals, false)
	c.Assert(ctx.TargetCoveredBy(&list2), Equals, true)
	c.Assert(ctx.TargetCoveredBy(&list3), Equals, false)

	// any -> [kubernetes:io.cilium.user=joe, io.cilium.foo]
	ctx = SearchContext{To: []Label{lblJoe, lblFoo}}
	c.Assert(ctx.TargetCoveredBy(&list1), Equals, true)
	c.Assert(ctx.TargetCoveredBy(&list2), Equals, false)
	c.Assert(ctx.TargetCoveredBy(&list3), Equals, true)
}

func (s *CommonSuite) TestAllowConsumer(c *C) {
	lblTeamA := NewLabel("io.cilium.teamA", "", "cilium")
	lblTeamB := NewLabel("io.cilium.teamB", "", "cilium")
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblBaz := NewLabel("io.cilium.baz", "", "cilium")

	// [Foo,TeamA] -> Bar
	a_foo_to_bar := SearchContext{
		From: []Label{lblTeamA, lblFoo},
		To:   []Label{lblBar},
	}

	// [Baz, TeamA] -> Bar
	a_baz_to_bar := SearchContext{
		From: []Label{lblTeamA, lblBaz},
		To:   []Label{lblBar},
	}

	// [Foo,TeamB] -> Bar
	b_foo_to_bar := SearchContext{
		From: []Label{lblTeamB, lblFoo},
		To:   []Label{lblBar},
	}

	// [Baz, TeamB] -> Bar
	b_baz_to_bar := SearchContext{
		From: []Label{lblTeamB, lblBaz},
		To:   []Label{lblBar},
	}

	allowFoo := AllowRule{Action: ACCEPT, Label: lblFoo}
	dontAllowFoo := AllowRule{Action: DENY, Label: lblFoo}
	allowTeamA := AllowRule{Action: ACCEPT, Label: lblTeamA}
	dontAllowBaz := AllowRule{Action: DENY, Label: lblBaz}
	alwaysAllowFoo := AllowRule{Action: ALWAYS_ACCEPT, Label: lblFoo}

	// Allow: foo, !foo
	consumers := PolicyRuleConsumers{
		Coverage: []Label{lblBar},
		Allow:    []AllowRule{allowFoo, dontAllowFoo},
	}

	// NOTE: We are testing on single consumer rule leve, there is
	// no default deny policy enforced. No match equals UNDECIDED

	c.Assert(consumers.Allows(&a_foo_to_bar), Equals, DENY)
	c.Assert(consumers.Allows(&b_foo_to_bar), Equals, DENY)
	c.Assert(consumers.Allows(&a_baz_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_baz_to_bar), Equals, UNDECIDED)

	// Always-Allow: foo, !foo
	consumers = PolicyRuleConsumers{
		Coverage: []Label{lblBar},
		Allow:    []AllowRule{alwaysAllowFoo, dontAllowFoo},
	}

	c.Assert(consumers.Allows(&a_foo_to_bar), Equals, ALWAYS_ACCEPT)
	c.Assert(consumers.Allows(&b_foo_to_bar), Equals, ALWAYS_ACCEPT)
	c.Assert(consumers.Allows(&a_baz_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_baz_to_bar), Equals, UNDECIDED)

	// Allow: TeamA, !baz
	consumers = PolicyRuleConsumers{
		Coverage: []Label{lblBar},
		Allow:    []AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&a_foo_to_bar), Equals, ACCEPT)
	c.Assert(consumers.Allows(&a_baz_to_bar), Equals, DENY)
	c.Assert(consumers.Allows(&b_foo_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_baz_to_bar), Equals, DENY)

	// Allow: TeamA, !baz
	consumers = PolicyRuleConsumers{
		Coverage: []Label{lblFoo},
		Allow:    []AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&a_foo_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&a_baz_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_foo_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_baz_to_bar), Equals, UNDECIDED)
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

	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	consumer := PolicyRuleConsumers{Coverage: []Label{lblBar}}
	c.Assert(consumer.Resolve(&node), Not(Equals), nil)

	consumer2 := PolicyRuleRequires{Coverage: []Label{lblBar}}
	c.Assert(consumer2.Resolve(&node), Not(Equals), nil)

	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	consumer = PolicyRuleConsumers{Coverage: []Label{lblFoo}}
	c.Assert(consumer.Resolve(&node), Equals, nil)

	lblFoo = NewLabel("foo", "", "cilium")
	consumer = PolicyRuleConsumers{Coverage: []Label{lblFoo}}
	c.Assert(consumer.Resolve(&node), Equals, nil)
}

func (s *CommonSuite) TestRequires(c *C) {
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblBaz := NewLabel("io.cilium.baz", "", "cilium")

	// Foo -> Bar
	a_foo_to_bar := SearchContext{
		From: []Label{lblFoo},
		To:   []Label{lblBar},
	}

	// Baz -> Bar
	a_baz_to_bar := SearchContext{
		From: []Label{lblBaz},
		To:   []Label{lblBar},
	}

	// Bar -> Baz
	a_bar_to_baz := SearchContext{
		From: []Label{lblBar},
		To:   []Label{lblBaz},
	}

	// coverage: bar
	// Require: foo
	requires := PolicyRuleRequires{
		Coverage: []Label{lblBar},
		Requires: []Label{lblFoo},
	}

	c.Assert(requires.Allows(&a_foo_to_bar), Equals, UNDECIDED)
	c.Assert(requires.Allows(&a_baz_to_bar), Equals, DENY)
	c.Assert(requires.Allows(&a_bar_to_baz), Equals, UNDECIDED)
}

func (s *CommonSuite) TestPolicyNodeAllows(c *C) {
	lblProd := NewLabel("io.cilium.Prod", "", "cilium")
	lblQA := NewLabel("io.cilium.QA", "", "cilium")
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblBaz := NewLabel("io.cilium.baz", "", "cilium")
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")
	lblPete := NewLabel("io.cilium.user", "pete", "kubernetes")

	// [Foo,QA] -> [Bar,QA]
	qa_foo_to_qa_bar := SearchContext{
		From: []Label{lblQA, lblFoo},
		To:   []Label{lblBar, lblQA},
	}

	// [Foo, Prod] -> [Bar,Prod]
	prod_foo_to_prod_bar := SearchContext{
		From: []Label{lblProd, lblFoo},
		To:   []Label{lblBar},
	}

	// [Foo,QA] -> [Bar,prod]
	qa_foo_to_prod_bar := SearchContext{
		From: []Label{lblQA, lblFoo},
		To:   []Label{lblBar, lblProd},
	}

	// [Foo,QA, Joe] -> [Bar,prod]
	qa_joe_foo_to_prod_bar := SearchContext{
		From: []Label{lblQA, lblFoo, lblJoe},
		To:   []Label{lblBar, lblProd},
	}

	// [Foo,QA, Pete] -> [Bar,Prod]
	qa_pete_foo_to_prod_bar := SearchContext{
		From: []Label{lblQA, lblFoo, lblPete},
		To:   []Label{lblBar, lblProd},
	}

	// [Baz, QA] -> Bar
	qa_baz_to_qa_bar := SearchContext{
		From: []Label{lblQA, lblBaz},
		To:   []Label{lblQA, lblBar},
	}

	rootNode := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Rules: []interface{}{
			PolicyRuleConsumers{
				Coverage: []Label{lblBar},
				Allow: []AllowRule{
					AllowRule{ // always-allow:  user=joe
						Action: ALWAYS_ACCEPT,
						Label:  lblJoe,
					},
					AllowRule{ // allow:  user=pete
						Action: ACCEPT,
						Label:  lblPete,
					},
				},
			},
			PolicyRuleRequires{ // coverage qa, requires qa
				Coverage: []Label{lblQA},
				Requires: []Label{lblQA},
			},
			PolicyRuleRequires{ // coverage prod, requires: prod
				Coverage: []Label{lblProd},
				Requires: []Label{lblProd},
			},
			PolicyRuleConsumers{
				Coverage: []Label{lblBar},
				Allow: []AllowRule{
					AllowRule{ // allow: foo
						Action: ACCEPT,
						Label:  lblFoo,
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)

	c.Assert(rootNode.Allows(&qa_foo_to_qa_bar), Equals, ACCEPT)
	c.Assert(rootNode.Allows(&prod_foo_to_prod_bar), Equals, ACCEPT)
	c.Assert(rootNode.Allows(&qa_foo_to_prod_bar), Equals, DENY)
	c.Assert(rootNode.Allows(&qa_joe_foo_to_prod_bar), Equals, ALWAYS_ACCEPT)
	c.Assert(rootNode.Allows(&qa_pete_foo_to_prod_bar), Equals, DENY)
	c.Assert(rootNode.Allows(&qa_baz_to_qa_bar), Equals, UNDECIDED)
}

func (s *CommonSuite) TestResolveTree(c *C) {
	rootNode := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{Rules: []interface{}{PolicyRuleConsumers{}}},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)
	c.Assert(rootNode.Children["foo"].Name, Equals, "foo")
}

func (s *CommonSuite) TestPolicyTreeAllows(c *C) {
	lblProd := NewLabel("io.cilium.Prod", "", "cilium")
	lblQA := NewLabel("io.cilium.QA", "", "cilium")
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblBaz := NewLabel("io.cilium.baz", "", "cilium")
	lblJoe := NewLabel("io.cilium.user", "joe", "kubernetes")
	lblPete := NewLabel("io.cilium.user", "pete", "kubernetes")

	// [Foo,QA] -> [Bar,QA]
	qa_foo_to_qa_bar := SearchContext{
		From: []Label{lblQA, lblFoo},
		To:   []Label{lblBar, lblQA},
	}

	// [Foo, Prod] -> [Bar,Prod]
	prod_foo_to_prod_bar := SearchContext{
		From: []Label{lblProd, lblFoo},
		To:   []Label{lblBar},
	}

	// [Foo,QA] -> [Bar,Prod]
	qa_foo_to_prod_bar := SearchContext{
		From: []Label{lblQA, lblFoo},
		To:   []Label{lblBar, lblProd},
	}

	// [Foo,QA, Joe] -> [Bar,prod]
	qa_joe_foo_to_prod_bar := SearchContext{
		From: []Label{lblQA, lblFoo, lblJoe},
		To:   []Label{lblBar, lblProd},
	}

	// [Foo,QA, Pete] -> [Bar,Prod]
	qa_pete_foo_to_prod_bar := SearchContext{
		From: []Label{lblQA, lblFoo, lblPete},
		To:   []Label{lblBar, lblProd},
	}

	// [Baz, QA] -> Bar
	qa_baz_to_qa_bar := SearchContext{
		From: []Label{lblQA, lblBaz},
		To:   []Label{lblQA, lblBar},
	}

	rootNode := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Rules: []interface{}{
			PolicyRuleConsumers{
				Coverage: []Label{lblBar},
				Allow: []AllowRule{
					// always-allow: user=joe
					AllowRule{Action: ALWAYS_ACCEPT, Label: lblJoe},
					// allow:  user=pete
					AllowRule{Action: ACCEPT, Label: lblPete},
				},
			},
			PolicyRuleRequires{ // coverage qa, requires qa
				Coverage: []Label{lblQA},
				Requires: []Label{lblQA},
			},
			PolicyRuleRequires{ // coverage prod, requires: prod
				Coverage: []Label{lblProd},
				Requires: []Label{lblProd},
			},
		},
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{},
			"bar": &PolicyNode{
				Rules: []interface{}{
					PolicyRuleConsumers{
						Allow: []AllowRule{
							AllowRule{ // allow: foo
								Action: ACCEPT,
								Label:  lblFoo,
							},
							AllowRule{Action: DENY, Label: lblJoe},
							AllowRule{Action: DENY, Label: lblPete},
						},
					},
				},
			},
		},
	}

	c.Assert(rootNode.ResolveTree(), Equals, nil)

	root := PolicyTree{rootNode}
	c.Assert(root.Allows(&qa_foo_to_qa_bar), Equals, ACCEPT)
	c.Assert(root.Allows(&prod_foo_to_prod_bar), Equals, ACCEPT)
	c.Assert(root.Allows(&qa_foo_to_prod_bar), Equals, DENY)
	c.Assert(root.Allows(&qa_joe_foo_to_prod_bar), Equals, ACCEPT)
	c.Assert(root.Allows(&qa_pete_foo_to_prod_bar), Equals, DENY)
	c.Assert(root.Allows(&qa_baz_to_qa_bar), Equals, DENY)

	os.Remove("/tmp/foo")
	f, err := os.Create("/tmp/foo")
	c.Assert(err, Equals, nil)
	defer f.Close()

	b, err := json.MarshalIndent(rootNode, "", "    ")
	c.Assert(err, Equals, nil)
	_, err = f.Write(b)
	c.Assert(err, Equals, nil)
	f.Sync()
}
