package types

import (
	"encoding/json"

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
	c.Assert(label.Key, Equals, "io.kubernetes.pod.name")
	c.Assert(label.Value, Equals, "foo")
	c.Assert(label.String(), Equals, "io.kubernetes.pod.name=foo")

	err = json.Unmarshal([]byte(invLabel), &label)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &label)
	c.Assert(err, Equals, nil)
	c.Assert(label.Source, Equals, "cilium")
	c.Assert(label.Key, Equals, "web")
	c.Assert(label.Value, Equals, "")
	c.Assert(label.String(), Equals, "web")

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
	c.Assert(rule.Inverted, Equals, true)
	c.Assert(rule.Label.Source, Equals, "kubernetes")
	c.Assert(rule.Label.Key, Equals, "io.kubernetes.pod.name")
	c.Assert(rule.Label.Value, Equals, "foo")
	c.Assert(rule.Label.String(), Equals, "io.kubernetes.pod.name=foo")

	err = json.Unmarshal([]byte(invLabel), &rule)
	c.Assert(err, Not(Equals), nil)

	err = json.Unmarshal([]byte(shortLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Label.Source, Equals, "cilium")
	c.Assert(rule.Label.Key, Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")
	c.Assert(rule.Label.String(), Equals, "web")

	err = json.Unmarshal([]byte(invertedLabel), &rule)
	c.Assert(err, Equals, nil)
	c.Assert(rule.Inverted, Equals, true)
	c.Assert(rule.Label.Source, Equals, "cilium")
	c.Assert(rule.Label.Key, Equals, "web")
	c.Assert(rule.Label.Value, Equals, "")
	c.Assert(rule.Label.String(), Equals, "web")

	err = json.Unmarshal([]byte(""), &rule)
	c.Assert(err, Not(Equals), nil)
}

func (s *CommonSuite) TestPolicyNodeCovers(c *C) {
	foo := PolicyNode{
		Name: "foo",
	}
	bar := PolicyNode{
		Name: "bar",
	}
	root := PolicyNode{
		Name: common.GlobalLabelPrefix,
		Children: map[string]*PolicyNode{
			"foo": &foo,
			"bar": &bar,
		},
	}

	foo.Parent = &root
	bar.Parent = &root

	err := root.resolvePath()
	c.Assert(err, Equals, nil)

	lblFoo := Label{KeyValue{"io.cilium.foo", ""}, "cilium"}
	ctx := SearchContext{To: []Label{lblFoo}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(foo.Covers(&ctx), Equals, true)
	c.Assert(bar.Covers(&ctx), Equals, false)

	lblRoot := Label{KeyValue{"io.cilium", ""}, "cilium"}
	ctx = SearchContext{To: []Label{lblRoot}}
	c.Assert(root.Covers(&ctx), Equals, true)
	c.Assert(foo.Covers(&ctx), Equals, false)
	c.Assert(bar.Covers(&ctx), Equals, false)
}

func (s *CommonSuite) TestLabelCompare(c *C) {
	a_1 := Label{KeyValue{"io.cilium", ""}, "cilium"}
	a_2 := Label{KeyValue{"io.cilium", ""}, "cilium"}
	b_1 := Label{KeyValue{"io.cilium.bar", ""}, "cilium"}
	c_1 := Label{KeyValue{"io.cilium.bar", ""}, "kubernetes"}
	d_1 := Label{KeyValue{"", ""}, ""}

	c.Assert(a_1.Compare(&a_2), Equals, true)
	c.Assert(a_2.Compare(&a_1), Equals, true)
	c.Assert(a_1.Compare(&b_1), Equals, false)
	c.Assert(a_1.Compare(&c_1), Equals, false)
	c.Assert(a_1.Compare(&d_1), Equals, false)
	c.Assert(b_1.Compare(&c_1), Equals, false)
}

func (s *CommonSuite) TestAllowRule(c *C) {
	lblFoo := Label{KeyValue{"io.cilium.foo", ""}, "cilium"}
	lblBar := Label{KeyValue{"io.cilium.bar", ""}, "cilium"}
	lblBaz := Label{KeyValue{"io.cilium.baz", ""}, "cilium"}
	allow := AllowRule{Label: lblFoo}
	allowInverted := AllowRule{Inverted: true, Label: lblFoo}

	ctx := SearchContext{
		From: []Label{lblFoo},
		To:   []Label{lblBar},
	}
	ctx2 := SearchContext{
		From: []Label{lblBaz},
		To:   []Label{lblBar},
	}

	c.Assert(allow.Allows(&ctx), Equals, ACCEPT)
	c.Assert(allowInverted.Allows(&ctx), Equals, DENY)
	c.Assert(allow.Allows(&ctx2), Equals, UNDECIDED)
	c.Assert(allowInverted.Allows(&ctx2), Equals, UNDECIDED)
}

func (s *CommonSuite) TestAllowConsumer(c *C) {
	lblTeamA := Label{KeyValue{"io.cilium.teamA", ""}, "cilium"}
	lblTeamB := Label{KeyValue{"io.cilium.teamB", ""}, "cilium"}
	lblFoo := Label{KeyValue{"io.cilium.foo", ""}, "cilium"}
	lblBar := Label{KeyValue{"io.cilium.bar", ""}, "cilium"}
	lblBaz := Label{KeyValue{"io.cilium.baz", ""}, "cilium"}

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

	allowFoo := AllowRule{Label: lblFoo}
	dontAllowFoo := AllowRule{Inverted: true, Label: lblFoo}
	allowTeamA := AllowRule{Label: lblTeamA}
	dontAllowBaz := AllowRule{Inverted: true, Label: lblBaz}

	// Allow: foo, !foo
	consumers := PolicyRuleConsumers{
		Allow: []AllowRule{allowFoo, dontAllowFoo},
	}

	// NOTE: We are testing on single consumer rule leve, there is
	// no default deny policy enforced. No match equals UNDECIDED

	c.Assert(consumers.Allows(&a_foo_to_bar), Equals, DENY)
	c.Assert(consumers.Allows(&b_foo_to_bar), Equals, DENY)
	c.Assert(consumers.Allows(&a_baz_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_baz_to_bar), Equals, UNDECIDED)

	// Allow: TeamA, !baz
	consumers = PolicyRuleConsumers{
		Allow: []AllowRule{allowTeamA, dontAllowBaz},
	}

	c.Assert(consumers.Allows(&a_foo_to_bar), Equals, ACCEPT)
	c.Assert(consumers.Allows(&a_baz_to_bar), Equals, DENY)
	c.Assert(consumers.Allows(&b_foo_to_bar), Equals, UNDECIDED)
	c.Assert(consumers.Allows(&b_baz_to_bar), Equals, DENY)
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

	err = rootNode.resolvePath()
	c.Assert(err, Equals, nil)
	c.Assert(rootNode.path, Equals, common.GlobalLabelPrefix)
	c.Assert(fooNode.path, Equals, common.GlobalLabelPrefix+".foo")

}
