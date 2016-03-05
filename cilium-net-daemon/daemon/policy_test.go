package daemon

import (
	"encoding/json"
	"os"

	"github.com/noironetworks/cilium-net/common"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
	. "github.com/noironetworks/cilium-net/common/types"
)

func (ds *DaemonSuite) TestFindNode(c *C) {
	var nullPtr *PolicyNode

	pn := PolicyNode{
		Name: "io.cilium",
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{},
			"bar": &PolicyNode{},
		},
	}

	err := ds.d.PolicyAdd("io.cilium", pn)
	c.Assert(err, Equals, nil)

	n, p, err := findNode("io.cilium")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)
	c.Assert(p, Equals, nullPtr)

	n, p, err = findNode("io.cilium.foo")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)
	c.Assert(p, Not(Equals), nil)

	n, p, err = findNode("io.cilium.baz")
	c.Assert(err, Not(Equals), nil)
	c.Assert(n, Equals, nullPtr)
	c.Assert(p, Equals, nullPtr)

	n, p, err = findNode("")
	c.Assert(err, Not(Equals), nil)
	c.Assert(n, Equals, nullPtr)
	c.Assert(p, Equals, nullPtr)

	n, p, err = findNode("io.cilium..foo")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nullPtr)
	c.Assert(p, Not(Equals), nullPtr)

	err = ds.d.PolicyDelete("io.cilium")
	c.Assert(err, Equals, nil)
}

func (ds *DaemonSuite) TestPolicyGet(c *C) {
	pn := PolicyNode{
		Name: "io.cilium",
		Children: map[string]*PolicyNode{
			"foo": &PolicyNode{
				Name: "magic",
			},
		},
	}

	err := ds.d.PolicyAdd("io.cilium", pn)
	c.Assert(err, Equals, nil)

	n, err := ds.d.PolicyGet("io.cilium.foo")
	c.Assert(err, Equals, nil)
	c.Assert(n, Not(Equals), nil)

	err = ds.d.PolicyDelete("io.cilium.foo")
	c.Assert(err, Equals, nil)
}

func (ds *DaemonSuite) TestPolicyNodeAllows(c *C) {
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

	c.Assert(PolicyCanConsume(&rootNode, &qa_foo_to_qa_bar), Equals, ACCEPT)
	c.Assert(PolicyCanConsume(&rootNode, &prod_foo_to_prod_bar), Equals, ACCEPT)
	c.Assert(PolicyCanConsume(&rootNode, &qa_foo_to_prod_bar), Equals, DENY)
	c.Assert(PolicyCanConsume(&rootNode, &qa_joe_foo_to_prod_bar), Equals, ACCEPT)
	c.Assert(PolicyCanConsume(&rootNode, &qa_pete_foo_to_prod_bar), Equals, DENY)
	c.Assert(PolicyCanConsume(&rootNode, &qa_baz_to_qa_bar), Equals, DENY)

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
