package daemon

import (
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

func (ds *DaemonSuite) TestUpdateConsumerMap(c *C) {
	lblProd := NewLabel("io.cilium.Prod", "", "cilium")
	lblQA := NewLabel("io.cilium.QA", "", "cilium")
	lblFoo := NewLabel("io.cilium.foo", "", "cilium")
	lblBar := NewLabel("io.cilium.bar", "", "cilium")
	lblJoe := NewLabel("io.cilium.user", "joe", "cilium")
	lblPete := NewLabel("io.cilium.user", "pete", "cilium")

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

	err := ds.d.PolicyAdd("io.cilium", rootNode)
	c.Assert(err, Equals, nil)

	qa_bar_lbls := Labels{lblBar.Key: &lblBar, lblQA.Key: &lblQA}
	qa_bar_sec_lbls_ctx, _, err := ds.d.PutLabels(qa_bar_lbls)
	c.Assert(err, Equals, nil)

	prod_bar_lbls := Labels{lblBar.Key: &lblBar, lblProd.Key: &lblProd}
	prod_bar_sec_lbls_ctx, _, err := ds.d.PutLabels(prod_bar_lbls)
	c.Assert(err, Equals, nil)

	qa_foo_lbls := Labels{lblFoo.Key: &lblFoo, lblQA.Key: &lblQA}
	qa_foo_sec_lbls_ctx, _, err := ds.d.PutLabels(qa_foo_lbls)
	c.Assert(err, Equals, nil)

	prod_foo_lbls := Labels{lblFoo.Key: &lblFoo, lblProd.Key: &lblProd}
	prod_foo_sec_lbls_ctx, _, err := ds.d.PutLabels(prod_foo_lbls)
	c.Assert(err, Equals, nil)

	prod_foo_joe_lbls := Labels{lblFoo.Key: &lblFoo, lblProd.Key: &lblProd, lblJoe.Key: &lblJoe}
	prod_foo_joe_sec_lbls_ctx, _, err := ds.d.PutLabels(prod_foo_joe_lbls)
	c.Assert(err, Equals, nil)

	e := Endpoint{SecLabel: uint32(qa_bar_sec_lbls_ctx.ID)}
	err = ds.d.RegenerateConsumerMap(&e)
	c.Assert(err, Equals, nil)
	c.Assert(e.AllowsSecLabel(qa_bar_sec_lbls_ctx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prod_bar_sec_lbls_ctx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(qa_foo_sec_lbls_ctx.ID), Equals, true)
	c.Assert(e.AllowsSecLabel(prod_foo_sec_lbls_ctx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prod_foo_joe_sec_lbls_ctx.ID), Equals, true)

	e = Endpoint{SecLabel: uint32(prod_bar_sec_lbls_ctx.ID)}
	err = ds.d.RegenerateConsumerMap(&e)
	c.Assert(err, Equals, nil)
	c.Assert(e.AllowsSecLabel(0), Equals, false)
	c.Assert(e.AllowsSecLabel(qa_bar_sec_lbls_ctx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prod_bar_sec_lbls_ctx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(qa_foo_sec_lbls_ctx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prod_foo_sec_lbls_ctx.ID), Equals, true)
	c.Assert(e.AllowsSecLabel(prod_foo_joe_sec_lbls_ctx.ID), Equals, true)

	err = ds.d.PolicyDelete("io.cilium")
	c.Assert(err, Equals, nil)
}
