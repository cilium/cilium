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
	lblProd := NewLabel("io.cilium.Prod", "", common.CiliumLabelSource)
	lblQA := NewLabel("io.cilium.QA", "", common.CiliumLabelSource)
	lblFoo := NewLabel("io.cilium.foo", "", common.CiliumLabelSource)
	lblBar := NewLabel("io.cilium.bar", "", common.CiliumLabelSource)
	lblJoe := NewLabel("io.cilium.user", "joe", common.CiliumLabelSource)
	lblPete := NewLabel("io.cilium.user", "pete", common.CiliumLabelSource)

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

	qaBarLbls := Labels{lblBar.Key: &lblBar, lblQA.Key: &lblQA}
	qaBarSecLblsCtx, _, err := ds.d.PutLabels(qaBarLbls)
	c.Assert(err, Equals, nil)

	prodBarLbls := Labels{lblBar.Key: &lblBar, lblProd.Key: &lblProd}
	prodBarSecLblsCtx, _, err := ds.d.PutLabels(prodBarLbls)
	c.Assert(err, Equals, nil)

	qaFooLbls := Labels{lblFoo.Key: &lblFoo, lblQA.Key: &lblQA}
	qaFooSecLblsCtx, _, err := ds.d.PutLabels(qaFooLbls)
	c.Assert(err, Equals, nil)

	prodFooLbls := Labels{lblFoo.Key: &lblFoo, lblProd.Key: &lblProd}
	prodFooSecLblsCtx, _, err := ds.d.PutLabels(prodFooLbls)
	c.Assert(err, Equals, nil)

	prodFooJoeLbls := Labels{lblFoo.Key: &lblFoo, lblProd.Key: &lblProd, lblJoe.Key: &lblJoe}
	prodFooJoeSecLblsCtx, _, err := ds.d.PutLabels(prodFooJoeLbls)
	c.Assert(err, Equals, nil)

	e := Endpoint{SecLabel: uint32(qaBarSecLblsCtx.ID)}
	err = ds.d.RegenerateConsumerMap(&e)
	c.Assert(err, Equals, nil)
	c.Assert(e.AllowsSecLabel(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(qaFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.AllowsSecLabel(prodFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prodFooJoeSecLblsCtx.ID), Equals, true)

	e = Endpoint{SecLabel: uint32(prodBarSecLblsCtx.ID)}
	err = ds.d.RegenerateConsumerMap(&e)
	c.Assert(err, Equals, nil)
	c.Assert(e.AllowsSecLabel(0), Equals, false)
	c.Assert(e.AllowsSecLabel(qaBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prodBarSecLblsCtx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(qaFooSecLblsCtx.ID), Equals, false)
	c.Assert(e.AllowsSecLabel(prodFooSecLblsCtx.ID), Equals, true)
	c.Assert(e.AllowsSecLabel(prodFooJoeSecLblsCtx.ID), Equals, true)

	err = ds.d.PolicyDelete("io.cilium")
	c.Assert(err, Equals, nil)
}
