package daemon

import (
	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

func (ds *DaemonSuite) TestFindNode(c *C) {
	var nullPtr *types.PolicyNode

	pn := types.PolicyNode{
		Name: "io.cilium",
		Children: map[string]*types.PolicyNode{
			"foo": &types.PolicyNode{},
			"bar": &types.PolicyNode{},
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
	pn := types.PolicyNode{
		Name: "io.cilium",
		Children: map[string]*types.PolicyNode{
			"foo": &types.PolicyNode{
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
