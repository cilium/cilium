package daemon

import (
	"github.com/noironetworks/cilium-net/common/types"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

func (ds *DaemonSuite) findNodeTest(c *C) {
	pn := types.PolicyNode{
		Name: "io.cilium",
	}

	err := ds.d.PolicyAdd("io.cilium", pn)
	c.Assert(err, Equals, nil)

}
