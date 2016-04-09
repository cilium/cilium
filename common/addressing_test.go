package common

import (
	"bytes"
	"net"
	"testing"

	. "github.com/noironetworks/cilium-net/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	EpAddr            = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
	Epv4Addr          = net.IP{0xc0, 0x0, 0x2, 0x78}
	Ep6to4Addr        = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x2, 0x78}
	NodeAddr          = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
	NodeID     uint32 = 0xaaaa1111
	EpID       uint16 = 0x1112
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type CommonSuite struct{}

var _ = Suite(&CommonSuite{})

func (s *CommonSuite) TestEpAddrEndpointAddress(c *C) {
	c.Assert(ValidEndpointAddress(EpAddr), Equals, true,
		Commentf("unexpected invalid EP address %s", EpAddr.String()))

	c.Assert(ValidEndpointAddress(NodeAddr), Equals, false,
		Commentf("unexpected valid node address %s", NodeAddr.String()))
}

func (s *CommonSuite) TestNodeAddrEndpointAddress(c *C) {
	c.Assert(ValidNodeAddress(EpAddr), Equals, false,
		Commentf("unexpected valid EP address %s", EpAddr.String()))

	c.Assert(ValidNodeAddress(NodeAddr), Equals, true,
		Commentf("unexpected invalid node address %s", NodeAddr.String()))
}

func (s *CommonSuite) TestMapEndpointToNode(c *C) {
	node := MapEndpointToNode(EpAddr)

	c.Assert(bytes.Compare(node, NodeAddr), Equals, 0,
		Commentf("MapEndpointToNode failed: %s != %s", node.String(), NodeAddr.String()))
}

func (s *CommonSuite) TestBuildEndpointAddress(c *C) {
	endAddr := Build4to6EndpointAddress(NodeAddr, Epv4Addr)

	c.Assert(ValidEndpointAddress(endAddr), Equals, true,
		Commentf("unexpected invalid EP address %s", endAddr.String()))

	c.Assert(ValidNodeAddress(endAddr), Equals, false,
		Commentf("unexpected valid node address %s", endAddr.String()))

	c.Assert(bytes.Compare(endAddr, Ep6to4Addr), Equals, 0,
		Commentf("Build4to6EndpointAddress failed: %s != %s",
			endAddr.String(), Ep6to4Addr.String()))
}

func (s *CommonSuite) TestNodeAddr2ID(c *C) {
	id := NodeAddr2ID(NodeAddr)

	c.Assert(id, Equals, NodeID,
		Commentf("NodeAddr2ID failed: %s != %x != %x", NodeAddr.String(), id, NodeID))
}

func (s *CommonSuite) TestEndpointAddr2ID(c *C) {
	id := EndpointAddr2ID(EpAddr)

	c.Assert(id, Equals, EpID,
		Commentf("EndpointAddr2ID failed: %s != %x != %x", EpAddr.String(), id, EpID))
}
