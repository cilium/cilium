package common

import (
	"bytes"
	"net"
	"testing"

	. "github.com/noironetworks/cilium-net/common/Godeps/_workspace/src/gopkg.in/check.v1"
)

var (
	EpAddr   = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x11}
	NodeAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0, 0}
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

	c.Assert(bytes.Compare(node, NodeAddr) != 0, Equals, false,
		Commentf("MapEndpointToNode failed: %s != %s", node.String(), NodeAddr.String()))
}
