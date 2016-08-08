package addressing

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type AddressingSuite struct{}

var _ = Suite(&AddressingSuite{})

func (s *AddressingSuite) TestNewNodeAddress(c *C) {
	n, err := NewNodeAddress("b007::aaaa:bbbb:0:0", "10.1.0.1", "")
	c.Assert(err, Equals, nil)
	c.Assert(n.String(), Equals, "b007::aaaa:bbbb:0:0")
	c.Assert(n.IPv6Address.EndpointID(), Equals, uint16(0))
	c.Assert(n.IPv6Address.State(), Equals, uint16(0))
	c.Assert(n.IPv6Address.NodeID(), Equals, uint32(0xaaaabbbb))
	c.Assert(n.IPv4Address.EndpointID(), Equals, uint16(1))
	c.Assert(n.IPv4Address.NodeID(), Equals, uint32(0xa010000))

	n, err = NewNodeAddress("b007::", "20.2.0.1", "")
	c.Assert(err, Equals, nil)
	c.Assert(n.IPv6Address.EndpointID(), Equals, uint16(0))
	c.Assert(n.IPv6Address.State(), Equals, uint16(0))
	c.Assert(n.IPv6Address.NodeID(), Not(Equals), uint32(0))
	c.Assert(n.IPv4Address.EndpointID(), Equals, uint16(1))
	c.Assert(n.IPv4Address.NodeID(), Equals, uint32(0x14020000))

	// container bits set, should fail
	_, err = NewNodeAddress("b007::aaaa:bbbb:0:1", "10.1.0.0", "")
	c.Assert(err, Equals, ErrNodeIPEndpointIDSet)

	_, err = NewNodeAddress("b007::aaaa:bbbb:0:0", "0.0.0.0", "")
	c.Assert(err, Equals, ErrIPv4Invalid)

	_, err = NewNodeAddress("b007::aaaa:bbbb:0:1", "10.0.1.0", "")
	c.Assert(err, Equals, ErrNodeIPEndpointIDSet)
}
