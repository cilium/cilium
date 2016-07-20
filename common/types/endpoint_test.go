package types

import (
	"bytes"
	"testing"

	"github.com/noironetworks/cilium-net/common/addressing"

	. "gopkg.in/check.v1"
)

var (
	IPv6Addr, _ = addressing.NewCiliumIPv6("beef:beef:beef:beef:aaaa:aaaa:1111:1112")
	IPv4Addr, _ = addressing.NewCiliumIPv4("10.11.12.13")
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct{}

var _ = Suite(&EndpointSuite{})

func (s *EndpointSuite) TestEndpointID(c *C) {
	e := Endpoint{IPv6: IPv6Addr, IPv4: IPv4Addr}
	e.SetID()
	c.Assert(e.ID, Equals, uint16(4370)) //"0x1112"
	c.Assert(bytes.Compare(e.IPv6, IPv6Addr) == 0, Equals, true)
	c.Assert(bytes.Compare(e.IPv4, IPv4Addr) == 0, Equals, true)
}

func (s *EndpointSuite) TestOrderEndpointAsc(c *C) {
	eps := []Endpoint{
		Endpoint{ID: 5},
		Endpoint{ID: 1000},
		Endpoint{ID: 1},
		Endpoint{ID: 3},
		Endpoint{ID: 2},
	}
	epsWant := []Endpoint{
		Endpoint{ID: 1},
		Endpoint{ID: 2},
		Endpoint{ID: 3},
		Endpoint{ID: 5},
		Endpoint{ID: 1000},
	}
	OrderEndpointAsc(eps)
	c.Assert(eps, DeepEquals, epsWant)
}
