package types

import (
	"bytes"
	"net"
	"testing"

	. "gopkg.in/check.v1"
)

var (
	EpAddr = net.IP{0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xbe, 0xef, 0xaa, 0xaa, 0xaa, 0xaa, 0x11, 0x11, 0x11, 0x12}
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type EndpointSuite struct{}

var _ = Suite(&EndpointSuite{})

func (s *EndpointSuite) TestEndpointID(c *C) {
	e := Endpoint{LXCIP: EpAddr}
	e.SetID()
	c.Assert(e.ID, Equals, "4370") //"0x1112"
	c.Assert(bytes.Compare(e.LXCIP, EpAddr) == 0, Equals, true)
}

func (s *EndpointSuite) TestGetFmtOpt(c *C) {
	e := Endpoint{
		Opts: OptionMap{
			OptionPolicy: true,
			"BAR":        false,
		},
	}
	c.Assert(e.GetFmtOpt(OptionPolicy), Equals, "#define "+OptionSpecPolicy.Define)
	c.Assert(e.GetFmtOpt("BAR"), Equals, "#undef BAR")
	c.Assert(e.GetFmtOpt("BAZ"), Equals, "#undef BAZ")
}

func (s *EndpointSuite) TestOrderEndpointAsc(c *C) {
	eps := []Endpoint{
		Endpoint{ID: "5"},
		Endpoint{ID: "1000"},
		Endpoint{ID: "1"},
		Endpoint{ID: "3"},
		Endpoint{ID: "2"},
	}
	epsWant := []Endpoint{
		Endpoint{ID: "1"},
		Endpoint{ID: "2"},
		Endpoint{ID: "3"},
		Endpoint{ID: "5"},
		Endpoint{ID: "1000"},
	}
	OrderEndpointAsc(eps)
	c.Assert(eps, DeepEquals, epsWant)
}
