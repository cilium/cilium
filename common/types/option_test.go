package types

import (
	"bytes"
	"net"
	"testing"

	. "gopkg.in/check.v1"
)

func Test(t *testing.T) { TestingT(t) }

type OptionSuite struct{}

var _ = Suite(&OptionSuite{})

func (s *OptionSuite) TestGetFmtOpt(c *C) {
	o := BoolOptions{
		Opts: OptionMap{
			OptionPolicy: true,
			"BAR":        false,
		},
		Library: &OptionLibrary{
			OptionPolicy: &OptionSpecPolicy,
		},
	}
	c.Assert(o.GetFmtOpt(OptionPolicy), Equals, "#define "+OptionSpecPolicy.Define)
	c.Assert(o.GetFmtOpt("BAR"), Equals, "#undef BAR")
	c.Assert(o.GetFmtOpt("BAZ"), Equals, "#undef BAZ")
}

func (s *OptionSuite) TestOrderEndpointAsc(c *C) {
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
