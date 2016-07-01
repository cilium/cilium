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
			OptionDisablePolicy: true,
			"BAR":               false,
		},
		Library: &OptionLibrary{
			OptionDisablePolicy: &OptionSpecDisablePolicy,
		},
	}
	c.Assert(o.GetFmtOpt(OptionDisablePolicy), Equals, "#define "+OptionSpecDisablePolicy.Define)
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
