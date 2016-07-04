package types

import (
	. "gopkg.in/check.v1"
)

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
