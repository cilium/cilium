package server

import (
	"errors"
	"strings"

	"github.com/noironetworks/cilium-net/common/types"

	. "gopkg.in/check.v1"
)

func (s *DaemonSuite) TestDaemonUpdateOK(c *C) {
	optsWanted := types.OptionMap{"FOO": true}

	s.d.OnUpdate = func(opts types.OptionMap) error {
		c.Assert(opts, DeepEquals, optsWanted)
		return nil
	}

	err := s.c.Update(optsWanted)
	c.Assert(err, IsNil)

	s.d.OnUpdate = func(opts types.OptionMap) error {
		c.Assert(opts, IsNil)
		return nil
	}
	err = s.c.Update(nil)
	c.Assert(err, IsNil)
}

func (s *DaemonSuite) TestUpdateFail(c *C) {
	optsWanted := types.OptionMap{"FOO": true}

	s.d.OnUpdate = func(opts types.OptionMap) error {
		c.Assert(opts, DeepEquals, optsWanted)
		return errors.New("invalid option")
	}

	err := s.c.Update(optsWanted)
	c.Assert(strings.Contains(err.Error(), "invalid option"), Equals, true)
}
