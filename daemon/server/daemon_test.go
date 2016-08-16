//
// Copyright 2016 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
package server

import (
	"errors"
	"strings"

	"github.com/cilium/cilium/common/types"

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
