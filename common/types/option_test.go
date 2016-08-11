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
