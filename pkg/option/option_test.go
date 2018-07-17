// Copyright 2016-2017 Authors of Cilium
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

package option

import (
	"testing"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) {
	TestingT(t)
}

type OptionSuite struct{}

var _ = Suite(&OptionSuite{})

func (s *OptionSuite) TestGetFmtOpts(c *C) {
	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		Opts: OptionMap{
			"test": OptionEnabled,
			"BAR":  OptionDisabled,
			"foo":  OptionEnabled,
			"bar":  OptionDisabled,
		},
		Library: &OptionLibrary{
			"test": &OptionTest,
		},
	}

	fmtList := o.GetFmtList()
	fmtList2 := o.GetFmtList()

	// Both strings should be equal because the formatted options should be sorted.
	c.Assert(fmtList, Equals, fmtList2)

	o2 := IntOptions{
		Opts: OptionMap{
			"foo":  OptionEnabled,
			"BAR":  OptionDisabled,
			"bar":  OptionDisabled,
			"test": OptionEnabled,
		},
		Library: &OptionLibrary{
			"test": &OptionTest,
		},
	}

	fmtListO := o.GetFmtList()
	fmtListO2 := o2.GetFmtList()

	// Both strings should be equal because the formatted options should be sorted.
	c.Assert(fmtListO, Equals, fmtListO2)
}

func (s *OptionSuite) TestGetFmtOpt(c *C) {
	OptionTest := Option{
		Define:      "TEST_DEFINE",
		Description: "This is a test",
	}

	o := IntOptions{
		Opts: OptionMap{
			"test":  OptionEnabled,
			"BAR":   OptionDisabled,
			"alice": 2,
		},
		Library: &OptionLibrary{
			"test":  &OptionTest,
			"alice": &OptionTest,
		},
	}
	o.optsMU.Lock()
	c.Assert(o.getFmtOpt("test"), Equals, "#define TEST_DEFINE 1")
	c.Assert(o.getFmtOpt("BAR"), Equals, "#undef BAR")
	c.Assert(o.getFmtOpt("BAZ"), Equals, "#undef BAZ")
	c.Assert(o.getFmtOpt("alice"), Equals, "#define TEST_DEFINE 2")
	o.optsMU.Unlock()
}
