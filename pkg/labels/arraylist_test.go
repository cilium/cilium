// Copyright 2020 Authors of Cilium
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

// +build !privileged_tests

package labels

import (
	"github.com/cilium/cilium/pkg/checker"
	. "gopkg.in/check.v1"
)

func (s *LabelsSuite) TestLabelArrayListEquals(c *C) {
	list1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	list2 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	list3 := LabelArrayList{
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
	}
	list4 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
	}
	list5 := LabelArrayList(nil)
	list6 := LabelArrayList{}

	c.Assert(list1.Equals(list1), Equals, true)
	c.Assert(list1.Equals(list2), Equals, true)
	c.Assert(list1.Equals(list3), Equals, false)
	c.Assert(list1.Equals(list4), Equals, false)
	c.Assert(list1.Equals(list5), Equals, false)
	c.Assert(list1.Equals(list6), Equals, false)

	c.Assert(list2.Equals(list1), Equals, true)
	c.Assert(list2.Equals(list2), Equals, true)
	c.Assert(list2.Equals(list3), Equals, false)
	c.Assert(list2.Equals(list4), Equals, false)
	c.Assert(list2.Equals(list5), Equals, false)
	c.Assert(list2.Equals(list6), Equals, false)

	c.Assert(list3.Equals(list1), Equals, false)
	c.Assert(list3.Equals(list2), Equals, false)
	c.Assert(list3.Equals(list3), Equals, true)
	c.Assert(list3.Equals(list4), Equals, false)
	c.Assert(list3.Equals(list5), Equals, false)
	c.Assert(list3.Equals(list6), Equals, false)

	c.Assert(list4.Equals(list1), Equals, false)
	c.Assert(list4.Equals(list2), Equals, false)
	c.Assert(list4.Equals(list3), Equals, false)
	c.Assert(list4.Equals(list4), Equals, true)
	c.Assert(list4.Equals(list5), Equals, false)
	c.Assert(list4.Equals(list6), Equals, false)

	c.Assert(list5.Equals(list1), Equals, false)
	c.Assert(list5.Equals(list2), Equals, false)
	c.Assert(list5.Equals(list3), Equals, false)
	c.Assert(list5.Equals(list4), Equals, false)
	c.Assert(list5.Equals(list5), Equals, true)
	c.Assert(list5.Equals(list6), Equals, true)

	c.Assert(list6.Equals(list1), Equals, false)
	c.Assert(list6.Equals(list2), Equals, false)
	c.Assert(list6.Equals(list3), Equals, false)
	c.Assert(list6.Equals(list4), Equals, false)
	c.Assert(list6.Equals(list5), Equals, true)
	c.Assert(list6.Equals(list6), Equals, true)
}

func (s *LabelsSuite) TestLabelArrayListSort(c *C) {
	c.Assert(LabelArrayList(nil).Sort(), checker.DeepEquals, LabelArrayList(nil))
	c.Assert(LabelArrayList{}.Sort(), checker.DeepEquals, LabelArrayList{})

	list1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
			NewLabel("xyz", "", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
		nil,
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}
	expected1 := LabelArrayList{
		nil,
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
			NewLabel("xyz", "", LabelSourceAny),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}

	c.Assert(list1.Sort(), checker.DeepEquals, expected1)

	list2 := LabelArrayList{
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
		{
			NewLabel("aaa", "", LabelSourceAny),
		},
	}
	expected2 := LabelArrayList{
		{
			NewLabel("aaa", "", LabelSourceAny),
		},
		{
			NewLabel("aaa", "", LabelSourceReserved),
		},
		{
			NewLabel("env", "devel", LabelSourceAny),
		},
	}
	c.Assert(list2.Sort(), checker.DeepEquals, expected2)
}
