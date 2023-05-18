// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package labels

import (
	. "github.com/cilium/checkmate"

	"github.com/cilium/cilium/pkg/checker"
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

func (s *LabelsSuite) TestLabelArrayListMergeSorted(c *C) {
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
	list7 := LabelArrayList{
		{
			NewLabel("env", "prod", LabelSourceAny),
			NewLabel("user", "alice", LabelSourceContainer),
		},
	}

	expected1 := LabelArrayList{
		{
			NewLabel("env", "devel", LabelSourceAny),
			NewLabel("user", "bob", LabelSourceContainer),
		},
		{
			NewLabel("foo", "bar", LabelSourceAny),
		},
	}

	cases := []struct {
		name     string
		a, b     LabelArrayList
		expected LabelArrayList
	}{
		{name: "same list", a: list1, b: list1, expected: expected1},
		{name: "equal lists", a: list1, b: list2, expected: expected1},
		{name: "unsorted equal lists", a: list1, b: list3, expected: expected1},
		{name: "list b contained in list a", a: list1, b: list4, expected: expected1},
		{name: "list a contained in list b", a: list4, b: list1, expected: expected1},
		{name: "nil label arrays", a: list1, b: list5, expected: list1},
		{name: "empty label array lists", a: list1, b: list6, expected: list1},
		{name: "two different lists", a: list1, b: list7, expected: LabelArrayList{
			{
				NewLabel("env", "devel", LabelSourceAny),
				NewLabel("user", "bob", LabelSourceContainer),
			},
			{
				NewLabel("env", "prod", LabelSourceAny),
				NewLabel("user", "alice", LabelSourceContainer),
			},
			{
				NewLabel("foo", "bar", LabelSourceAny),
			},
		}},
	}

	for _, tc := range cases {
		// Copy to avoid polluting lists for the next cases.
		a := tc.a.DeepCopy()
		b := tc.b.DeepCopy()
		a.Merge(b...)
		c.Assert(a, checker.DeepEquals, tc.expected, Commentf(tc.name))
		c.Assert(a, checker.DeepEquals, a.Sort(), Commentf(tc.name+" returned unsorted result"))
	}
}
