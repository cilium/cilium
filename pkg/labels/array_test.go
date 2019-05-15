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

// +build !privileged_tests

package labels

import (
	"github.com/cilium/cilium/pkg/checker"

	. "gopkg.in/check.v1"
)

var _ = Suite(&LabelsSuite{})

func (s *LabelsSuite) TestMatches(c *C) {
	a := LabelArray{
		NewLabel("1", "1", "1"),
		NewLabel("2", "2", "1"),
		NewLabel("3", "3", "1"),
	}
	b := LabelArray{
		NewLabel("1", "1", "1"),
		NewLabel("2", "2", "1"),
	}
	empty := LabelArray{}

	c.Assert(a.Contains(b), Equals, true)      // b is in a
	c.Assert(b.Contains(a), Equals, false)     // a is NOT in b
	c.Assert(a.Contains(empty), Equals, true)  // empty is in a
	c.Assert(b.Contains(empty), Equals, true)  // empty is in b
	c.Assert(empty.Contains(a), Equals, false) // a is NOT in empty
}

func (s *LabelsSuite) TestParse(c *C) {
	c.Assert(ParseLabelArray(), checker.DeepEquals, LabelArray{})
	c.Assert(ParseLabelArray("magic"), checker.DeepEquals, LabelArray{ParseLabel("magic")})
	// LabelArray is sorted
	c.Assert(ParseLabelArray("a", "c", "b"), checker.DeepEquals,
		LabelArray{ParseLabel("a"), ParseLabel("b"), ParseLabel("c")})
	// NewLabelArrayFromSortedList
	c.Assert(NewLabelArrayFromSortedList("unspec:a=;unspec:b;unspec:c=d"), checker.DeepEquals,
		LabelArray{ParseLabel("a"), ParseLabel("b"), ParseLabel("c=d")})
}

func (s *LabelsSuite) TestHas(c *C) {
	lbls := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	var hasTests = []struct {
		input    string // input
		expected bool   // expected result
	}{
		{"", false},
		{"any", false},
		{"env", true},
		{"container.env", false},
		{"container:env", false},
		{"any:env", false},
		{"any.env", true},
		{"any:user", false},
		{"any.user", true},
		{"user", true},
		{"container.user", true},
		{"container:bob", false},
	}
	for _, tt := range hasTests {
		c.Logf("has %q?", tt.input)
		c.Assert(lbls.Has(tt.input), Equals, tt.expected)
	}
}

func (s *LabelsSuite) TestSame(c *C) {
	lbls1 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	lbls2 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
		NewLabel("user", "bob", LabelSourceContainer),
	}
	lbls3 := LabelArray{
		NewLabel("user", "bob", LabelSourceContainer),
		NewLabel("env", "devel", LabelSourceAny),
	}
	lbls4 := LabelArray{
		NewLabel("env", "devel", LabelSourceAny),
	}
	lbls5 := LabelArray{
		NewLabel("env", "prod", LabelSourceAny),
	}
	lbls6 := LabelArray{}

	c.Assert(lbls1.Same(lbls1), Equals, true)
	c.Assert(lbls1.Same(lbls2), Equals, true)
	c.Assert(lbls1.Same(lbls3), Equals, false) // inverted order
	c.Assert(lbls1.Same(lbls4), Equals, false) // different count
	c.Assert(lbls1.Same(lbls5), Equals, false)
	c.Assert(lbls1.Same(lbls6), Equals, false)

	c.Assert(lbls2.Same(lbls1), Equals, true)
	c.Assert(lbls2.Same(lbls2), Equals, true)
	c.Assert(lbls2.Same(lbls3), Equals, false) // inverted order
	c.Assert(lbls2.Same(lbls4), Equals, false) // different count
	c.Assert(lbls2.Same(lbls5), Equals, false)
	c.Assert(lbls2.Same(lbls6), Equals, false)

	c.Assert(lbls3.Same(lbls1), Equals, false)
	c.Assert(lbls3.Same(lbls2), Equals, false)
	c.Assert(lbls3.Same(lbls3), Equals, true)
	c.Assert(lbls3.Same(lbls4), Equals, false)
	c.Assert(lbls3.Same(lbls5), Equals, false)
	c.Assert(lbls3.Same(lbls6), Equals, false)

	c.Assert(lbls4.Same(lbls1), Equals, false)
	c.Assert(lbls4.Same(lbls2), Equals, false)
	c.Assert(lbls4.Same(lbls3), Equals, false)
	c.Assert(lbls4.Same(lbls4), Equals, true)
	c.Assert(lbls4.Same(lbls5), Equals, false)
	c.Assert(lbls4.Same(lbls6), Equals, false)

	c.Assert(lbls5.Same(lbls1), Equals, false)
	c.Assert(lbls5.Same(lbls2), Equals, false)
	c.Assert(lbls5.Same(lbls3), Equals, false)
	c.Assert(lbls5.Same(lbls4), Equals, false)
	c.Assert(lbls5.Same(lbls5), Equals, true)
	c.Assert(lbls5.Same(lbls6), Equals, false)

	c.Assert(lbls6.Same(lbls1), Equals, false)
	c.Assert(lbls6.Same(lbls2), Equals, false)
	c.Assert(lbls6.Same(lbls3), Equals, false)
	c.Assert(lbls6.Same(lbls4), Equals, false)
	c.Assert(lbls6.Same(lbls5), Equals, false)
	c.Assert(lbls6.Same(lbls6), Equals, true)
}
