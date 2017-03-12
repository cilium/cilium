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

package policy

import (
	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestNormalizeNames(c *C) {
	n := Node{}
	path, err := n.NormalizeNames(RootNodeName)
	c.Assert(err, IsNil)
	c.Assert(path, Equals, RootNodeName)
	c.Assert(n.Name, Equals, RootNodeName)

	n = Node{Name: "foo"}
	path, err = n.NormalizeNames(RootNodeName)
	c.Assert(err, IsNil)
	c.Assert(path, Equals, RootNodeName)
	c.Assert(n.Name, Equals, "foo")

	n = Node{}
	path, err = n.NormalizeNames("root.foo.bar")
	c.Assert(err, IsNil)
	c.Assert(path, Equals, "root.foo")
	c.Assert(n.Name, Equals, "bar")

	// absolute name foo.bar does not match path .bar.foo
	n = Node{Name: "foo.bar"}
	path, err = n.NormalizeNames("root.bar.foo")
	c.Assert(err, Not(IsNil))
	c.Assert(path, Equals, "")

	// absolute name root.foo.bar matches path .bar.foo
	n = Node{Name: "root.foo.bar"}
	path, err = n.NormalizeNames("root.foo")
	c.Assert(err, IsNil)
	c.Assert(path, Equals, "root.foo")
	c.Assert(n.Name, Equals, "bar")

	// absolute name foo.bar2 does not match path baz
	n = Node{
		Children: map[string]*Node{
			"bar": {Name: "foo.bar2"},
		},
	}
	path, err = n.NormalizeNames("baz")
	c.Assert(err, Not(IsNil))
	c.Assert(path, Equals, "")

	n = Node{
		Children: map[string]*Node{
			"bar": {Name: "bar2"},
		},
	}
	path, err = n.NormalizeNames(".")
	c.Assert(err, Not(IsNil))
	c.Assert(path, Equals, "")
}
