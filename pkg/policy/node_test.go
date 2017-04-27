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
	// name:nil path:root => root node
	n := Node{}
	path, err := n.NormalizeNames(RootNodeName)
	c.Assert(err, IsNil)
	c.Assert(path, Equals, RootNodeName)
	c.Assert(n.Name, Equals, RootNodeName)

	// name:foo, path:root => foo@root
	n = Node{Name: "foo"}
	path, err = n.NormalizeNames(RootNodeName)
	c.Assert(err, IsNil)
	c.Assert(path, Equals, RootNodeName)
	c.Assert(n.Name, Equals, "foo")

	// name:nil, path:root.foo.bar => bar@root.foo
	n = Node{}
	path, err = n.NormalizeNames("root.foo.bar")
	c.Assert(err, IsNil)
	c.Assert(path, Equals, "root.foo")
	c.Assert(n.Name, Equals, "bar")

	// name:foo1.foo2.bar, path:root => bar@root.foo1.foo2
	n = Node{Name: "foo1.foo2.bar"}
	path, err = n.NormalizeNames("root")
	c.Assert(err, IsNil)
	c.Assert(path, Equals, "root.foo1.foo2")
	c.Assert(n.Name, Equals, "bar")

	// name:foo1.foo2.bar, path:root.foo1.foo2 => bar@root.foo1.foo2.foo1.foo2
	n = Node{Name: "foo1.foo2.bar"}
	path, err = n.NormalizeNames("root.foo1.foo2")
	c.Assert(err, IsNil)
	c.Assert(path, Equals, "root.foo1.foo2.foo1.foo2")
	c.Assert(n.Name, Equals, "bar")

	// name:foo.bar path:root.bar.foo => error
	n = Node{Name: "root.foo.bar"}
	path, err = n.NormalizeNames("root.bar.foo")
	c.Assert(err, Not(IsNil))

	// absolute name root.foo.bar matches path .bar.foo
	n = Node{Name: "root.foo.bar"}
	path, err = n.NormalizeNames("root.foo")
	c.Assert(err, IsNil)
	c.Assert(path, Equals, "root.foo")
	c.Assert(n.Name, Equals, "bar")

	// absolute name foo.bar2 does not match map key bar
	n = Node{
		Children: map[string]*Node{
			"bar": {Name: "foo.bar2"},
		},
	}
	path, err = n.NormalizeNames(RootNodeName)
	c.Assert(err, Not(IsNil))
	c.Assert(path, Equals, "")

	n = Node{
		Children: map[string]*Node{
			"bar.foo": {Name: "bar.foo"},
		},
	}
	path, err = n.NormalizeNames(RootNodeName)
	c.Assert(err, IsNil)
	c.Assert(path, Equals, RootNodeName)
}

func (ds *PolicyTestSuite) TestIgnoreNameCoverage(c *C) {
	n := Node{IgnoreNameCoverage: true}
	c.Assert(n.Covers(nil), Equals, true)
}
