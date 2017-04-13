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
	"encoding/json"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	. "gopkg.in/check.v1"
)

func (ds *PolicyTestSuite) TestAddDelete(c *C) {
	//var nullPtr *Node

	tree := NewTree()

	// Empty tree should return empty result
	n, p := tree.LookupLocked("")
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)

	root := NewNode(RootNodeName, nil)

	// adding a root node should succeed
	added, err := tree.Add(RootNodeName, root)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// lookup of root node should succeed now
	n, p = tree.LookupLocked(RootNodeName)
	c.Assert(n, Equals, root)
	c.Assert(n.Name, Equals, RootNodeName)
	c.Assert(p, IsNil)

	// lookup of empty path should return root node
	n, p = tree.LookupLocked("")
	c.Assert(n, Equals, root)
	c.Assert(n.Name, Equals, RootNodeName)
	c.Assert(p, IsNil)

	deleted := tree.Delete(RootNodeName, "")
	c.Assert(deleted, Equals, true)

	n, p = tree.LookupLocked(RootNodeName)
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)

	// Added a child if no root node exist must add parents of that node
	foo := NewNode("foo", nil)
	added, err = tree.Add(RootNodeName+".bar", foo)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// The node should exist afterwards
	n, pBar := tree.LookupLocked(RootNodeName + ".bar.foo")
	c.Assert(n, Equals, foo)
	c.Assert(pBar.Name, Equals, "bar")
	c.Assert(pBar.path, Equals, RootNodeName+".bar")

	// The root node should have been added
	n, p = tree.LookupLocked(RootNodeName)
	c.Assert(n, Not(IsNil))
	c.Assert(p, IsNil)

	fooNode := NewNode("foo", nil)
	root = &Node{
		Children: map[string]*Node{
			"foo": fooNode,
			"bar": {},
		},
	}

	// Add root node with children, should succeed
	added, err = tree.Add(RootNodeName, root)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// lookup of root node should succeed now
	n, p = tree.LookupLocked(RootNodeName)
	// The "root" node was merged into the tree's root, therefore we need to
	// make it the same with this hack
	root.Children["bar"] = pBar
	root.resolved = true
	c.Assert(n, DeepEquals, root)
	c.Assert(n.Name, Equals, RootNodeName)
	c.Assert(p, IsNil)

	// lookup of child foo should succeed
	n, p = tree.LookupLocked("root.foo")
	c.Assert(n, Equals, fooNode)
	c.Assert(p, DeepEquals, root)

	// delete root node
	deleted = tree.Delete("root", "")
	c.Assert(deleted, Equals, true)

	// lookup of root node should fail now
	n, p = tree.LookupLocked(RootNodeName)
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)

	// lookup of child foo should fail now
	n, p = tree.LookupLocked("root.foo")
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)
}

func (ds *PolicyTestSuite) TestLookup(c *C) {
	//var nullPtr *Node

	tree := NewTree()
	foo := NewNode("foo", nil)

	// adding foo to root
	added, err := tree.Add(RootNodeName, foo)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// search for foo.bar, should return nil, foo
	n, p := tree.LookupLocked("foo.bar")
	c.Assert(n, IsNil)
	c.Assert(p, Equals, foo)

	// search for root.io, should return nil, root
	n, p = tree.LookupLocked("root.io")
	c.Assert(n, IsNil)
	c.Assert(p, Equals, tree.Root)

	// adding bar to foo
	bar := NewNode("bar", nil)
	added, err = tree.Add("root.foo", bar)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// lookup of foo
	n, p = tree.LookupLocked("foo")
	c.Assert(n, Equals, foo)
	c.Assert(n.path, Equals, "root.foo")
	c.Assert(n.Name, Equals, "foo")
	c.Assert(p.Name, Equals, "root")

	// lookup of bar should return nil, root
	n, p = tree.LookupLocked("bar")
	c.Assert(n, IsNil)
	c.Assert(p, Equals, tree.Root)

	// lookup of foo.bar should succeed
	n, p = tree.LookupLocked("foo.bar")
	c.Assert(n, Equals, bar)
	c.Assert(n.path, Equals, "root.foo.bar")
	c.Assert(n.Name, Equals, "bar")
	c.Assert(p, Equals, foo)

	// lookup of foo.bar.baz should return nil, bar
	n, p = tree.LookupLocked("foo.bar.baz")
	c.Assert(n, IsNil)
	c.Assert(p, Equals, bar)

	// adding bar to foo
	deep := Node{Name: "deep"}
	added, err = tree.Add("foo.bar.1.2.3", &deep)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// lookup of foo.bar.1
	n, p = tree.LookupLocked("foo.bar.1")
	c.Assert(n.Name, Equals, "1")
	c.Assert(p, Equals, bar)

	// lookup of foo.bar.1.2
	n, p = tree.LookupLocked("foo.bar.1.2")
	c.Assert(n.Name, Equals, "2")
	c.Assert(p.Name, Equals, "1")

	// lookup of foo.bar.1.2.3.deep
	n, p = tree.LookupLocked("foo.bar.1.2.3.deep")
	c.Assert(n.Name, Equals, "deep")
	c.Assert(p.Name, Equals, "3")
}

func (ds *PolicyTestSuite) TestAddDelete2(c *C) {
	//var nullPtr *Node

	tree := NewTree()
	root := NewNode("io.cilium", nil)

	// adding "io.cilium" to root node should succeed
	added, err := tree.Add(RootNodeName, root)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// Lookup io and io.cilium nodes created
	n, p := tree.LookupLocked("io")
	c.Assert(n.Name, Equals, "io")
	c.Assert(p.Name, Equals, "root")
	n, p = tree.LookupLocked("io.cilium")
	c.Assert(n.Name, Equals, "cilium")
	c.Assert(p.Name, Equals, "io")

	// adding "k8s-app" to io.cilium.k8s node should succeed
	k8s := NewNode("k8s-app", nil)
	added, err = tree.Add("io.cilium.k8s", k8s)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	// Lookup io.cilium.k8s and io.cilium.k8s.k8s-app nodes created
	n, p = tree.LookupLocked("io.cilium.k8s")
	c.Assert(n, Not(IsNil))
	c.Assert(n.Name, Equals, "k8s")
	c.Assert(p.Name, Equals, "cilium")
	c.Assert(p.path, Equals, "root.io.cilium")
	n, p = tree.LookupLocked("io.cilium.k8s.k8s-app")
	c.Assert(n, Equals, k8s)
	c.Assert(p.Name, Equals, "k8s")
	c.Assert(p.path, Equals, "root.io.cilium.k8s")

	deleted := tree.Delete(RootNodeName, "")
	c.Assert(deleted, Equals, true)

	n, p = tree.LookupLocked(RootNodeName)
	c.Assert(n, IsNil)
	c.Assert(p, IsNil)
}

var defaultCtx = &SearchContext{
	Trace: TRACE_ENABLED,
	From: []*labels.Label{
		{Key: "id.foo", Source: "cilium"},
	},
	To: []*labels.Label{
		{Key: "id.bar", Source: "cilium"},
	},
}

func (ds *PolicyTestSuite) TestAlwaysAllow(c *C) {
	// always-accept foo of root must overwrite deny foo of child
	policyText := `
{
	"name": "root",
	"rules": [{
		"coverage": ["id.bar"],
		"allow": [{
			"action": "always-accept",
			"label": {
				"key": "id.foo",
				"source": "cilium"
			}
		}]
	}],
	"children": {
		"id": {
			"rules": [{
				"coverage": ["bar"],
				"allow": ["!foo"]
			}]
		}
	}
}
`
	node := Node{}
	err := json.Unmarshal([]byte(policyText), &node)
	c.Assert(err, IsNil)

	tree := NewTree()
	added, err := tree.Add("root", &node)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	decision := tree.AllowsRLocked(defaultCtx)
	c.Assert(decision, Equals, api.ACCEPT)
}

func (ds *PolicyTestSuite) TestDenyOverwrite(c *C) {
	// deny foo of child must overwrite allow foo of root
	policyText := `
{
	"name": "root",
	"rules": [{
		"coverage": ["id.bar"],
		"allow": ["id.foo"]
	}],
	"children": {
		"id": {
			"rules": [{
				"coverage": ["bar"],
				"allow": ["!foo"]
			}]
		}
	}
}
`
	node := Node{}
	err := json.Unmarshal([]byte(policyText), &node)
	c.Assert(err, IsNil)

	tree := NewTree()
	added, err := tree.Add("root", &node)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	decision := tree.AllowsRLocked(defaultCtx)
	c.Assert(decision, Equals, api.DENY)
}

func (ds *PolicyTestSuite) TestRulePrecedence(c *C) {
	// !id.foo rule must overwrite id.foo rule
	policyText := `
{
	"name": "root",
	"rules": [{
		"coverage": ["id.bar"],
		"allow": ["id.foo", "!id.foo"]
	}]
}
`
	node := Node{}
	err := json.Unmarshal([]byte(policyText), &node)
	c.Assert(err, IsNil)

	tree := NewTree()
	added, err := tree.Add("root", &node)
	c.Assert(added, Equals, true)
	c.Assert(err, IsNil)

	decision := tree.AllowsRLocked(defaultCtx)
	c.Assert(decision, Equals, api.DENY)
}

func (ds *PolicyTestSuite) TestOutsideCoverage(c *C) {
	// coverage of not_id rules it outside of the node path
	policyText := `
{
	"name": "root",
	"rules": [{
		"coverage": ["id.bar"],
		"allow": ["id.foo"]
	}],
	"children": {
		"not_id": {
			"rules": [{
				"coverage": ["root.id.bar"],
				"allow": ["!root.id.foo"]
			}]
		}
	}
}
`
	node := Node{}
	err := json.Unmarshal([]byte(policyText), &node)
	c.Assert(err, Not(IsNil))
}
