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
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
)

// Node to define hierarchy of rules
type Node struct {
	path      string
	Name      string           `json:"name"`
	Parent    *Node            `json:"-"`
	Rules     []PolicyRule     `json:"rules,omitempty"`
	Children  map[string]*Node `json:"children,omitempty"`
	mergeable bool
	resolved  bool
}

func NewNode(name string, parent *Node) *Node {
	return &Node{
		Name:      name,
		Parent:    parent,
		Rules:     nil,
		Children:  map[string]*Node{},
		mergeable: false,
	}
}

func (n *Node) Path() string {
	if n.path == "" {
		n.buildPath()
	}

	return n.path
}

// ResolveName translates a possibly relative name to an absolute path relative to the node
func (n *Node) ResolveName(name string) string {
	// If name is an absolute path already, return it
	if strings.HasPrefix(name, RootPrefix) {
		return name
	}

	for strings.HasPrefix(name, "../") {
		name = name[3:]
		n = n.Parent
		if n == nil {
			log.Warningf("Could not resolve label %+v, reached root\n", name)
			return name
		}
	}

	return JoinPath(n.Path(), name)
}

// NormalizeNames walks all policy nodes and normalizes the policy node name
// according to to the path specified. Takes a node with a list of optional
// children and the path to where the node is/will be located in the tree.
//
// 1. If the name of a node is omitted, the node name will be derived from
// the path. The element after the last node path delimiter is assumed to
// be the node name, e.g. rootNode.parentNode.name
//
// 2. If the node name is an absolute path, it must match the path but will
// be translated to a relative node name.
func (n *Node) NormalizeNames(path string) (string, error) {
	if n == nil {
		return path, nil
	}

	// Path must always be absolute. If root delimiter has not been added,
	// add it now.
	if !strings.HasPrefix(path, RootNodeName) {
		path = JoinPath(RootNodeName, path)
	}

	// If no name is provided, the last node name in the path is assumed
	// to be the node's name
	if n.Name == "" {
		if path == RootNodeName {
			path, n.Name = RootNodeName, RootNodeName
		} else {
			path, n.Name = SplitNodePath(path)
		}
	}

	if n.Name != RootNodeName {
		// If name starts with the root prefix, it is an absolute path,
		// check if it matches the provided path
		if strings.HasPrefix(n.Name, RootPrefix) {
			// If path is "root.foo", we need to subtract "root.foo."
			toTrim := JoinPath(path, "")

			if !strings.HasPrefix(n.Name, toTrim) {
				return "", fmt.Errorf("absolute node name '%s' must match path '%s'",
					n.Name, toTrim)
			}

			n.Name = strings.TrimPrefix(n.Name, toTrim)
		}

		// Any additional segments separated by a node path delimiter
		// are moved into the path
		for strings.Contains(n.Name, NodePathDelimiter) {
			remainingPath, isolatedName := SplitNodePath(n.Name)
			path = JoinPath(path, remainingPath)
			n.Name = isolatedName
		}
	}

	// Validate all child nodes as well
	for keyName, child := range n.Children {
		if child.Name != "" {
			if keyName != child.Name {
				return "", fmt.Errorf("map key name '%s' must match child name '%s'",
					keyName, child.Name)
			}
		} else {
			child.Name = keyName
		}

		if _, err := child.NormalizeNames(JoinPath(path, n.Name)); err != nil {
			return "", err
		}
	}

	return path, nil
}

func coversLabel(l *labels.Label, path string) bool {
	key := l.AbsoluteKey()

	// root matches everything, e.g. "." matches ".foo"
	if path == RootNodeName {
		return true
	}

	if strings.HasPrefix(key, path) {
		// key and path are identical, e.g. ".foo" matches ".foo"
		if len(key) == len(path) {
			return true
		}

		// if path < prefix, then match must be up to delimiter, e.g. ".foo" matches ".foo.bar"
		if len(path) < len(key) && key[len(path)] == '.' {
			return true
		}
	}

	return false
}

func (n *Node) Covers(ctx *SearchContext) bool {
	for _, v := range ctx.To {
		if coversLabel(v, n.Path()) {
			return true
		}
	}

	return false
}

func (n *Node) Allows(ctx *SearchContext) ConsumableDecision {
	decision := UNDECIDED

	policyTraceVerbose(ctx, "Evaluating node %+v\n", n)

	for k := range n.Rules {
		rule := n.Rules[k]
		subDecision := UNDECIDED

		switch rule.(type) {
		case *RuleConsumers:
			r := rule.(*RuleConsumers)
			subDecision = r.Allows(ctx)

		case *RuleRequires:
			r := rule.(*RuleRequires)
			subDecision = r.Allows(ctx)
		}

		switch subDecision {
		case ALWAYS_ACCEPT:
			return ALWAYS_ACCEPT
		case DENY:
			return DENY
		case ACCEPT:
			decision = ACCEPT
		}
	}

	return decision
}

func (n *Node) buildPath() (string, error) {
	if n.Parent != nil {
		// Optimization: if parent has calculated path already (likely),
		// we don't have to walk to the entire root again
		s := n.Parent.path
		if s == "" {
			var err error
			if s, err = n.Parent.buildPath(); err != nil {
				return "", err
			}
		}

		n.path = JoinPath(s, n.Name)
		return n.path, nil
	}

	if n.Name != RootNodeName {
		return "", fmt.Errorf("encountered non-root node '%s' without a parent while building path", n.Name)
	}

	n.path = RootNodeName
	return n.path, nil
}

func (n *Node) resolveRules() error {
	log.Debugf("Resolving rules of node %+v\n", n)

	for k := range n.Rules {
		if err := n.Rules[k].Resolve(n); err != nil {
			return err
		}

		if !n.Rules[k].IsMergeable() {
			n.mergeable = false
			break
		}
	}

	return nil
}

func (n *Node) HasPolicyRule(pr PolicyRule) bool {
	pr256Sum, _ := pr.SHA256Sum()
	for _, r := range n.Rules {
		if r256Sum, _ := r.SHA256Sum(); r256Sum == pr256Sum {
			return true
		}
	}
	return false
}

func (n *Node) ResolveTree() error {
	log.Debugf("Resolving policy node %+v\n", n)

	if _, err := n.buildPath(); err != nil {
		return err
	}

	if err := n.resolveRules(); err != nil {
		return err
	}

	for k, val := range n.Children {
		n.Children[k].Parent = n
		val.Parent = n
		val.Name = k
		if err := val.ResolveTree(); err != nil {
			return err
		}
	}

	n.isMergeable()
	n.resolved = true

	return nil
}

func (n *Node) isMergeable() bool {
	for k := range n.Rules {
		if !n.Rules[k].IsMergeable() {
			n.mergeable = false
			return n.mergeable
		}
	}

	n.mergeable = true
	return n.mergeable
}

// IsMergeable returns true if the node is eligible to be merged with another node
func (n *Node) IsMergeable() bool {
	if n.resolved {
		return n.mergeable
	}

	return n.isMergeable()
}

func (n *Node) UnmarshalJSON(data []byte) error {
	var policyNode struct {
		Name     string             `json:"name,omitempty"`
		Rules    []*json.RawMessage `json:"rules,omitempty"`
		Children map[string]*Node   `json:"children,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&policyNode); err != nil {
		return fmt.Errorf("decode of Node failed: %s", err)
	}

	n.Name = policyNode.Name
	n.Children = policyNode.Children

	for _, rawMsg := range policyNode.Rules {
		var om map[string]*json.RawMessage

		if err := json.Unmarshal(*rawMsg, &om); err != nil {
			return err
		}

		if _, ok := om[privEnc[ALLOW]]; ok {
			var prC RuleConsumers

			if err := json.Unmarshal(*rawMsg, &prC); err != nil {
				return err
			}

			if n.HasPolicyRule(&prC) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", prC)
			} else {
				n.Rules = append(n.Rules, &prC)
			}
		} else if _, ok := om[privEnc[ALWAYS_ALLOW]]; ok {
			var prC RuleConsumers

			if err := json.Unmarshal(*rawMsg, &prC); err != nil {
				return err
			}

			for _, r := range prC.Allow {
				// DENY rules are always deny anyway
				if r.Action == ACCEPT {
					r.Action = ALWAYS_ACCEPT
				}
			}

			if n.HasPolicyRule(&prC) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", prC)
			} else {
				n.Rules = append(n.Rules, &prC)
			}
		} else if _, ok := om[privEnc[REQUIRES]]; ok {
			var prR RuleRequires

			if err := json.Unmarshal(*rawMsg, &prR); err != nil {
				return err
			}

			if n.HasPolicyRule(&prR) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", prR)
			} else {
				n.Rules = append(n.Rules, &prR)
			}
		} else if _, ok := om[privEnc[L4]]; ok {
			var prL4 RuleL4

			if err := json.Unmarshal(*rawMsg, &prL4); err != nil {
				return err
			}

			if n.HasPolicyRule(&prL4) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", prL4)
			} else {
				n.Rules = append(n.Rules, &prL4)
			}
		} else {
			return fmt.Errorf("unknown policy rule object: %+v", om)
		}
	}

	// We have now parsed all children in a recursive manner and are back
	// to the root node. Walk the tree again to resolve the path and the
	// labels of all nodes and rules.
	if n.Name == RootNodeName {
		log.Debugf("Resolving tree: %+v\n", n)
		if err := n.ResolveTree(); err != nil {
			return err
		}
		log.Debugf("Resolved tree: %+v\n", n)
	}

	return nil
}

// CanMerge returns an error if obj cannot be safely merged into an existing node
func (n *Node) CanMerge(obj *Node) error {
	if n.Name != obj.Name {
		return fmt.Errorf("node name mismatch %q != %q", n.Name, obj.Name)
	}

	if obj.path != "" && n.path != obj.path {
		return fmt.Errorf("node path mismatch %q != %q", n.path, obj.path)
	}

	if !n.IsMergeable() || !obj.IsMergeable() {
		return fmt.Errorf("node %s is not mergeable", obj.Name)
	}

	for k := range obj.Children {
		if childNode, ok := n.Children[k]; ok {
			if err := childNode.CanMerge(obj.Children[k]); err != nil {
				return err
			}
		}
	}

	return nil
}

// Merge incorporates the rules and children of obj into an existing node
func (n *Node) Merge(obj *Node) (bool, error) {
	if err := n.CanMerge(obj); err != nil {
		return false, fmt.Errorf("cannot merge node: %s", err)
	}

	policyModified := false
	for _, objRule := range obj.Rules {
		if !n.HasPolicyRule(objRule) {
			n.Rules = append(n.Rules, objRule)
			policyModified = true
		}
	}

	for k := range obj.Children {
		childPolicyModified, err := n.AddChild(k, obj.Children[k])
		if err != nil {
			log.Warningf("unexpected error while merging nodes: %s", err)
		}
		policyModified = policyModified || childPolicyModified
	}

	n.resolved = false

	return policyModified, nil
}

func (n *Node) AddChild(name string, child *Node) (bool, error) {
	if _, ok := n.Children[name]; ok {
		child.Parent = n
		child.Path()
		return n.Children[name].Merge(child)
	}

	n.Children[name] = child
	child.Parent = n
	child.Path()

	return true, nil
}

func (n *Node) DebugString(level int) string {
	str := fmt.Sprintf("%+v\n", n)

	for _, child := range n.Children {
		f := fmt.Sprintf("%%%ds%%s", level*4)
		str += fmt.Sprintf(f, " ", child.DebugString(level+1))
	}

	return str
}

func (n *Node) JSONMarshal() string {
	b, err := json.MarshalIndent(n, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func (n *Node) ResolveL4Policy(ctx *SearchContext, result *L4Policy) *L4Policy {
	for k := range n.Rules {
		switch n.Rules[k].(type) {
		case *RuleL4:
			l4 := n.Rules[k].(*RuleL4)
			l4.GetL4Policy(ctx, result)
		}
	}

	for _, child := range n.Children {
		if child.Covers(ctx) {
			child.ResolveL4Policy(ctx, result)
		}
	}

	return result
}

// HasRules returns true if a node has any rules attached or at least one child.
func (n *Node) HasRules() bool {
	return (n.Children != nil && len(n.Children) > 0) || len(n.Rules) > 0
}
