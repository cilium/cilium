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

func (p *Node) Path() string {
	if p.path == "" {
		p.buildPath()
	}

	return p.path
}

// ResolveName translates a possibly relative name to an absolute path relative to the node
func (node *Node) ResolveName(name string) string {
	// If name is an absolute path already, return it
	if strings.HasPrefix(name, RootPrefix) {
		return name
	}

	for strings.HasPrefix(name, "../") {
		name = name[3:]
		node = node.Parent
		if node == nil {
			log.Warningf("Could not resolve label %+v, reached root\n", name)
			return name
		}
	}

	return JoinPath(node.Path(), name)
}

// NormalizeNames walks all policy nodes and normalizes the policy node name
// according to to the path specified. Takes a node with a list of optional
// children and the path to where the node is/will be located in the tree.
//
// 1. If the name of a node is ommitted, the node name will be derived from
// the path. The element after the last node path delimiter is assumed to
// be the node name, e.g. rootNode.parentNode.name
//
// 2. If the node name is an absolute path, it must match the path but will
// be translated to a relative node name.
func (n *Node) NormalizeNames(path string) (string, error) {
	if n == nil {
		return path, nil
	}

	// Path is always absolute. If root delimiter has not been added,
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

	// If name starts with a node path delimiter, it is an absolute path,
	// check if it matches the provided path
	if n.Name != RootNodeName {
		if strings.HasPrefix(n.Name, RootNodeName) {
			// If path is ".foo", we need to subtract ".foo."
			sub := JoinPath(path, "")

			if !strings.HasPrefix(n.Name, sub) {
				return "", fmt.Errorf("absolute node name '%s' must match path '%s'",
					n.Name, path)
			}

			n.Name = strings.TrimPrefix(n.Name, sub)
		}

		if strings.Contains(n.Name, NodePathDelimiter) {
			return "", fmt.Errorf("relative node name '%s' may not contain path delimiter",
				n.Name)
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

func (p *Node) Covers(ctx *SearchContext) bool {
	for k := range ctx.To {
		if coversLabel(&ctx.To[k], p.Path()) {
			return true
		}
	}

	return false
}

func (p *Node) Allows(ctx *SearchContext) ConsumableDecision {
	decision := UNDECIDED

	policyTraceVerbose(ctx, "Evaluating node %+v\n", p)

	for k := range p.Rules {
		rule := p.Rules[k]
		sub_decision := UNDECIDED

		switch rule.(type) {
		case *RuleConsumers:
			r := rule.(*RuleConsumers)
			sub_decision = r.Allows(ctx)

		case *RuleRequires:
			r := rule.(*RuleRequires)
			sub_decision = r.Allows(ctx)
		}

		switch sub_decision {
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

func (pn *Node) buildPath() (string, error) {
	if pn.Parent != nil {
		// Optimization: if parent has calculated path already (likely),
		// we don't have to walk to the entire root again
		s := pn.Parent.path
		if s == "" {
			var err error
			if s, err = pn.Parent.buildPath(); err != nil {
				return "", err
			}
		}

		pn.path = JoinPath(s, pn.Name)
		return pn.path, nil
	}

	if pn.Name != RootNodeName {
		return "", fmt.Errorf("encountered non-root node '%s' without a parent while building path", pn.Name)
	}

	pn.path = RootNodeName
	return pn.path, nil
}

func (pn *Node) resolveRules() error {
	log.Debugf("Resolving rules of node %+v\n", pn)

	for k := range pn.Rules {
		if err := pn.Rules[k].Resolve(pn); err != nil {
			return err
		}

		if !pn.Rules[k].IsMergeable() {
			pn.mergeable = false
			break
		}
	}

	return nil
}

func (p *Node) HasPolicyRule(pr PolicyRule) bool {
	pr256Sum, _ := pr.SHA256Sum()
	for _, r := range p.Rules {
		if r256Sum, _ := r.SHA256Sum(); r256Sum == pr256Sum {
			return true
		}
	}
	return false
}

func (pn *Node) ResolveTree() error {
	log.Debugf("Resolving policy node %+v\n", pn)

	if _, err := pn.buildPath(); err != nil {
		return err
	}

	if err := pn.resolveRules(); err != nil {
		return err
	}

	for k, val := range pn.Children {
		pn.Children[k].Parent = pn
		val.Parent = pn
		val.Name = k
		if err := val.ResolveTree(); err != nil {
			return err
		}
	}

	pn.isMergeable()
	pn.resolved = true

	return nil
}

func (pn *Node) isMergeable() bool {
	for k := range pn.Rules {
		if !pn.Rules[k].IsMergeable() {
			pn.mergeable = false
			return pn.mergeable
		}
	}

	pn.mergeable = true
	return pn.mergeable
}

// IsMergeable returns true if the node is eligible to be merged with another node
func (pn *Node) IsMergeable() bool {
	if pn.resolved {
		return pn.mergeable
	}

	return pn.isMergeable()
}

func (pn *Node) UnmarshalJSON(data []byte) error {
	var policyNode struct {
		Name     string             `json:"name,omitempty"`
		Rules    []*json.RawMessage `json:"rules,omitempty"`
		Children map[string]*Node   `json:"children,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&policyNode); err != nil {
		return fmt.Errorf("decode of Node failed: %s", err)
	}

	pn.Name = policyNode.Name
	pn.Children = policyNode.Children

	for _, rawMsg := range policyNode.Rules {
		var om map[string]*json.RawMessage

		if err := json.Unmarshal(*rawMsg, &om); err != nil {
			return err
		}

		if _, ok := om[privEnc[ALLOW]]; ok {
			var pr_c RuleConsumers

			if err := json.Unmarshal(*rawMsg, &pr_c); err != nil {
				return err
			}

			if pn.HasPolicyRule(&pr_c) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", pr_c)
			} else {
				pn.Rules = append(pn.Rules, &pr_c)
			}
		} else if _, ok := om[privEnc[ALWAYS_ALLOW]]; ok {
			var pr_c RuleConsumers

			if err := json.Unmarshal(*rawMsg, &pr_c); err != nil {
				return err
			}

			for _, r := range pr_c.Allow {
				// DENY rules are always deny anyway
				if r.Action == ACCEPT {
					r.Action = ALWAYS_ACCEPT
				}
			}

			if pn.HasPolicyRule(&pr_c) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", pr_c)
			} else {
				pn.Rules = append(pn.Rules, &pr_c)
			}
		} else if _, ok := om[privEnc[REQUIRES]]; ok {
			var pr_r RuleRequires

			if err := json.Unmarshal(*rawMsg, &pr_r); err != nil {
				return err
			}

			if pn.HasPolicyRule(&pr_r) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", pr_r)
			} else {
				pn.Rules = append(pn.Rules, &pr_r)
			}
		} else if _, ok := om[privEnc[L4]]; ok {
			var pr_l4 RuleL4

			if err := json.Unmarshal(*rawMsg, &pr_l4); err != nil {
				return err
			}

			if pn.HasPolicyRule(&pr_l4) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", pr_l4)
			} else {
				pn.Rules = append(pn.Rules, &pr_l4)
			}
		} else {
			return fmt.Errorf("unknown policy rule object: %+v", om)
		}
	}

	// We have now parsed all children in a recursive manner and are back
	// to the root node. Walk the tree again to resolve the path and the
	// labels of all nodes and rules.
	if pn.Name == RootNodeName {
		log.Debugf("Resolving tree: %+v\n", pn)
		if err := pn.ResolveTree(); err != nil {
			return err
		}
		log.Debugf("Resolved tree: %+v\n", pn)
	}

	return nil
}

// CanMerge returns an error if obj cannot be safely merged into an existing node
func (pn *Node) CanMerge(obj *Node) error {
	if obj.Name != pn.Name {
		return fmt.Errorf("node name mismatch %s != %s", obj.Name, pn.Name)
	}

	if obj.path != pn.path {
		return fmt.Errorf("node path mismatch %s != %s", obj.path, pn.path)
	}

	if !pn.IsMergeable() || !obj.IsMergeable() {
		return fmt.Errorf("node %s is not mergeable", obj.Name)
	}

	for k := range obj.Children {
		if childNode, ok := pn.Children[k]; ok {
			if err := childNode.CanMerge(obj.Children[k]); err != nil {
				return err
			}
		}
	}

	return nil
}

// Merge incorporates the rules and children of obj into an existnig node
func (pn *Node) Merge(obj *Node) (bool, error) {
	if err := pn.CanMerge(obj); err != nil {
		return false, fmt.Errorf("cannot merge node: %s", err)
	}

	policyModified := false
	for _, objRule := range obj.Rules {
		if !pn.HasPolicyRule(objRule) {
			pn.Rules = append(pn.Rules, objRule)
			policyModified = true
		}
	}

	for k := range obj.Children {
		childPolicyModified, err := pn.AddChild(k, obj.Children[k])
		if err != nil {
			log.Warningf("unexpected error while merging nodes: %s", err)
		}
		policyModified = policyModified || childPolicyModified
	}

	pn.resolved = false

	return policyModified, nil
}

func (pn *Node) AddChild(name string, child *Node) (bool, error) {
	if _, ok := pn.Children[name]; ok {
		child.Parent = pn
		child.Path()
		return pn.Children[name].Merge(child)
	} else {
		pn.Children[name] = child
		child.Parent = pn
		child.Path()
	}

	return true, nil
}

func (pn *Node) DebugString(level int) string {
	str := fmt.Sprintf("%+v\n", pn)

	for _, child := range pn.Children {
		f := fmt.Sprintf("%%%ds%%s", level*4)
		str += fmt.Sprintf(f, " ", child.DebugString(level+1))
	}

	return str
}

func (pn *Node) JSONMarshal() string {
	b, err := json.MarshalIndent(pn, "", "  ")
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

// Returns true if a node has any rules attached or at least one child
func (n *Node) HasRules() bool {
	return (n.Children != nil && len(n.Children) > 0) || len(n.Rules) > 0
}
