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

	"github.com/cilium/cilium/common"
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

func (p *Node) GetLabelParent() labels.LabelAttachment {
	return p.Parent
}

func (p *Node) Path() string {
	if p.path == "" {
		p.path, _ = p.BuildPath()
		// FIXME: handle error?
	}

	return p.path
}

func (p *Node) Covers(ctx *SearchContext) bool {
	for k := range ctx.To {
		if ctx.To[k].Covers(p.Path()) {
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

func (pn *Node) BuildPath() (string, error) {
	if pn.Parent != nil {
		// Optimization: if parent has calculated path already (likely),
		// we don't have to walk to the entire root again
		if pn.Parent.path != "" {
			return fmt.Sprintf("%s.%s", pn.Parent.path, pn.Name), nil
		}

		if s, err := pn.Parent.BuildPath(); err != nil {
			return "", err
		} else {
			return fmt.Sprintf("%s.%s", s, pn.Name), nil
		}
	}

	if !strings.HasPrefix(pn.Name, common.GlobalLabelPrefix) {
		return "", fmt.Errorf("error in policy: node %s parent prefix is different than %s", pn.Name, common.GlobalLabelPrefix)
	}

	return common.GlobalLabelPrefix, nil
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
	var err error

	log.Debugf("Resolving policy node %+v\n", pn)

	pn.path, err = pn.BuildPath()
	if err != nil {
		return err
	}

	if err := pn.resolveRules(); err != nil {
		return err
	}

	for k, val := range pn.Children {
		pn.Children[k].Parent = pn
		val.Parent = pn
		val.Name = k
		if err = val.ResolveTree(); err != nil {
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
	if pn.Name == common.GlobalLabelPrefix {
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
