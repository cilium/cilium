//
// Copyright 2016 Authors of Cilium
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
//
package policy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-policy")
)

// Available privileges for policy nodes to define
type Privilege byte

const (
	ALLOW Privilege = iota
	ALWAYS_ALLOW
	REQUIRES
	DROP_PRIVILEGES
)

var (
	privEnc = map[Privilege]string{
		ALLOW:           "allow",
		ALWAYS_ALLOW:    "always-allow",
		REQUIRES:        "requires",
		DROP_PRIVILEGES: "drop-privileges",
	}
	privDec = map[string]Privilege{
		"allow":           ALLOW,
		"always-allow":    ALWAYS_ALLOW,
		"requires":        REQUIRES,
		"drop-privileges": DROP_PRIVILEGES,
	}
)

func (p Privilege) String() string {
	if v, exists := privEnc[p]; exists {
		return v
	}
	return ""
}

func (p *Privilege) UnmarshalJSON(b []byte) error {
	if p == nil {
		p = new(Privilege)
	}
	if len(b) <= len(`""`) {
		return fmt.Errorf("invalid privilege '%s'", string(b))
	}
	if v, exists := privDec[string(b[1:len(b)-1])]; exists {
		*p = Privilege(v)
		return nil
	}

	return fmt.Errorf("unknown '%s' privilege", string(b))
}

func (d Privilege) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d)), nil
}

type ConsumableDecision byte

const (
	UNDECIDED ConsumableDecision = iota
	ACCEPT
	ALWAYS_ACCEPT
	DENY
)

var (
	cdEnc = map[ConsumableDecision]string{
		UNDECIDED:     "undecided",
		ACCEPT:        "accept",
		ALWAYS_ACCEPT: "always-accept",
		DENY:          "deny",
	}
	cdDec = map[string]ConsumableDecision{
		"undecided":     UNDECIDED,
		"accept":        ACCEPT,
		"always-accept": ALWAYS_ACCEPT,
		"deny":          DENY,
	}
)

type Tracing int

const (
	TRACE_DISABLED Tracing = iota
	TRACE_ENABLED
	TRACE_VERBOSE
)

func policyTrace(ctx *SearchContext, format string, a ...interface{}) {
	switch ctx.Trace {
	case TRACE_ENABLED, TRACE_VERBOSE:
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

func policyTraceVerbose(ctx *SearchContext, format string, a ...interface{}) {
	switch ctx.Trace {
	case TRACE_VERBOSE:
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

func (d ConsumableDecision) String() string {
	if v, exists := cdEnc[d]; exists {
		return v
	}
	return ""
}

func (d *ConsumableDecision) UnmarshalJSON(b []byte) error {
	if d == nil {
		d = new(ConsumableDecision)
	}
	if len(b) <= len(`""`) {
		return fmt.Errorf("invalid consumable decision '%s'", string(b))
	}
	if v, exists := cdDec[string(b[1:len(b)-1])]; exists {
		*d = ConsumableDecision(v)
		return nil
	}

	return fmt.Errorf("unknown '%s' consumable decision", string(b))
}

func (d ConsumableDecision) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d)), nil
}

type SearchContext struct {
	Trace   Tracing
	Logging *logging.LogBackend
	// TODO: Put this as []*Label?
	From []labels.Label
	To   []labels.Label
}

type SearchContextReply struct {
	Logging  []byte
	Decision ConsumableDecision
}

func (s *SearchContext) TargetCoveredBy(coverage []labels.Label) bool {
	for k := range coverage {
		covLabel := &coverage[k]
		for k2 := range s.To {
			toLabel := &s.To[k2]
			if covLabel.Matches(toLabel) {
				return true
			}
		}
	}

	return false
}

type PolicyRule interface {
	Allows(ctx *SearchContext) ConsumableDecision
	Resolve(node *Node) error
	SHA256Sum() (string, error)
}

// Do not allow further rules of specified type
type PolicyRuleDropPrivileges struct {
	Coverage       []labels.Label `json:"coverage,omitempty"`
	DropPrivileges []Privilege    `json:"drop-privileges"`
}

// Node to define hierarchy of rules
type Node struct {
	path     string
	Name     string           `json:"name"`
	Parent   *Node            `json:"-"`
	Rules    []PolicyRule     `json:"rules,omitempty"`
	Children map[string]*Node `json:"children,omitempty"`
}

func NewNode(name string, parent *Node) *Node {
	return &Node{
		Name:     name,
		Parent:   parent,
		Rules:    nil,
		Children: map[string]*Node{},
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
		sub_decision := p.Rules[k].Allows(ctx)

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

	if pn.Name != common.GlobalLabelPrefix {
		return "", fmt.Errorf("error in policy: node %s is lacking parent", pn.Name)
	}

	return common.GlobalLabelPrefix, nil
}

func (pn *Node) resolveRules() error {
	log.Debugf("Resolving rules of node %+v\n", pn)

	for k := range pn.Rules {
		if err := pn.Rules[k].Resolve(pn); err != nil {
			return err
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

	return nil
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
			var pr_c PolicyRuleConsumers

			if err := json.Unmarshal(*rawMsg, &pr_c); err != nil {
				return err
			}

			if pn.HasPolicyRule(&pr_c) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", pr_c)
			} else {
				pn.Rules = append(pn.Rules, &pr_c)
			}
		} else if _, ok := om[privEnc[ALWAYS_ALLOW]]; ok {
			var pr_c PolicyRuleConsumers

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
			var pr_r PolicyRuleRequires

			if err := json.Unmarshal(*rawMsg, &pr_r); err != nil {
				return err
			}

			if pn.HasPolicyRule(&pr_r) {
				log.Infof("Ignoring rule %+v since it's already present in the list of rules", pr_r)
			} else {
				pn.Rules = append(pn.Rules, &pr_r)
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

func (pn *Node) Merge(obj *Node) error {
	if obj.Name != pn.Name {
		return fmt.Errorf("policy node merge failed: Node name mismatch %s != %s",
			obj.Name, pn.Name)
	}

	if obj.path != pn.path {
		return fmt.Errorf("policy node merge failed: Node path mismatch %s != %s",
			obj.path, pn.path)
	}

	for _, objRule := range obj.Rules {
		if pn.HasPolicyRule(objRule) {
			log.Infof("Ignoring rule %+v since it's already present in the list of rules", objRule)
		} else {
			pn.Rules = append(pn.Rules, objRule)
		}
	}

	for k := range obj.Children {
		if err := pn.AddChild(k, obj.Children[k]); err != nil {
			return err
		}
	}

	return nil
}

func (pn *Node) AddChild(name string, child *Node) error {
	if _, ok := pn.Children[name]; ok {
		child.Parent = pn
		child.Path()
		return pn.Children[name].Merge(child)
	} else {
		pn.Children[name] = child
		child.Parent = pn
		child.Path()
	}

	return nil
}

func (pn *Node) DebugString(level int) string {
	str := fmt.Sprintf("%+v\n", pn)

	for _, child := range pn.Children {
		f := fmt.Sprintf("%%%ds%%s", level*4)
		str += fmt.Sprintf(f, " ", child.DebugString(level+1))
	}

	return str
}

// Overall policy tree
type Tree struct {
	Root *Node
}

func canConsume(root *Node, ctx *SearchContext) ConsumableDecision {
	decision := UNDECIDED
	nmatch := 0

	for _, child := range root.Children {
		if child.Covers(ctx) {
			nmatch++
			policyTrace(ctx, "Covered by child: %s\n", child.path)
			switch child.Allows(ctx) {
			case DENY:
				return DENY
			case ALWAYS_ACCEPT:
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
			policyTrace(ctx, "... no conclusion after %s rules, current decision: %s\n", child.path, decision)
		}
	}

	if nmatch == 0 {
		policyTrace(ctx, "No matching children in %s\n", root.path)
		return decision
	}

	for _, child := range root.Children {
		if child.Covers(ctx) {
			switch canConsume(child, ctx) {
			case DENY:
				return DENY
			case ALWAYS_ACCEPT:
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
		}
	}

	return decision
}

func (t *Tree) Allows(ctx *SearchContext) ConsumableDecision {
	policyTrace(ctx, "Resolving policy for context %+v\n", ctx)

	// In absence of policy, deny
	if t.Root == nil {
		policyTrace(ctx, "No policy loaded: deny\n")
		return DENY
	}

	var sub_decision ConsumableDecision

	decision := t.Root.Allows(ctx)
	policyTrace(ctx, "Root rules decision: %s\n", decision)
	switch decision {
	case ALWAYS_ACCEPT:
		decision = ACCEPT
		goto end
	case DENY:
		goto end
	}

	sub_decision = canConsume(t.Root, ctx)
	policyTrace(ctx, "Root children decision: %s\n", sub_decision)
	switch sub_decision {
	case ALWAYS_ACCEPT, ACCEPT:
		decision = ACCEPT
	case DENY:
		decision = DENY
	case UNDECIDED:
		if decision == UNDECIDED {
			decision = DENY
		}
	}

end:
	policyTrace(ctx, "Final tree decision: %s\n", decision)

	return decision
}

func SplitNodePath(fullPath string) (string, string) {
	var extension = filepath.Ext(fullPath)
	return fullPath[0 : len(fullPath)-len(extension)], extension
}
