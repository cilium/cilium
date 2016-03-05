package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/noironetworks/cilium-net/common"
)

// Available privileges for policy nodes to define
type Privilege byte

const (
	ALLOW Privilege = iota
	REQUIRES
	DROP_PRIVILEGES
)

type ConsumableDecision byte

const (
	UNDECIDED ConsumableDecision = iota
	ACCEPT
	ALWAYS_ACCEPT
	DENY
)

func (d *ConsumableDecision) String() string {
	switch *d {
	case ACCEPT:
		return "accept"
	case ALWAYS_ACCEPT:
		return "always-accept"
	case DENY:
		return "deny"
	case UNDECIDED:
		return "undecided"
	}

	return "unknown"
}

func (d *ConsumableDecision) UnmarshalJSON(b []byte) error {
	// FIXME
	return nil
}

func (d *ConsumableDecision) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d.String())), nil
}

type SearchContext struct {
	From []Label
	To   []Label
}

func (s *SearchContext) TargetCoveredBy(coverage *[]Label) bool {
	for _, covLabel := range *coverage {
		for _, toLabel := range s.To {
			if covLabel.Compare(&toLabel) {
				return true
			}
		}
	}

	return false
}

type AllowRule struct {
	Action ConsumableDecision `json:"action,omitempty"`
	Label  Label
}

func (a *AllowRule) UnmarshalJSON(data []byte) error {
	if a == nil {
		return fmt.Errorf("Cannot unmarhshal to nil pointer")
	}

	if len(data) == 0 {
		return fmt.Errorf("Invalid AllowRule: empty data")
	}

	var aux Label

	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&aux); err != nil {
		return fmt.Errorf("Decode of AllowRule failed: %+v", err)
	}

	if aux.Key[0] == '!' {
		a.Action = DENY
		aux.Key = aux.Key[1:]
	} else {
		a.Action = ACCEPT
	}

	a.Label = aux

	return nil
}

func (a *AllowRule) Allows(ctx *SearchContext) ConsumableDecision {
	for _, label := range ctx.From {
		if label.Compare(&a.Label) {
			return a.Action
		}
	}

	return UNDECIDED
}

// Allow the following consumers
type PolicyRuleConsumers struct {
	Coverage []Label     `json:"Coverage,omitempty"`
	Allow    []AllowRule `json:"Allow"`
}

func (c *PolicyRuleConsumers) Allows(ctx *SearchContext) ConsumableDecision {
	// A decision is undecided until we encoutner a DENY or ACCEPT.
	// An ACCEPT can still be overwritten by a DENY inside the same rule.
	decision := UNDECIDED

	if len(c.Coverage) > 0 && !ctx.TargetCoveredBy(&c.Coverage) {
		return UNDECIDED
	}

	for _, allowRule := range c.Allow {
		switch allowRule.Allows(ctx) {
		case DENY:
			return DENY
		case ALWAYS_ACCEPT:
			return ALWAYS_ACCEPT
		case ACCEPT:
			decision = ACCEPT
			break
		}
	}

	return decision
}

func (c *PolicyRuleConsumers) Resolve(node *PolicyNode) error {
	for _, l := range c.Coverage {
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) {
			return fmt.Errorf("Label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for _, r := range c.Allow {
		r.Label.Resolve(node)
	}

	return nil
}

// Any further consumer requires the specified list of
// labels in order to consume
type PolicyRuleRequires struct {
	Coverage []Label `json:"Coverage,omitempty"`
	Requires []Label `json:"Requires"`
}

// A require rule imposes additional label requirements but does not
// imply access immediately. Hence if the label context is not sufficient
// access can be denied but fullfillment of the requirement only leads to
// the decision being UNDECIDED waiting on an explicit allow rule further
// down the tree
func (r *PolicyRuleRequires) Allows(ctx *SearchContext) ConsumableDecision {
	if len(r.Coverage) > 0 && ctx.TargetCoveredBy(&r.Coverage) {
		for _, reqLabel := range r.Requires {
			match := false

			for _, label := range ctx.From {
				if label.Compare(&reqLabel) {
					match = true
				}
			}

			if match == false {
				return DENY
			}
		}
	}

	return UNDECIDED
}

func (c *PolicyRuleRequires) Resolve(node *PolicyNode) error {
	for _, l := range c.Coverage {
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) {
			return fmt.Errorf("Label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for _, l := range c.Requires {
		l.Resolve(node)
	}

	return nil
}

type Port struct {
	proto  string `json:"Protocol"`
	number int    `json:"Number"`
}

type PolicyRulePorts struct {
	Coverage []Label `json:"Coverage,omitempty"`
	Ports    []Port  `json:"Ports"`
}

// Do not allow further rules of specified type
type PolicyRuleDropPrivileges struct {
	Coverage       []Label     `json:"Coverage,omitempty"`
	DropPrivileges []Privilege `json:"Drop-privileges"`
}

// Node to define hierarchy of rules
type PolicyNode struct {
	path     string
	Name     string                 `json:"-"`
	Parent   *PolicyNode            `json:"-"`
	Rules    []interface{}          `json:"Rules,omitempty"`
	Children map[string]*PolicyNode `json:"Children,omitempty"`
}

func (p *PolicyNode) Path() string {
	if p.path == "" {
		p.path, _ = p.BuildPath()
		// FIXME: handle error?
	}

	return p.path
}

func (p *PolicyNode) Covers(ctx *SearchContext) bool {
	for _, label := range ctx.To {
		if strings.HasPrefix(label.AbsoluteKey(), p.Path()) {
			return true
		}
	}

	return false
}

func (p *PolicyNode) Allows(ctx *SearchContext) ConsumableDecision {
	decision := UNDECIDED

	for _, rule := range p.Rules {
		switch rule.(type) {
		case PolicyRuleConsumers:
			pr_c := rule.(PolicyRuleConsumers)
			decision = pr_c.Allows(ctx)
			break
		case PolicyRuleRequires:
			pr_r := rule.(PolicyRuleRequires)
			decision = pr_r.Allows(ctx)
			break
		}

		switch decision {
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

func (pn *PolicyNode) BuildPath() (string, error) {
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
		return "", fmt.Errorf("Error in policy: node %s is lacking parent", pn.Name)
	}

	return common.GlobalLabelPrefix, nil
}

func (pn *PolicyNode) resolveRules() error {
	for _, rule := range pn.Rules {
		switch rule.(type) {
		case PolicyRuleConsumers:
			r := rule.(PolicyRuleConsumers)
			if err := r.Resolve(pn); err != nil {
				return err
			}
			break
		case PolicyRuleRequires:
			r := rule.(PolicyRuleRequires)
			if err := r.Resolve(pn); err != nil {
				return err
			}
			break
		}
	}

	return nil
}

func (pn *PolicyNode) ResolveTree() error {
	var err error

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

func (pn *PolicyNode) UnmarshalJSON(data []byte) error {
	var policyNode struct {
		Name     string                 `json:"Name,omitempty"`
		Rules    []*json.RawMessage     `json:"Rules,omitempty"`
		Children map[string]*PolicyNode `json:"Children,omitempty"`
	}

	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&policyNode); err != nil {
		return fmt.Errorf("Decode of PolicyNode failed: %+v", err)
	}

	pn.Name = policyNode.Name
	pn.Children = policyNode.Children

	// We have now parsed all children in a recursive manner and are back
	// to the root node. Walk the tree again to resolve the path of each
	// node.
	if pn.Name == common.GlobalLabelPrefix {
		if err := pn.ResolveTree(); err != nil {
			return err
		}
	}

	for _, rawMsg := range policyNode.Rules {
		var om map[string]*json.RawMessage

		if err := json.Unmarshal(*rawMsg, &om); err != nil {
			return err
		}

		if _, ok := om["Allow"]; ok {
			var pr_c PolicyRuleConsumers

			if err := json.Unmarshal(*rawMsg, &pr_c); err != nil {
				return err
			}

			pn.Rules = append(pn.Rules, pr_c)
		} else if _, ok := om["Always-Allow"]; ok {
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

			pn.Rules = append(pn.Rules, pr_c)
		} else if _, ok := om["Requires"]; ok {
			var pr_r PolicyRuleRequires

			if err := json.Unmarshal(*rawMsg, &pr_r); err != nil {
				return err
			}

			pn.Rules = append(pn.Rules, pr_r)
		} else {
			return fmt.Errorf("Unknown policy rule object: %+v", om)
		}
	}

	return nil
}

// Overall policy tree
type PolicyTree struct {
	Root PolicyNode
}

func canConsume(root *PolicyNode, ctx *SearchContext) ConsumableDecision {
	decision := UNDECIDED

	for _, child := range root.Children {
		if child.Covers(ctx) {
			switch child.Allows(ctx) {
			case DENY:
				return DENY
			case ALWAYS_ACCEPT:
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
		}
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

func (t *PolicyTree) Allows(ctx *SearchContext) ConsumableDecision {
	decision := t.Root.Allows(ctx)
	switch decision {
	case ALWAYS_ACCEPT:
		return ACCEPT
	case DENY:
		return DENY
	}

	decision = canConsume(&t.Root, ctx)
	if decision == ALWAYS_ACCEPT {
		decision = ACCEPT
	} else if decision == UNDECIDED {
		decision = DENY
	}

	return decision
}
