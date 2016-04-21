package types

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/noironetworks/cilium-net/common"

	"github.com/noironetworks/cilium-net/Godeps/_workspace/src/github.com/op/go-logging"
)

// Available privileges for policy nodes to define
type Privilege byte

const (
	ALLOW Privilege = iota
	REQUIRES
	DROP_PRIVILEGES
)

type ReservedID int

const (
	ID_NAME_HOST  = "host"
	ID_NAME_WORLD = "world"
)

const (
	ID_UNKNOWN ReservedID = iota
	ID_HOST
	ID_WORLD
)

var ReservedIDMap = map[string]ReservedID{
	ID_NAME_HOST:  ID_HOST,
	ID_NAME_WORLD: ID_WORLD,
}

func (id *ReservedID) String() string {
	for k, v := range ReservedIDMap {
		if v == *id {
			return k
		}
	}

	return ""
}

func GetID(name string) ReservedID {
	if v, ok := ReservedIDMap[name]; ok {
		return v
	} else {
		return ID_UNKNOWN
	}
}

type ConsumableDecision byte

const (
	UNDECIDED ConsumableDecision = iota
	ACCEPT
	ALWAYS_ACCEPT
	DENY
)

var (
	log = logging.MustGetLogger("cilium-net")
)

func policyTrace(ctx *SearchContext, format string, a ...interface{}) {
	if ctx.Trace {
		log.Debugf(format, a...)
		if ctx.Logging != nil {
			ctx.Logging.Logger.Printf(format, a...)
		}
	}
}

func (d ConsumableDecision) String() string {
	switch d {
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
	if d == nil {
		d = new(ConsumableDecision)
	}
	switch strings.ToLower(string(b)) {
	case `"accept"`:
		*d = ACCEPT
	case `"always-accept`:
		*d = ALWAYS_ACCEPT
	case `"deny`:
		*d = DENY
	case `"undecided`:
		*d = UNDECIDED
	}

	return nil
}

func (d ConsumableDecision) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%s"`, d.String())), nil
}

type SearchContext struct {
	Trace   bool
	Logging *logging.LogBackend
	// TODO: Put this as []*Label?
	From []Label
	To   []Label
}

type SearchContextReply struct {
	Logging  []byte
	Decision ConsumableDecision
}

func (s *SearchContext) TargetCoveredBy(coverage []Label) bool {
	for k, _ := range coverage {
		covLabel := &coverage[k]
		for k2, _ := range s.To {
			toLabel := &s.To[k2]
			if covLabel.Equals(toLabel) {
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

	var aux struct {
		Action ConsumableDecision `json:"action"`
		Label  Label
	}

	// Default is allow
	aux.Action = ACCEPT

	// We first attempt to parse a full AllowRule JSON object which
	// was likely created by MarshalJSON of the client, in case that
	// fails we attempt to parse the string as a pure Label which
	// can be used as a shortform to specify allow rules.
	decoder := json.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&aux)
	if err != nil || !aux.Label.IsValid() {
		var aux Label

		decoder = json.NewDecoder(bytes.NewReader(data))
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
	} else {
		a.Action = aux.Action
		a.Label = aux.Label
	}

	return nil
}

func (a *AllowRule) Allows(ctx *SearchContext) ConsumableDecision {
	for k, _ := range ctx.From {
		label := &ctx.From[k]
		if label.Equals(&a.Label) {
			policyTrace(ctx, "Allow Rule %+v decision\n", a)
			return a.Action
		}
	}

	policyTrace(ctx, "Allow Rule %+v decision: UNDECIDED\n", a)
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

	if len(c.Coverage) > 0 && !ctx.TargetCoveredBy(c.Coverage) {
		policyTrace(ctx, "Consumer rule %+v missed coverage\n", c)
		return UNDECIDED
	}

	for k, _ := range c.Allow {
		allowRule := &c.Allow[k]
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
	for k, _ := range c.Coverage {
		l := &c.Coverage[k]
		l.Resolve(node)
		log.Debugf("Resolved label %+v\n", l)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) {
			return fmt.Errorf("Label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for k, _ := range c.Allow {
		r := &c.Allow[k]
		r.Label.Resolve(node)
		log.Debugf("Resolved label %+v\n", r.Label)
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
	if len(r.Coverage) > 0 && ctx.TargetCoveredBy(r.Coverage) {
		for k, _ := range r.Requires {
			reqLabel := &r.Requires[k]
			match := false

			for k2, _ := range ctx.From {
				label := &ctx.From[k2]
				if label.Equals(reqLabel) {
					match = true
				}
			}

			if match == false {
				policyTrace(ctx, "Did not find required labels: %+v\n", r)
				return DENY
			}
		}
	}

	return UNDECIDED
}

func (c *PolicyRuleRequires) Resolve(node *PolicyNode) error {
	for k, _ := range c.Coverage {
		l := &c.Coverage[k]
		l.Resolve(node)
		log.Debugf("Resolved label %+v\n", l)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) {
			return fmt.Errorf("Label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for k, _ := range c.Requires {
		l := &c.Requires[k]
		l.Resolve(node)
		log.Debugf("Resolved label %+v\n", l)
	}

	return nil
}

type Port struct {
	// FIXME: struct field has json tag but is not exported
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
	Name     string                 `json:"Name"`
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
	for k, _ := range ctx.To {
		label := &ctx.To[k]
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

		policyTrace(ctx, "Rule %+v decision: %s\n", rule, decision.String())

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
		log.Debugf("Resolving tree: %+v\n", pn)
		if err := pn.ResolveTree(); err != nil {
			return err
		}
		log.Debugf("Resolved tree: %+v\n", pn)
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

func (pn *PolicyNode) Merge(obj *PolicyNode) error {
	if obj.Name != pn.Name {
		return fmt.Errorf("Policy node merge failed: Node name mismatch %s != %s",
			obj.Name, pn.Name)
	}

	if obj.path != pn.path {
		return fmt.Errorf("Policy node merge failed: Node path mismatch %s != %s",
			obj.path, pn.path)
	}

	pn.Rules = append(pn.Rules, obj.Rules...)

	for k, _ := range obj.Children {
		if err := pn.AddChild(k, obj.Children[k]); err != nil {
			return err
		}
	}

	return nil
}

func (pn *PolicyNode) AddChild(name string, child *PolicyNode) error {
	if _, ok := pn.Children[name]; ok {
		if err := pn.Children[name].Merge(child); err != nil {
			return err
		}
	} else {
		pn.Children[name] = child
	}

	return nil
}

func (pn *PolicyNode) DebugString(level int) string {
	str := fmt.Sprintf("%+v\n", pn)

	for _, child := range pn.Children {
		f := fmt.Sprintf("%%%ds%%s", level*4)
		str += fmt.Sprintf(f, " ", child.DebugString(level+1))
	}

	return str
}

// Overall policy tree
type PolicyTree struct {
	Root *PolicyNode
}

func canConsume(root *PolicyNode, ctx *SearchContext) ConsumableDecision {
	decision := UNDECIDED

	for _, child := range root.Children {
		if child.Covers(ctx) {
			policyTrace(ctx, "Matching child node: %+v\n", child)
			switch child.Allows(ctx) {
			case DENY:
				return DENY
			case ALWAYS_ACCEPT:
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
			policyTrace(ctx, "... proceeding with decision: %s\n", decision.String())
		}
	}

	for _, child := range root.Children {
		if child.Covers(ctx) {
			policyTrace(ctx, "Covered by child %+v\n", child)
			switch canConsume(child, ctx) {
			case DENY:
				return DENY
			case ALWAYS_ACCEPT:
				return ALWAYS_ACCEPT
			case ACCEPT:
				decision = ACCEPT
			}
			policyTrace(ctx, "... proceeding with decision: %s\n", decision.String())
		}
	}

	return decision
}

func (t *PolicyTree) Allows(ctx *SearchContext) ConsumableDecision {
	policyTrace(ctx, "Deriving policy for context %+v\n", ctx)

	// In absence of policy, deny
	if t.Root == nil {
		return DENY
	}

	decision := t.Root.Allows(ctx)
	policyTrace(ctx, "Root rules: %s\n", decision.String())
	switch decision {
	case ALWAYS_ACCEPT:
		return ACCEPT
	case DENY:
		return DENY
	}

	decision = canConsume(t.Root, ctx)
	policyTrace(ctx, "Root children decision: %s\n", decision.String())
	if decision == ALWAYS_ACCEPT {
		decision = ACCEPT
	} else if decision == UNDECIDED {
		decision = DENY
	}

	policyTrace(ctx, "Final tree decision: %s\n", decision.String())

	return decision
}
