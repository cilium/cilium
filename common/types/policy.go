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
	ACCEPT ConsumableDecision = iota
	DENY
	UNDECIDED
)

func (d *ConsumableDecision) String() string {
	switch *d {
	case ACCEPT:
		return "accept"
		break
	case DENY:
		return "deny"
		break
	case UNDECIDED:
		return "undecided"
		break
	}

	return "unknown"
}

type KeyValue struct {
	key   string `json:"key"`
	Value string `json:"value,omitempty"`
}

type Label struct {
	KeyValue
	absKey string `json:-`
	Source string
}

func NewLabel(key string, value string, source string) Label {
	lbl := Label{
		KeyValue: KeyValue{key, value},
		Source:   source,
	}

	return lbl
}

func (l *Label) Compare(b *Label) bool {
	return l.Source == b.Source && l.Key() == b.Key() && l.Value == b.Value
}

func (l *Label) Resolve(node *PolicyNode) {
	if l.Source == "cilium" && !strings.HasPrefix(l.key, common.GlobalLabelPrefix) {
		l.absKey = node.Path() + "." + l.key
	} else {
		l.absKey = l.key
	}
}

func (l *Label) Key() string {
	if l.absKey != "" {
		return l.absKey
	}

	return l.key
}

func (l *Label) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))

	if l == nil {
		return fmt.Errorf("Cannot unmarhshal to nil pointer")
	}

	if len(data) == 0 {
		return fmt.Errorf("Invalid Label: empty data")
	}

	if bytes.Contains(data, []byte(`"source":`)) {
		var aux struct {
			Source string `json:"source"`
			Key    string `json:"key" binding:"required"`
			Value  string `json:"value"`
		}

		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("Decode of Label failed: %+v", err)
		}

		if aux.Key == "" {
			return fmt.Errorf("Invalid Label: must provide a label key")
		}

		l.Source = aux.Source
		l.key = aux.Key
		l.Value = aux.Value
	} else {
		// This is a short form in which only a string to be interpreted
		// as a cilium label key is provided
		var aux string

		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("Decode of Label as string failed: %+v", err)
		}

		if aux == "" {
			return fmt.Errorf("Invalid Label: must provide a label key")
		}

		l.Source = "cilium"
		l.key = aux
		l.Value = ""
	}

	return nil
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

// Base type for all PolicyRule* types
type PolicyRuleBase struct {
	Coverage []Label `json:"Coverage,omitempty"`
}

type AllowRule struct {
	Inverted bool `json:"inverted,omitempty"`
	Label    Label
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

	if aux.key[0] == '!' {
		a.Inverted = true
		aux.key = aux.key[1:]
	} else {
		a.Inverted = false
	}

	a.Label = aux

	return nil
}

func (a *AllowRule) Allows(ctx *SearchContext) ConsumableDecision {
	for _, label := range ctx.From {
		if label.Compare(&a.Label) {
			if a.Inverted {
				return DENY
			} else {
				return ACCEPT
			}
		}
	}

	return UNDECIDED
}

// Allow the following consumers
type PolicyRuleConsumers struct {
	PolicyRuleBase
	Allow []AllowRule `json:"Allow"`
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

		if !strings.HasPrefix(l.Key(), node.Path()) {
			return fmt.Errorf("Label %s does not share prefix of node %s",
				l.Key(), node.Path())
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
	PolicyRuleBase
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

		if !strings.HasPrefix(l.Key(), node.Path()) {
			return fmt.Errorf("Label %s does not share prefix of node %s",
				l.Key(), node.Path())
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
	PolicyRuleBase
	Ports []Port `json:"Ports"`
}

// Do not allow further rules of specified type
type PolicyRuleDropPrivileges struct {
	PolicyRuleBase
	DropPrivileges []Privilege `json:"Drop-privileges"`
}

// Node to define hierarchy of rules
type PolicyNode struct {
	Name     string
	path     string                 `json:"-"`
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
		if strings.HasPrefix(label.Key(), p.Path()) {
			return true
		}
	}

	return false
}

// Overall policy tree
type PolicyTree struct {
	Root PolicyNode
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

func (pn *PolicyNode) resolveTree() error {
	var err error

	pn.path, err = pn.BuildPath()
	if err != nil {
		return err
	}

	if err := pn.resolveRules(); err != nil {
		return err
	}

	for _, val := range pn.Children {
		if err = val.resolveTree(); err != nil {
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

	// Fill out "Name" field of children which ommited it in the JSON
	for k, _ := range policyNode.Children {
		pn.Children[k].Name = k
		pn.Children[k].Parent = pn
	}

	// We have now parsed all children in a recursive manner and are back
	// to the root node. Walk the tree again to resolve the path of each
	// node.
	if pn.Name == common.GlobalLabelPrefix {
		if err := pn.resolveTree(); err != nil {
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
