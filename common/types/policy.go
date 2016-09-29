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
package types

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/cilium/cilium/common"

	"github.com/op/go-logging"
)

var (
	log = logging.MustGetLogger("cilium-net")
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

type ReservedID uint32

const (
	ID_NAME_ALL   = "all"
	ID_NAME_HOST  = "host"
	ID_NAME_WORLD = "world"
)

const (
	ID_UNKNOWN ReservedID = iota
	ID_HOST
	ID_WORLD
)

var (
	ResDec = map[string]ReservedID{
		ID_NAME_HOST:  ID_HOST,
		ID_NAME_WORLD: ID_WORLD,
	}
	ResEnc = map[ReservedID]string{
		ID_HOST:  ID_NAME_HOST,
		ID_WORLD: ID_NAME_WORLD,
	}
)

func (id ReservedID) String() string {
	if v, exists := ResEnc[id]; exists {
		return v
	}

	return ""
}

func GetID(name string) ReservedID {
	if v, ok := ResDec[name]; ok {
		return v
	}
	return ID_UNKNOWN
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
	From []Label
	To   []Label
}

type SearchContextReply struct {
	Logging  []byte
	Decision ConsumableDecision
}

func (s *SearchContext) TargetCoveredBy(coverage []Label) bool {
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

type AllowRule struct {
	Action ConsumableDecision `json:"action,omitempty"`
	Label  Label              `json:"label"`
}

func (a *AllowRule) UnmarshalJSON(data []byte) error {
	if a == nil {
		a = new(AllowRule)
	}

	if len(data) == 0 {
		return fmt.Errorf("invalid AllowRule: empty data")
	}

	var aux struct {
		Action ConsumableDecision `json:"action,omitempty"`
		Label  Label              `json:"label"`
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
			return fmt.Errorf("decode of AllowRule failed: %s", err)
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
	for k := range ctx.From {
		label := &ctx.From[k]
		if a.Label.Matches(label) {
			policyTrace(ctx, "Label %v matched in rule %+v\n", label, a)
			return a.Action
		}
	}

	policyTrace(ctx, "No match in allow rule %+v\n", a)
	return UNDECIDED
}

type PolicyRule interface {
	Allows(ctx *SearchContext) ConsumableDecision
	Resolve(node *PolicyNode) error
	SHA256Sum() (string, error)
}

// Allow the following consumers
type PolicyRuleConsumers struct {
	Coverage []Label     `json:"coverage,omitempty"`
	Allow    []AllowRule `json:"allow"`
}

func (c *PolicyRuleConsumers) Allows(ctx *SearchContext) ConsumableDecision {
	// A decision is undecided until we encoutner a DENY or ACCEPT.
	// An ACCEPT can still be overwritten by a DENY inside the same rule.
	decision := UNDECIDED

	if len(c.Coverage) > 0 && !ctx.TargetCoveredBy(c.Coverage) {
		policyTrace(ctx, "Rule %v has no coverage\n", c)
		return UNDECIDED
	}

	policyTrace(ctx, "Matching coverage for rule %+v ", c)

	for k := range c.Allow {
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
	log.Debugf("Resolving consumer rule %+v\n", c)
	for k := range c.Coverage {
		l := &c.Coverage[k]
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) &&
			!(l.Source == common.ReservedLabelSource) {
			return fmt.Errorf("label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for k := range c.Allow {
		r := &c.Allow[k]
		r.Label.Resolve(node)
	}

	return nil
}

func (c *PolicyRuleConsumers) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(c); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

// Any further consumer requires the specified list of
// labels in order to consume
type PolicyRuleRequires struct {
	Coverage []Label `json:"coverage,omitempty"`
	Requires []Label `json:"requires"`
}

// A require rule imposes additional label requirements but does not
// imply access immediately. Hence if the label context is not sufficient
// access can be denied but fullfillment of the requirement only leads to
// the decision being UNDECIDED waiting on an explicit allow rule further
// down the tree
func (r *PolicyRuleRequires) Allows(ctx *SearchContext) ConsumableDecision {
	if len(r.Coverage) > 0 && ctx.TargetCoveredBy(r.Coverage) {
		policyTrace(ctx, "Matching coverage for rule %+v ", r)
		for k := range r.Requires {
			reqLabel := &r.Requires[k]
			match := false

			for k2 := range ctx.From {
				label := &ctx.From[k2]
				if label.Equals(reqLabel) {
					match = true
				}
			}

			if match == false {
				policyTrace(ctx, "... did not find required labels [%+v]: %v\n", r.Requires, DENY)
				return DENY
			}
		}
	} else {
		policyTrace(ctx, "Rule %v has no coverage\n", r)
	}

	return UNDECIDED
}

func (c *PolicyRuleRequires) Resolve(node *PolicyNode) error {
	log.Debugf("Resolving requires rule %+v\n", c)
	for k := range c.Coverage {
		l := &c.Coverage[k]
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) {
			return fmt.Errorf("label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for k := range c.Requires {
		l := &c.Requires[k]
		l.Resolve(node)
	}

	return nil
}

func (c *PolicyRuleRequires) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(c); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

type Port struct {
	Proto  string `json:"protocol"`
	Number int    `json:"number"`
}

type PolicyRulePorts struct {
	Coverage []Label `json:"coverage,omitempty"`
	Ports    []Port  `json:"ports"`
}

// Do not allow further rules of specified type
type PolicyRuleDropPrivileges struct {
	Coverage       []Label     `json:"coverage,omitempty"`
	DropPrivileges []Privilege `json:"drop-privileges"`
}

// Node to define hierarchy of rules
type PolicyNode struct {
	path     string
	Name     string                 `json:"name"`
	Parent   *PolicyNode            `json:"-"`
	Rules    []PolicyRule           `json:"rules,omitempty"`
	Children map[string]*PolicyNode `json:"children,omitempty"`
}

func NewPolicyNode(name string, parent *PolicyNode) *PolicyNode {
	return &PolicyNode{
		Name:     name,
		Parent:   parent,
		Rules:    nil,
		Children: map[string]*PolicyNode{},
	}
}

func (p *PolicyNode) Path() string {
	if p.path == "" {
		p.path, _ = p.BuildPath()
		// FIXME: handle error?
	}

	return p.path
}

func (p *PolicyNode) Covers(ctx *SearchContext) bool {
	for k := range ctx.To {
		if ctx.To[k].Covers(p.Path()) {
			return true
		}
	}

	return false
}

func (p *PolicyNode) Allows(ctx *SearchContext) ConsumableDecision {
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
		return "", fmt.Errorf("error in policy: node %s is lacking parent", pn.Name)
	}

	return common.GlobalLabelPrefix, nil
}

func (pn *PolicyNode) resolveRules() error {
	log.Debugf("Resolving rules of node %+v\n", pn)

	for k := range pn.Rules {
		if err := pn.Rules[k].Resolve(pn); err != nil {
			return err
		}
	}

	return nil
}

func (p *PolicyNode) HasPolicyRule(pr PolicyRule) bool {
	pr256Sum, _ := pr.SHA256Sum()
	for _, r := range p.Rules {
		if r256Sum, _ := r.SHA256Sum(); r256Sum == pr256Sum {
			return true
		}
	}
	return false
}

func (pn *PolicyNode) ResolveTree() error {
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

func (pn *PolicyNode) UnmarshalJSON(data []byte) error {
	var policyNode struct {
		Name     string                 `json:"name,omitempty"`
		Rules    []*json.RawMessage     `json:"rules,omitempty"`
		Children map[string]*PolicyNode `json:"children,omitempty"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))

	if err := decoder.Decode(&policyNode); err != nil {
		return fmt.Errorf("decode of PolicyNode failed: %s", err)
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

func (pn *PolicyNode) Merge(obj *PolicyNode) error {
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

func (pn *PolicyNode) AddChild(name string, child *PolicyNode) error {
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

func (t *PolicyTree) Allows(ctx *SearchContext) ConsumableDecision {
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

func SplitPolicyNodePath(fullPath string) (string, string) {
	var extension = filepath.Ext(fullPath)
	return fullPath[0 : len(fullPath)-len(extension)], extension
}
