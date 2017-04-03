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
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
)

type AllowRule struct {
	Action ConsumableDecision `json:"action,omitempty"`
	Label  *labels.Label      `json:"label"`
}

func (a *AllowRule) IsMergeable() bool {
	switch a.Action {
	case DENY:
		// Deny rules will result in immediate return from the policy
		// evaluation process and thus rely on strict ordering of the rules.
		// Merging of such rules in a node will result in undefined behaviour.
		return false
	}

	return true
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
		Label  *labels.Label      `json:"label"`
	}

	// Default is allow
	aux.Action = ACCEPT

	// We first attempt to parse a full AllowRule JSON object which
	// was likely created by MarshalJSON of the client, in case that
	// fails we attempt to parse the string as a pure Label which
	// can be used as a shortform to specify allow rules.
	decoder := json.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&aux)
	if err != nil || aux.Label == nil || !aux.Label.IsValid() {
		var aux labels.Label

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

		a.Label = &aux
	} else {
		a.Action = aux.Action
		a.Label = aux.Label
	}

	return nil
}

func (a *AllowRule) String() string {
	return fmt.Sprintf("{label: %s, action: %s}", a.Label, a.Action.String())
}

func (a *AllowRule) Allows(ctx *SearchContext) ConsumableDecision {
	ctx.Depth++
	defer func() {
		ctx.Depth--
	}()
	for _, label := range ctx.From {
		if a.Label.Matches(label) {
			policyTrace(ctx, "Found label matching [%s] in rule: [%s]\n", label.String(), a.String())
			return a.Action
		}
	}

	policyTrace(ctx, "No matching labels in allow rule: [%s]\n", a.String())
	return UNDECIDED
}

// RuleConsumers allows the following consumers.
type RuleConsumers struct {
	Coverage []*labels.Label `json:"coverage,omitempty"`
	Allow    []*AllowRule    `json:"allow"`
}

func (prc *RuleConsumers) IsMergeable() bool {
	for _, r := range prc.Allow {
		if !r.IsMergeable() {
			return false
		}
	}

	return true
}

func (prc *RuleConsumers) String() string {
	coverages := []string{}
	for _, lbl := range prc.Coverage {
		coverages = append(coverages, lbl.String())
	}
	allows := []string{}
	for _, allow := range prc.Allow {
		allows = append(allows, allow.String())
	}
	return fmt.Sprintf("Coverage: [%s] Allowing: [%s]", strings.Join(coverages, " "),
		strings.Join(allows, " "))
}

func (prc *RuleConsumers) Allows(ctx *SearchContext) ConsumableDecision {
	// A decision is undecided until we encoutner a DENY or ACCEPT.
	// An ACCEPT can still be overwritten by a DENY inside the same rule.
	decision := UNDECIDED

	if len(prc.Coverage) > 0 && !ctx.TargetCoveredBy(prc.Coverage) {
		policyTrace(ctx, "Rule has no coverage: [%s]\n", prc.String())
		return UNDECIDED
	}

	policyTrace(ctx, "Found coverage rule: [%s]", prc.String())

	for _, allowRule := range prc.Allow {
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

func (prc *RuleConsumers) Resolve(node *Node) error {
	log.Debugf("Resolving consumer rule %+v\n", prc)
	for _, l := range prc.Coverage {
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) &&
			!(l.Source == common.ReservedLabelSource) {
			return fmt.Errorf("label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for _, r := range prc.Allow {
		r.Label.Resolve(node)
	}

	return nil
}

func (prc *RuleConsumers) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(prc); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (prc *RuleConsumers) CoverageSHA256Sum() (string, error) {
	return labels.LabelSliceSHA256Sum(prc.Coverage)
}
