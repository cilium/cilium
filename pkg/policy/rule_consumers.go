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
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sLbls "k8s.io/apimachinery/pkg/labels"
)

type AllowRule struct {
	Action        api.ConsumableDecision `json:"action,omitempty"`
	Labels        labels.LabelArray      `json:"matchLabels,omitempty"`
	MatchSelector *metav1.LabelSelector  `json:"matchSelector,omitempty"`
}

func (a *AllowRule) IsMergeable() bool {
	switch a.Action {
	case api.DENY:
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

	// Template to parse allow rule into
	// default action is accept
	aux := api.RuleAllow{Action: api.ACCEPT}

	// We first attempt to parse a full AllowRule JSON object which
	// was likely created by MarshalJSON of the client, in case that
	// fails we attempt to parse the string as a pure Label which
	// can be used as a shortform to specify allow rules.
	decoder := json.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&aux)
	if err != nil || !aux.IsValid() {
		var aux labels.Label

		decoder = json.NewDecoder(bytes.NewReader(data))
		if err := decoder.Decode(&aux); err != nil {
			return fmt.Errorf("decode of AllowRule failed: %s", err)
		}

		if aux.Key[0] == '!' {
			a.Action = api.DENY
			aux.Key = aux.Key[1:]
		} else {
			a.Action = api.ACCEPT
		}

		a.Labels = labels.LabelArray{&aux}
	} else {
		a.Action = aux.Action
		if aux.LabelCompat != nil && aux.LabelCompat.Key != "" {
			a.Labels = labels.LabelArray{aux.LabelCompat}
		} else {
			a.Labels = aux.Labels
		}
	}

	return nil
}

func (a *AllowRule) String() string {
	return fmt.Sprintf("{labels: %s, selector: %s, action: %s}", a.Labels, a.MatchSelector, a.Action.String())
}

// Allows returns the decision whether the node allows the From to consume the
// To in the provided search context
func (a *AllowRule) Allows(ctx *SearchContext) api.ConsumableDecision {
	ctx.Depth++
	defer func() {
		ctx.Depth--
	}()

	if a.Labels != nil {
		if ctx.From.Contains(a.Labels) {
			ctx.PolicyTrace("Found all required labels [%v] in rule: [%s]\n", a.Labels, a.String())
			return a.Action
		}
	} else if a.MatchSelector != nil {
		lbSelector, err := metav1.LabelSelectorAsSelector(a.MatchSelector)
		if err != nil {
			log.Errorf("unable the match selector %+v in selector: %s", a.MatchSelector, err)
			return api.UNDECIDED
		}
		if lbSelector.Matches(k8sLbls.Labels(removeRootK8sPrefixFromLabelArray(ctx.From))) {
			return a.Action
		}
	}

	ctx.PolicyTrace("No matching labels in allow rule: [%s]\n", a.String())
	return api.UNDECIDED
}

// RuleConsumers allows the following consumers.
type RuleConsumers struct {
	RuleBase
	Allow []*AllowRule `json:"allow"`
}

// AllowReserved creates a RuleConsumers that allows to receive traffic from the
// `res` reserved label to the given `coverage` label array.
func AllowReserved(coverage *labels.Label, res string) PolicyRule {
	ar := &AllowRule{
		Action: api.ACCEPT,
		Labels: []*labels.Label{
			labels.NewLabel(
				res, "", common.ReservedLabelSource,
			),
		},
	}

	return &RuleConsumers{
		RuleBase: RuleBase{Coverage: []*labels.Label{coverage}},
		Allow:    []*AllowRule{ar},
	}
}

// ReservedAllow creates a RuleConsumers that allows to receive traffic from the
// `allow` label to the given `res` reserved label.
func ReservedAllow(res string, allow *labels.Label) PolicyRule {
	ar := &AllowRule{
		Action: api.ACCEPT,
		Labels: []*labels.Label{
			allow,
		},
	}
	return &RuleConsumers{
		RuleBase: RuleBase{Coverage: []*labels.Label{
			labels.NewLabel(res, "", common.ReservedLabelSource)},
		},
		Allow: []*AllowRule{ar},
	}
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

// Allows returns the decision whether the node allows the From to consume the
// To in the provided search context
func (prc *RuleConsumers) Allows(ctx *SearchContext) api.ConsumableDecision {
	// A decision is undecided until we encounter a DENY or ACCEPT.
	// An ACCEPT can still be overwritten by a DENY inside the same rule.
	decision := api.UNDECIDED

	if prc.Coverage != nil && len(prc.Coverage) > 0 {
		if !ctx.TargetCoveredBy(prc.Coverage) {
			ctx.PolicyTrace("Rule has no coverage: [%s]\n", prc.String())
			return api.UNDECIDED
		}
	} else if prc.CoverageSelector != nil {
		lbSelector, err := metav1.LabelSelectorAsSelector(prc.CoverageSelector)
		if err != nil {
			log.Errorf("unable the coverage selector %+v in selector: %s", prc.CoverageSelector, err)
			return api.UNDECIDED
		}
		if !lbSelector.Matches(k8sLbls.Labels(removeRootK8sPrefixFromLabelArray(ctx.To))) {
			ctx.PolicyTrace("Rule has no coverage: [%s] for %s\n", prc.String(), ctx.To)
			return api.UNDECIDED
		}
	}

	ctx.PolicyTrace("Found coverage rule: [%s]", prc.String())

	for _, allowRule := range prc.Allow {
		switch allowRule.Allows(ctx) {
		case api.DENY:
			return api.DENY
		case api.ALWAYS_ACCEPT:
			return api.ALWAYS_ACCEPT
		case api.ACCEPT:
			decision = api.ACCEPT
			break
		}
	}

	return decision
}

func (prc *RuleConsumers) Resolve(node *Node) error {
	log.Debugf("Resolving consumer rule %+v\n", prc)

	if err := prc.RuleBase.Resolve(node); err != nil {
		return err
	}

	for _, r := range prc.Allow {
		r.Labels.Resolve(node)
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
