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
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"
)

// RuleRequires any further consumer requires the specified list of
// labels in order to consume.
type RuleRequires struct {
	Coverage []*labels.Label `json:"coverage,omitempty"`
	Requires []*labels.Label `json:"requires"`
}

func (prr *RuleRequires) IsMergeable() bool {
	return true
}

func (prr *RuleRequires) String() string {
	return fmt.Sprintf("Coverage: %s, Requires: %s", prr.Coverage, prr.Requires)
}

// Allows a require rule imposes additional label requirements but does not
// imply access immediately. Hence if the label context is not sufficient
// access can be denied but fullfillment of the requirement only leads to
// the decision being UNDECIDED waiting on an explicit allow rule further
// down the tree
func (prr *RuleRequires) Allows(ctx *SearchContext) api.ConsumableDecision {
	if len(prr.Coverage) > 0 && ctx.TargetCoveredBy(prr.Coverage) {
		policyTrace(ctx, "Found coverage rule: %s\n", prr.String())
		for _, reqLabel := range prr.Requires {
			match := false

			for _, label := range ctx.From {
				if label.Equals(reqLabel) {
					match = true
				}
			}

			if match == false {
				ctx.Depth++
				policyTrace(ctx, "No matching labels in required rule [%s], verdict: [%s]\n",
					prr.Requires, api.DENY.String())
				ctx.Depth--
				return api.DENY
			}
		}
	} else {
		policyTrace(ctx, "Rule has no coverage: %s\n", prr)
	}

	return api.UNDECIDED
}

func (prr *RuleRequires) Resolve(node *Node) error {
	log.Debugf("Resolving requires rule %+v\n", prr)
	for _, l := range prr.Coverage {
		l.Resolve(node)

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) {
			return fmt.Errorf("label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	for _, l := range prr.Requires {
		l.Resolve(node)
	}

	return nil
}

func (prr *RuleRequires) SHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(prr); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}

func (prr *RuleRequires) CoverageSHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(prr.Coverage); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}
