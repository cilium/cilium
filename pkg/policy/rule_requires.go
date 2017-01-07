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
	"crypto/sha512"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/cilium/pkg/labels"
)

// Any further consumer requires the specified list of
// labels in order to consume
type PolicyRuleRequires struct {
	Coverage []labels.Label `json:"coverage,omitempty"`
	Requires []labels.Label `json:"requires"`
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

func (c *PolicyRuleRequires) Resolve(node *Node) error {
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

func (c *PolicyRuleRequires) CoverageSHA256Sum() (string, error) {
	sha := sha512.New512_256()
	if err := json.NewEncoder(sha).Encode(c.Coverage); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha.Sum(nil)), nil
}
