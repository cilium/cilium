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
	"fmt"
	"strings"

	"github.com/cilium/cilium/common"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/policy/api"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type PolicyRule interface {
	// Resolve must resolve any internal label members to the full path
	// assuming that the rule is attached to the specified node.
	Resolve(node *Node) error

	// SHA256Sum must return the SHA256 hash over the policy rule
	SHA256Sum() (string, error)

	// CoverageSHA256Sum must return the SHA256 hash over the coverage
	// section of the policy rule
	CoverageSHA256Sum() (string, error)

	// IsMergeable must return true if a rule allows merging with other
	// rules within a node. Certain rules are not additive and require
	// strict ordering, such rules may never be merged in a node as
	// merging may occur in undefined order.
	IsMergeable() bool
}

type Rule interface {
	Allows(ctx *SearchContext) api.ConsumableDecision
	String() string
	IsMergeable() bool
}

// RuleBase is the base type for all other rules
// Coverage and CoverageSelector are mutually exclusive. Only one of them can be
// defined.
type RuleBase struct {
	Coverage         labels.LabelArray     `json:"coverage,omitempty"`
	CoverageSelector *metav1.LabelSelector `json:"coverageSelector,omitempty"`
}

// Resolve translates all relative names of the generic part of the rule
// to absolute names. It also verifies that all label references are
// within the scope rules of the node
func (r *RuleBase) Resolve(node *Node) error {
	log.Debugf("Resolving rule %+v\n", r)

	for _, l := range r.Coverage {
		l.Resolve(node)

		if node.IgnoreNameCoverage {
			continue
		}

		if !strings.HasPrefix(l.AbsoluteKey(), node.Path()) &&
			!(l.Source == common.ReservedLabelSource) {
			return fmt.Errorf("label %s does not share prefix of node %s",
				l.AbsoluteKey(), node.Path())
		}
	}

	return nil
}
