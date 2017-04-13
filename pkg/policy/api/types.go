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

package api

import (
	"github.com/cilium/cilium/pkg/labels"
)

// RuleAllow is a rule which allows ingress consumers
type RuleAllow struct {
	// Labels is a list of labels which must be present in the consumers
	// in order for it to be allowed.
	Labels []*labels.Label `json:"matchLabels,omitempty"`

	// LabelCompat is a single allowed label.
	LabelCompat *labels.Label `json:"label,omitempty"` // Kept for backwards compatibility

	// Action is the action to return when evaluating the consuming decision
	Action ConsumableDecision `json:"action,omitempty"`
}

// IsValid returns true if the rule is valid
func (r RuleAllow) IsValid() bool {
	return (r.LabelCompat != nil && r.LabelCompat.IsValid()) || len(r.Labels) > 0
}
