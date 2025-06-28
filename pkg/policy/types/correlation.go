// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import "github.com/cilium/cilium/pkg/labels"

// PolicyCorrelationInfo is the information about a policy required for policy correlation.
type PolicyCorrelationInfo struct {
	// RuleLabels are the rule labels.
	RuleLabels labels.LabelArrayListString

	// Log is the set of custom Log strings. Policies without a Spec.Log.Value will have
	// no entry here. Duplicate strings are coalesced.
	Log []string

	// Revision is the policy revision.
	Revision uint64
}
