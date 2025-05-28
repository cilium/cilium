// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

// PolicyCorrelationInfo is the information about a policy required for policy correlation.
type PolicyCorrelationInfo struct {
	// RuleLabels are the rule labels.
	RuleLabels string
	// Revision is the policy revision.
	Revision uint64
}
