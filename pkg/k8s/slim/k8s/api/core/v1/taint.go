// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Copyright 2017 The Kubernetes Authors.

package v1

import "fmt"

// MatchTaint checks if the taint matches taintToMatch. Taints are unique by key:effect,
// if the two taints have same key:effect, regard as they match.
func (t *Taint) MatchTaint(taintToMatch *Taint) bool {
	return t.Key == taintToMatch.Key && t.Effect == taintToMatch.Effect
}

// taint.ToString() converts taint struct to string in format '<key>=<value>:<effect>', '<key>=<value>:', '<key>:<effect>', or '<key>'.
func (t *Taint) ToString() string {
	if len(t.Effect) == 0 {
		if len(t.Value) == 0 {
			return fmt.Sprintf("%v", t.Key)
		}
		return fmt.Sprintf("%v=%v:", t.Key, t.Value)
	}
	if len(t.Value) == 0 {
		return fmt.Sprintf("%v:%v", t.Key, t.Effect)
	}
	return fmt.Sprintf("%v=%v:%v", t.Key, t.Value, t.Effect)
}
