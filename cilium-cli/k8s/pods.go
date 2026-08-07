// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

// IsSupersededPodRejection reports whether a Failed pod reached its terminal
// state by admission-rejection or eviction rather than by running and crashing.
// Such pods (e.g. bound to a node still carrying node.cilium.io/agent-not-ready
// :NoExecute) are already replaced by a healthy sibling from the controller, so
// they must not fail `status --wait`. A container that ran and crashed has an
// empty pod-level Status.Reason and is therefore still surfaced.
func IsSupersededPodRejection(reason string) bool {
	switch reason {
	case "TaintToleration", "NodeAffinity", "NodeLost", "Evicted",
		"Shutdown", "Preempting", "UnexpectedAdmissionError":
		return true
	}
	return false
}
