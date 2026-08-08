// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	corev1 "k8s.io/api/core/v1"
)

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

// LivePods returns the pods that are not terminal, controller-superseded
// leftovers. Listing pods by label selector alone also returns such leftovers,
// which carry no pod IP and are never going to run, so counting them makes a
// healthy single-replica deployment look like it has two pods.
func LivePods(pods []corev1.Pod) []corev1.Pod {
	live := make([]corev1.Pod, 0, len(pods))
	for _, pod := range pods {
		if pod.Status.Phase == corev1.PodFailed && IsSupersededPodRejection(pod.Status.Reason) {
			continue
		}
		live = append(live, pod)
	}
	return live
}
