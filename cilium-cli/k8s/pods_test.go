// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package k8s

import (
	"testing"

	"github.com/stretchr/testify/assert"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestIsSupersededPodRejection(t *testing.T) {
	for _, reason := range []string{"TaintToleration", "NodeAffinity", "NodeLost", "Evicted", "Shutdown", "Preempting", "UnexpectedAdmissionError"} {
		assert.True(t, IsSupersededPodRejection(reason), reason)
	}
	for _, reason := range []string{"", "OOMKilled", "Error", "ContainerCannotRun"} {
		assert.False(t, IsSupersededPodRejection(reason), reason)
	}
}

func pod(name string, phase corev1.PodPhase, reason string) corev1.Pod {
	return corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Status:     corev1.PodStatus{Phase: phase, Reason: reason},
	}
}

func TestLivePods(t *testing.T) {
	// A superseded leftover alongside its healthy replacement.
	live := LivePods([]corev1.Pod{
		pod("echo-evicted", corev1.PodFailed, "Evicted"),
		pod("echo-running", corev1.PodRunning, ""),
	})
	assert.Len(t, live, 1)
	assert.Equal(t, "echo-running", live[0].Name)

	// Genuine failures are kept, so a broken deployment is still surfaced.
	live = LivePods([]corev1.Pod{
		pod("echo-oom", corev1.PodFailed, ""),
		pod("echo-running", corev1.PodRunning, ""),
	})
	assert.Len(t, live, 2)

	// The reason alone is not enough, the pod has to be terminal.
	live = LivePods([]corev1.Pod{pod("echo-running", corev1.PodRunning, "Evicted")})
	assert.Len(t, live, 1)

	// Everything evicted leaves nothing live, which still trips the callers.
	live = LivePods([]corev1.Pod{pod("echo-evicted", corev1.PodFailed, "Evicted")})
	assert.Empty(t, live)

	assert.Empty(t, LivePods(nil))
}
