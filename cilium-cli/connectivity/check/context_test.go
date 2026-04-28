// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package check

import (
	"bytes"
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/cilium/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium/cilium-cli/k8s"
)

func newCiliumAgentPod(name string, phase corev1.PodPhase, terminating bool) *corev1.Pod {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: "kube-system",
			Labels:    map[string]string{"k8s-app": "cilium"},
		},
		Status: corev1.PodStatus{Phase: phase},
	}
	if terminating {
		now := metav1.Now()
		pod.DeletionTimestamp = &now
		pod.Finalizers = []string{"cilium.io/test"}
	}
	return pod
}

func TestInitCiliumPodsSkipsNonRunning(t *testing.T) {
	objs := []runtime.Object{
		newCiliumAgentPod("cilium-running", corev1.PodRunning, false),
		newCiliumAgentPod("cilium-terminating", corev1.PodRunning, true),
	}
	ct, _ := newFakeConnectivityTest(t, objs...)
	ct.params.CiliumNamespace = "kube-system"
	ct.params.AgentPodSelector = defaults.AgentPodSelector
	ct.ciliumPods = make(map[string]Pod)

	require.NoError(t, ct.initCiliumPods(context.Background()))
	assert.Len(t, ct.ciliumPods, 1, "only the Running, non-terminating pod should be included")
	_, ok := ct.ciliumPods["cilium-running"]
	assert.True(t, ok, "Running pod should be included")
	_, ok = ct.ciliumPods["cilium-terminating"]
	assert.False(t, ok, "Terminating pod should be skipped")
}

func TestInitCiliumPodsErrorWhenAllNonRunning(t *testing.T) {
	objs := []runtime.Object{
		newCiliumAgentPod("cilium-terminating-1", corev1.PodRunning, true),
		newCiliumAgentPod("cilium-terminating-2", corev1.PodRunning, true),
	}
	ct, _ := newFakeConnectivityTest(t, objs...)
	ct.params.CiliumNamespace = "kube-system"
	ct.params.AgentPodSelector = defaults.AgentPodSelector
	ct.ciliumPods = make(map[string]Pod)

	err := ct.initCiliumPods(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Running cilium agent pods")
}

func TestInitCiliumPodsMultiClusterErrorWhenOneClusterEmpty(t *testing.T) {
	srcClient := &k8s.Client{
		Clientset: fake.NewSimpleClientset(newCiliumAgentPod("cilium-src-running", corev1.PodRunning, false)),
	}
	dstClient := &k8s.Client{
		Clientset: fake.NewSimpleClientset(newCiliumAgentPod("cilium-dst-terminating", corev1.PodRunning, true)),
	}

	ct := &ConnectivityTest{
		params: Parameters{
			CiliumNamespace:  "kube-system",
			AgentPodSelector: defaults.AgentPodSelector,
			Writer:           &bytes.Buffer{},
		},
		clients:    &deploymentClients{src: srcClient, dst: dstClient},
		ciliumPods: make(map[string]Pod),
	}

	err := ct.initCiliumPods(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no Running cilium agent pods available in cluster")
}
