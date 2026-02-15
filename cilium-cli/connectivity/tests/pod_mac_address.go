// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/pkg/annotation"
)

const podMACAddressLabelSelector = "specific-mac-address=specific-mac-address"

// PodMACAddress validates that Cilium configured the pod interface MAC to the
// value advertised in the pod annotation.
func PodMACAddress() check.Scenario {
	return &podMACAddress{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type podMACAddress struct {
	check.ScenarioBase
}

func (s *podMACAddress) Name() string {
	return "pod-mac-address"
}

func (s *podMACAddress) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	pods, err := ct.K8sClient().ListPods(ctx, ct.Params().TestNamespace, metav1.ListOptions{LabelSelector: podMACAddressLabelSelector})
	if err != nil {
		t.Fatalf("failed to list pod with label selector %q: %v", podMACAddressLabelSelector, err)
	}
	if len(pods.Items) != 1 {
		t.Fatalf("expected exactly 1 pod for %q, got %d", podMACAddressLabelSelector, len(pods.Items))
	}

	pod := pods.Items[0]
	macAddress := pod.Annotations[annotation.PodAnnotationMAC]
	if macAddress == "" {
		t.Fatalf("pod %s/%s has no %q annotation", pod.Namespace, pod.Name, annotation.PodAnnotationMAC)
	}

	t.NewGenericAction(s, fmt.Sprintf("check-mac-%s", pod.Name)).Run(func(a *check.Action) {
		containerName := pod.Spec.Containers[0].Name
		cmd := []string{"sh", "-c", fmt.Sprintf("ip link show | grep -F -i -- %q", macAddress)}
		stdout, err := ct.K8sClient().ExecInPod(ctx, pod.Namespace, pod.Name, containerName, cmd)
		if err != nil {
			a.Fatalf("failed to verify MAC address %q in pod %s/%s: %v\noutput: %s", macAddress, pod.Namespace, pod.Name, err, strings.TrimSpace(stdout.String()))
		}
	})
}
