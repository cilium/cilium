// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/utils/features"

	"github.com/cilium/cilium/pkg/cilium-cli/connectivity/check"
)

// PodToK8sLocal sends a curl from all control plane client Pods
// to all control-plane nodes.
func PodToK8sLocal() check.Scenario {
	return &podToK8sLocal{}
}

// podToK8sLocal implements a Scenario.
type podToK8sLocal struct{}

func (s *podToK8sLocal) Name() string {
	return "pod-to-k8s-local"
}

func (s *podToK8sLocal) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	k8sSvc := ct.K8sService()
	for _, pod := range ct.ControlPlaneClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference
		t.NewAction(s, fmt.Sprintf("curl-k8s-from-pod-%s", pod.Name()), &pod, k8sSvc, features.IPFamilyAny).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.CurlCommand(k8sSvc, features.IPFamilyAny))
			a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
				DNSRequired: true,
				AltDstPort:  k8sSvc.Port(),
			}))

			a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
		})
	}
}
