// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// PodToK8sLocal sends a curl from all control plane client Pods
// to all control-plane nodes.
func PodToK8sLocal() check.Scenario {
	return &podToK8sLocal{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// podToK8sLocal implements a Scenario.
type podToK8sLocal struct {
	check.ScenarioBase
}

func (s *podToK8sLocal) Name() string {
	return "pod-to-k8s-local"
}

func (s *podToK8sLocal) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	k8sSvc := ct.K8sService()
	ipFamilies := []features.IPFamily{features.IPFamilyV4, features.IPFamilyV6}
	for _, pod := range ct.ControlPlaneClientPods() {
		for _, ipFamily := range ipFamilies {
			actionName := fmt.Sprintf("curl-k8s-from-pod-%s-%s", pod.Name(), ipFamily)
			t.NewAction(s, actionName, &pod, k8sSvc, ipFamily).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommand(k8sSvc))
				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: true,
					AltDstPort:  k8sSvc.Port(),
				}))

				a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
			})
		}
	}
}
