// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

func PodToExternalWorkload() check.Scenario {
	return &podToExternalWorkload{}
}

type podToExternalWorkload struct{}

func (s *podToExternalWorkload) Name() string {
	return "pod-to-external-workload"
}

func (s *podToExternalWorkload) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, wl := range ct.ExternalWorkloads() {
			t.NewAction(s, fmt.Sprintf("ping-%d", i), &pod, wl).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.PingCommand(wl))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))

				a.ValidateFlows(ctx, wl, a.GetIngressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))
			})

			i++
		}
	}
}
