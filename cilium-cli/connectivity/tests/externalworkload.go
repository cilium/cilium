// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

func PodToExternalWorkload(name string) check.Scenario {
	return &podToExternalWorkload{
		name: name,
	}
}

type podToExternalWorkload struct {
	name string
}

func (s *podToExternalWorkload) Name() string {
	tn := "pod-to-external-workload"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *podToExternalWorkload) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, wl := range t.Context().ExternalWorkloads() {
			t.NewAction(s, fmt.Sprintf("ping-%d", i), &pod, wl).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ping(wl))

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
