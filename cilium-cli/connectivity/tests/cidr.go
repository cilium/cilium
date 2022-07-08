// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToCIDR sends an ICMP packet from each client Pod
// to 1.1.1.1 and 1.0.0.1.
func PodToCIDR() check.Scenario {
	return &podToCIDR{}
}

// podToCIDR implements a Scenario.
type podToCIDR struct{}

func (s *podToCIDR) Name() string {
	return "pod-to-cidr"
}

func (s *podToCIDR) Run(ctx context.Context, t *check.Test) {
	eps := []check.TestPeer{
		check.HTTPEndpoint("cloudflare-1001", "http://1.0.0.1"),
		check.HTTPEndpoint("cloudflare-1111", "http://1.1.1.1"),
	}

	for _, ep := range eps {
		var i int
		for _, src := range t.Context().ClientPods() {
			src := src // copy to avoid memory aliasing when using reference

			t.NewAction(s, fmt.Sprintf("%s-%d", ep.Name(), i), &src, ep).Run(func(a *check.Action) {
				a.ExecInPod(ctx, curl(ep))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					RSTAllowed: true,
				}))
			})
			i++
		}
	}
}
