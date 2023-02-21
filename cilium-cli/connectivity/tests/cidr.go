// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

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
		check.HTTPEndpoint("cloudflare-1001", "https://"+t.Context().Params().ExternalOtherIP),
		check.HTTPEndpoint("cloudflare-1111", "https://"+t.Context().Params().ExternalIP),
	}
	ct := t.Context()

	for _, ep := range eps {
		var i int
		for _, src := range ct.ClientPods() {
			src := src // copy to avoid memory aliasing when using reference

			t.NewAction(s, fmt.Sprintf("%s-%d", ep.Name(), i), &src, ep, check.IPFamilyNone).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(ep, check.IPFamilyNone))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					RSTAllowed: true,
				}))
			})
			i++
		}
	}
}
