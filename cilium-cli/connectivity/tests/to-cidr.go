// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToCIDR sends an ICMP packet from each client Pod
// to ExternalIP and ExternalOtherIP.
func PodToCIDR() check.Scenario {
	return &podToCIDR{}
}

// podToCIDR implements a Scenario.
type podToCIDR struct{}

func (s *podToCIDR) Name() string {
	return "pod-to-cidr"
}

func (s *podToCIDR) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	for _, ip := range []string{ct.Params().ExternalIP, ct.Params().ExternalOtherIP} {
		ep := check.HTTPEndpoint(fmt.Sprintf("external-%s", strings.ReplaceAll(ip, ".", "")), "https://"+ip)

		var i int
		for _, src := range ct.ClientPods() {
			src := src // copy to avoid memory aliasing when using reference

			t.NewAction(s, fmt.Sprintf("%s-%d", ep.Name(), i), &src, ep, check.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(ep, check.IPFamilyAny))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					RSTAllowed: true,
				}))
			})
			i++
		}
	}
}
