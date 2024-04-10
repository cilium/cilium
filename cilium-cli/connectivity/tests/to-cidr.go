// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	"strings"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// PodToCIDR sends an HTTPS request from each client Pod
// to ExternalIP and ExternalOtherIP
func PodToCIDR(opts ...RetryOption) check.Scenario {
	cond := &retryCondition{}
	for _, op := range opts {
		op(cond)
	}
	return &podToCIDR{rc: cond}
}

// podToCIDR implements a Scenario.
type podToCIDR struct {
	rc *retryCondition
}

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

			t.NewAction(s, fmt.Sprintf("%s-%d", ep.Name(), i), &src, ep, features.IPFamilyAny).Run(func(a *check.Action) {
				opts := s.rc.CurlOptions(ep, features.IPFamilyAny, src, ct.Params())
				a.ExecInPod(ctx, ct.CurlCommand(ep, features.IPFamilyAny, opts...))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					RSTAllowed: true,
				}))
			})
			i++
		}
	}
}
