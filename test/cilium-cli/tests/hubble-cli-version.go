// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

func PolicyVerdict() check.Scenario {
	return &policyVerdict{}
}

type policyVerdict struct{}

func (p *policyVerdict) Name() string {
	return "policy-verdict"
}

func (p *policyVerdict) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference
		for _, echo := range ct.EchoPods() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(p, fmt.Sprintf("curl-%p-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, ipFam))
					//a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{}))
					//a.ValidateFlows(ctx, echo, a.GetIngressRequirements(check.FlowParameters{}))
				})
			})

			i++
		}

	}
}
