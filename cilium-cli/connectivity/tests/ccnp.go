// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// ClientToClient sends an ICMP packet from each client Pod
// to each client Pod in the test context.
func CCNPClienttoClient() check.Scenario {
	return &CCNPClientClient{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// clientToClient implements a Scenario.
type CCNPClientClient struct {
	check.ScenarioBase
}

func (s *CCNPClientClient) Name() string {
	return "ccnp-client-to-client"
}

func (s *CCNPClientClient) Run(ctx context.Context, t *check.Test) {

	var i int
	ct := t.Context()

	for _, src := range ct.CCNPTestPods() {
		for _, dst := range ct.CCNPTestPods() {
			if src.Pod.Status.PodIP == dst.Pod.Status.PodIP {
				// Currently we only get flows once per IP,
				// skip pings to self.
				continue
			}
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &src, &dst, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))
					a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
						Protocol: check.ICMP,
					}))
					a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check.FlowParameters{
						Protocol: check.ICMP,
					}))

				})
			})

			i++
		}
	}
}
