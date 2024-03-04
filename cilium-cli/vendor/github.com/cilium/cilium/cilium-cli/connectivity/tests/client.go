// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"
	check2 "github.com/cilium/cilium/cilium-cli/connectivity/check"

	"github.com/cilium/cilium-cli/utils/features"
)

// ClientToClient sends an ICMP packet from each client Pod
// to each client Pod in the test context.
func ClientToClient() check2.Scenario {
	return &clientToClient{}
}

// clientToClient implements a Scenario.
type clientToClient struct{}

func (s *clientToClient) Name() string {
	return "client-to-client"
}

func (s *clientToClient) Run(ctx context.Context, t *check2.Test) {
	var i int
	ct := t.Context()

	for _, src := range ct.ClientPods() {
		src := src // copy to avoid memory aliasing when using reference

		for _, dst := range ct.ClientPods() {
			if src.Pod.Status.PodIP == dst.Pod.Status.PodIP {
				// Currently we only get flows once per IP,
				// skip pings to self.
				continue
			}

			dst := dst // copy to avoid memory aliasing when using reference

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &src, &dst, ipFam).Run(func(a *check2.Action) {
					a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))

					a.ValidateFlows(ctx, src, a.GetEgressRequirements(check2.FlowParameters{
						Protocol: check2.ICMP,
					}))

					a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check2.FlowParameters{
						Protocol: check2.ICMP,
					}))

					a.ValidateMetrics(ctx, src, a.GetEgressMetricsRequirements())
					a.ValidateMetrics(ctx, dst, a.GetIngressMetricsRequirements())
				})
			})

			i++
		}
	}
}
