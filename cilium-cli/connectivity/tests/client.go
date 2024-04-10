// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// ClientToClient sends an ICMP packet from each client Pod
// to each client Pod in the test context.
func ClientToClient() check.Scenario {
	return &clientToClient{}
}

// clientToClient implements a Scenario.
type clientToClient struct{}

func (s *clientToClient) Name() string {
	return "client-to-client"
}

func (s *clientToClient) Run(ctx context.Context, t *check.Test) {
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
				t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &src, &dst, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))

					a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
						Protocol: check.ICMP,
					}))

					a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check.FlowParameters{
						Protocol: check.ICMP,
					}))

					a.ValidateMetrics(ctx, src, a.GetEgressMetricsRequirements())
					a.ValidateMetrics(ctx, dst, a.GetIngressMetricsRequirements())
				})
			})

			i++
		}
	}
}
