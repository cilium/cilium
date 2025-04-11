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
func ClientToClient() check.Scenario {
	return &clientToClient{
		ScenarioBase: check.NewScenarioBase(),
	}
}

// clientToClient implements a Scenario.
type clientToClient struct {
	check.ScenarioBase
}

func (s *clientToClient) Name() string {
	return "client-to-client"
}

func (s *clientToClient) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, src := range ct.ClientPods() {
		for _, dst := range ct.ClientPods() {
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

					a.ValidateMetrics(ctx, src, a.GetEgressMetricsRequirements())
					a.ValidateMetrics(ctx, dst, a.GetIngressMetricsRequirements())
				})
			})

			i++
		}
	}
}

// ClientToItself is a test to check whether a client can connect itself via Service loopback.
func ClientToItself() check.Scenario {
	return &clientToItself{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type clientToItself struct {
	check.ScenarioBase
}

func (s *clientToItself) Name() string {
	return "pod-to-itself"
}

func (s *clientToItself) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	var i int
	for _, echo := range ct.EchoPods() {
		for _, svc := range ct.EchoServices() {
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				if ipFam == features.IPFamilyV6 {
					// Skip IPv6 for now since it's not supported.
					return
				}
				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &echo, svc, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(svc))

					a.ValidateFlows(ctx, echo, a.GetEgressRequirements(check.FlowParameters{
						DNSRequired: true,
						AltDstPort:  svc.Port(),
					}))
					a.ValidateMetrics(ctx, echo, a.GetEgressMetricsRequirements())
				})
			})
			i++
		}
	}
}
