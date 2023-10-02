// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// PodToHost sends an ICMP ping from all client Pods to all nodes
// in the test context.
func PodToHost() check.Scenario {
	return &podToHost{}
}

// podToHost implements a Scenario.
type podToHost struct{}

func (s *podToHost) Name() string {
	return "pod-to-host"
}

func (s *podToHost) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()
	// Construct a unique list of all nodes in the cluster running workloads.

	var i int

	for _, pod := range ct.ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, node := range ct.Nodes() {
			node := node

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				for _, addr := range node.Status.Addresses {
					if features.GetIPFamily(addr.Address) != ipFam {
						continue
					}

					dst := check.ICMPEndpoint("", addr.Address)
					ipFam := features.GetIPFamily(addr.Address)

					t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &pod, dst, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))

						a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
							Protocol: check.ICMP,
						}))

						a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
					})

					i++
				}
			})
		}
	}
}

// PodToHostPort sends an HTTP request from all client Pods
// to all echo Services' HostPorts.
func PodToHostPort() check.Scenario {
	return &podToHostPort{}
}

// podToHostPort implements a ConditionalScenario.
type podToHostPort struct{}

func (s *podToHostPort) Name() string {
	return "pod-to-hostport"
}

func (s *podToHostPort) Requirements() []features.Requirement {
	return []features.Requirement{
		features.RequireEnabled(features.HostPort),
	}
}

func (s *podToHostPort) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, client := range ct.ClientPods() {
		client := client // copy to avoid memory aliasing when using reference

		for _, echo := range ct.EchoPods() {
			echo := echo // copy to avoid memory aliasing when using reference

			baseURL := fmt.Sprintf("%s://%s:%d%s", echo.Scheme(), echo.Pod.Status.HostIP, check.EchoServerHostPort, echo.Path())
			ep := check.HTTPEndpoint(echo.Name(), baseURL)
			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, ep, features.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(ep, features.IPFamilyAny))

				a.ValidateFlows(ctx, client, a.GetEgressRequirements(check.FlowParameters{
					// Because the HostPort request is NATed, we might only
					// observe flows after DNAT has been applied (e.g. by
					// HostReachableServices),
					AltDstIP:   echo.Address(features.IPFamilyAny),
					AltDstPort: echo.Port(),
				}))
			})

			i++
		}
	}
}
