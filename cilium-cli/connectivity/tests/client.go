// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// ClientToClient sends an ICMP packet from each client Pod
// to each client Pod in the test context.
func ClientToClient(name string) check.Scenario {
	return &clientToClient{
		name: name,
	}
}

// clientToClient implements a Scenario.
type clientToClient struct {
	name string
}

func (s *clientToClient) Name() string {
	tn := "client-to-client"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *clientToClient) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, src := range t.Context().ClientPods() {
		for _, dst := range t.Context().ClientPods() {
			if src.Pod.Status.PodIP == dst.Pod.Status.PodIP {
				// Currently we only get flows once per IP,
				// skip pings to self.
				continue
			}

			t.NewAction(s, fmt.Sprintf("ping-%d", i), &src, &dst).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ping(dst))

				a.ValidateFlows(ctx, src, a.GetEgressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))

				a.ValidateFlows(ctx, dst, a.GetIngressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))
			})

			i++
		}
	}
}
