// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToHost sends an ICMP ping from all client Pods to all nodes
// in the test context.
func PodToHost(name string) check.Scenario {
	return &podToHost{
		name: name,
	}
}

// podToHost implements a Scenario.
type podToHost struct {
	name string
}

func (s *podToHost) Name() string {
	tn := "pod-to-host"
	if s.name == "" {
		return tn
	}
	return fmt.Sprintf("%s:%s", tn, s.name)
}

func (s *podToHost) Run(ctx context.Context, t *check.Test) {
	// Construct a unique list of all nodes in the cluster running workloads.
	// TODO(timo): Should probably use Cilium agent Pods or actual nodes as the
	// source of truth here.
	nodes := make(map[string]check.TestPeer)
	for _, client := range t.Context().ClientPods() {
		ip := client.Pod.Status.HostIP
		nodes[ip] = check.ICMPEndpoint("", ip)
	}
	for _, echo := range t.Context().EchoPods() {
		ip := echo.Pod.Status.HostIP
		nodes[ip] = check.ICMPEndpoint("", ip)
	}

	var i int

	for _, pod := range t.Context().ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, node := range nodes {
			t.NewAction(s, fmt.Sprintf("ping-%d", i), &pod, node).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ping(node))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					Protocol: check.ICMP,
				}))
			})

			i++
		}
	}
}
