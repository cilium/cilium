// Copyright 2020-2021 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tests

import (
	"context"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/filters"
)

type PodToHost struct{}

func (t *PodToHost) Name() string {
	return "pod-to-host"
}

func (t *PodToHost) Run(ctx context.Context, c check.TestContext) {
	// Construct a map of all unique host IPs where pods are running on.
	// This will include:
	// - The local host
	// - Remote hosts unless running in single node environments
	// - Remote hosts in remote clusters when running in multi-cluster mode
	hostIPs := map[string]struct{}{}
	for _, client := range c.ClientPods() {
		hostIPs[client.Pod.Status.HostIP] = struct{}{}
	}
	for _, echo := range c.EchoPods() {
		hostIPs[echo.Pod.Status.HostIP] = struct{}{}
	}

	for _, client := range c.ClientPods() {
		for hostIP := range hostIPs {
			cmd := []string{"ping", "-c", "3", hostIP}
			run := check.NewTestRun(t.Name(), c, client, check.NetworkEndpointContext{Peer: hostIP})

			_, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, cmd)
			if err != nil {
				run.Failure("ping command failed: %s", err)
			} else {
				run.Success("ping command %q succeeded", cmd)
			}

			run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, filters.FlowSetRequirement{
				First: filters.FlowRequirement{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, hostIP), filters.Or(filters.ICMP(8), filters.ICMPv6(128))), Msg: "ICMP request"},
				Last:  filters.FlowRequirement{Filter: filters.And(filters.IP(hostIP, client.Pod.Status.PodIP), filters.Or(filters.ICMP(0), filters.ICMPv6(129))), Msg: "ICMP response", SkipOnAggregation: true},
				Except: []filters.FlowRequirement{
					{Filter: filters.Drop(), Msg: "Drop"},
				},
			})

			run.End()
		}
	}
}
