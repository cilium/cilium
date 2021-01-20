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

package connectivity

import (
	"context"
)

type connectivityTestPodToHost struct{}

func (p *connectivityTestPodToHost) Name() string {
	return "pod-to-host"
}

func (p *connectivityTestPodToHost) Run(ctx context.Context, c TestContext) {
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
			run := NewTestRun(p.Name(), c, client, NetworkEndpointContext{Peer: hostIP})

			_, err := client.k8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, clientDeploymentName, cmd)
			if err != nil {
				run.Failure("ping command failed: %s", err)
			}

			run.ValidateFlows(ctx, client.Name(), []FilterPair{
				{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
				{Filter: ICMPFilter(client.Pod.Status.PodIP, hostIP, 8), Expect: true, Msg: "ICMP request"},
				{Filter: ICMPFilter(hostIP, client.Pod.Status.PodIP, 0), Expect: true, Msg: "ICMP response"},
			})

			run.End()
		}
	}
}
