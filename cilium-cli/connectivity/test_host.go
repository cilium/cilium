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
	for _, client := range c.ClientPods() {
		hostIP := client.Pod.Status.HostIP
		cmd := []string{"ping", "-c", "3", hostIP}
		run := NewTestRun(p.Name(), c, client, NetworkEndpointContext{Peer: hostIP})

		_, err := client.k8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, clientDeploymentName, cmd)
		if err != nil {
			run.Failure("ping command failed: %s", err)
		}

		run.ValidateFlows(ctx, client.Name(), []FilterPair{
			{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
			{Filter: ICMPFilter(client.Pod.Status.PodIP, hostIP, 8), Expect: true, Msg: "ICMP request not found"},
			{Filter: ICMPFilter(hostIP, client.Pod.Status.PodIP, 0), Expect: true, Msg: "ICMP response not found"},
		})

		run.End()
	}
}
