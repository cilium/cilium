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

type connectivityTestPodToWorld struct{}

func (p *connectivityTestPodToWorld) Name() string {
	return "pod-to-world"
}

func (p *connectivityTestPodToWorld) Run(ctx context.Context, c TestContext) {
	fqdn := "https://google.com"

	for _, client := range c.ClientPods() {
		run := NewTestRun(p.Name(), c, client, NetworkEndpointContext{Peer: fqdn})

		_, err := client.k8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, clientDeploymentName, curlCommand(fqdn))
		if err != nil {
			run.Failure("curl connectivity check command failed: %s", err)
		}

		run.ValidateFlows(ctx, client.Name(), []FilterPair{
			{Filter: DropFilter(), Expect: false, Msg: "Found drop"},
			{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "Found RST"},
			{Filter: UDPFilter(client.Pod.Status.PodIP, "", 0, 53), Expect: true, Msg: "DNS request not found"},
			{Filter: UDPFilter("", client.Pod.Status.PodIP, 53, 0), Expect: true, Msg: "DNS response not found"},
			{Filter: TCPFilter(client.Pod.Status.PodIP, "", 0, 443, true, false, false, false), Expect: true, Msg: "SYN not found"},
			{Filter: TCPFilter("", client.Pod.Status.PodIP, 443, 0, true, true, false, false), Expect: true, Msg: "SYN-ACK not found"},
			{Filter: TCPFilter(client.Pod.Status.PodIP, "", 0, 443, false, true, true, false), Expect: true, Msg: "FIN not found"},
			{Filter: TCPFilter("", client.Pod.Status.PodIP, 443, 0, false, true, true, false), Expect: true, Msg: "FIN-ACK not found"},
		})

		run.End()
	}
}
