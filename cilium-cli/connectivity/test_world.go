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

	"github.com/cilium/cilium-cli/connectivity/filters"
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

		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, []FilterPair{
			{Filter: filters.Drop(), Expect: false, Msg: "Drop"},
			{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.UDP(0, 53)), Expect: true, Msg: "DNS request"},
			{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.UDP(53, 0)), Expect: true, Msg: "DNS response"},
			{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.TCP(0, 443), filters.SYN()), Expect: true, Msg: "SYN"},
			{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.TCP(443, 0), filters.SYNACK()), Expect: true, Msg: "SYN-ACK"},
			{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.TCP(0, 443), filters.Or(filters.FIN(), filters.RST())), Expect: true, Msg: "FIN or RST"},
			{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.TCP(443, 0), filters.Or(filters.FIN(), filters.RST())), Expect: true, Msg: "FIN or RST"},
		})

		run.End()
	}
}
