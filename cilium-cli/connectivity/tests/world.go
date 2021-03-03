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

type PodToWorld struct{}

func (t *PodToWorld) Name() string {
	return "pod-to-world"
}

func (t *PodToWorld) Run(ctx context.Context, c check.TestContext) {
	fqdn := "https://google.com"

	for _, client := range c.ClientPods() {
		run := check.NewTestRun(t.Name(), c, client, check.NetworkEndpointContext{Peer: fqdn})

		_, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, curlCommand(fqdn))
		if err != nil {
			run.Failure("curl connectivity check command failed: %s", err)
		}

		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, []filters.Pair{
			{Filter: filters.Drop(), Expect: false, Msg: "Drop"},
			{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.UDP(0, 53)), Expect: true, Msg: "DNS request"},
			{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.UDP(53, 0)), Expect: true, Msg: "DNS response"},
			{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.TCP(0, 443), filters.SYN()), Expect: true, Msg: "SYN"},
			{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.TCP(443, 0), filters.SYNACK()), Expect: true, Msg: "SYN-ACK"},
			// For the connection termination, we will either see:
			// a) FIN + FIN b) FIN + RST c) RST
			{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.TCP(0, 443), filters.Or(filters.FIN(), filters.RST())), Expect: true, Msg: "FIN or RST"},
		})

		run.End()
	}
}
