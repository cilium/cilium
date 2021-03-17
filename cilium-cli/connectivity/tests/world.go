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

		cmd := curlCommand(fqdn)
		_, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, cmd)
		if err != nil {
			run.Failure("curl connectivity check command failed: %s", err)
		} else {
			run.Success("curl command %q succeeded", cmd)
		}

		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, filters.FlowSetRequirement{
			First: filters.FlowRequirement{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.UDP(0, 53)), Msg: "DNS request"},
			Middle: []filters.FlowRequirement{
				{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.UDP(53, 0)), Msg: "DNS response"},
				{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.TCP(0, 443), filters.SYN()), Msg: "SYN"},
				{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.TCP(443, 0), filters.SYNACK()), Msg: "SYN-ACK"},
			},
			// For the connection termination, we will either see:
			// a) FIN + FIN b) FIN + RST c) RST
			Last: filters.FlowRequirement{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.TCP(0, 443), filters.Or(filters.FIN(), filters.RST())), Msg: "FIN or RST"},
			Except: []filters.FlowRequirement{
				{Filter: filters.Drop(), Msg: "Drop"},
			},
		})

		run.End()
	}
}
