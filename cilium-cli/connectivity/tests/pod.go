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
	"net"
	"strconv"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/connectivity/filters"
)

type PodToPod struct{}

func (t *PodToPod) Name() string {
	return "pod-to-pod"
}

func (t *PodToPod) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		for _, echo := range c.EchoPods() {
			destination := net.JoinHostPort(echo.Pod.Status.PodIP, strconv.Itoa(8080))
			run := check.NewTestRun(t.Name(), c, client, echo)

			_, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, curlCommand(destination))
			if err != nil {
				run.Failure("curl connectivity check command failed: %s", err)
			}

			echoToClient := filters.IP(echo.Pod.Status.PodIP, client.Pod.Status.PodIP) // echo -> client response
			clientToEcho := filters.IP(client.Pod.Status.PodIP, echo.Pod.Status.PodIP) // client -> echo request
			tcpRequest := filters.TCP(0, 8080)                                         // request to port 8080
			tcpResponse := filters.TCP(8080, 0)                                        // response from port 8080

			run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, []filters.Pair{
				{Filter: filters.Drop(), Expect: false, Msg: "Drop"},
				{Filter: filters.RST(), Expect: false, Msg: "RST"},
				{Filter: filters.And(echoToClient, tcpResponse, filters.SYNACK()), Expect: true, Msg: "SYN-ACK"},
				{Filter: filters.And(echoToClient, tcpResponse, filters.FIN()), Expect: true, Msg: "FIN-ACK"},
			})

			run.ValidateFlows(ctx, echo.Name(), echo.Pod.Status.PodIP, []filters.Pair{
				{Filter: filters.Drop(), Expect: false, Msg: "Drop"},
				{Filter: filters.RST(), Expect: false, Msg: "RST"},
				{Filter: filters.And(clientToEcho, tcpRequest, filters.SYN()), Expect: true, Msg: "SYN"},
				{Filter: filters.And(clientToEcho, tcpRequest, filters.FIN()), Expect: true, Msg: "FIN"},
			})

			run.End()
		}
	}
}
