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

type connectivityTestPodToPod struct{}

func (p *connectivityTestPodToPod) Name() string {
	return "pod-to-pod"
}

func (p *connectivityTestPodToPod) Run(ctx context.Context, c TestContext) {
	for _, client := range c.ClientPods() {
		for _, echo := range c.EchoPods() {
			run := NewTestRun(p.Name(), c, client, echo)

			_, err := client.k8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, clientDeploymentName, curlCommand(echo.Pod.Status.PodIP+":8080"))
			if err != nil {
				run.Failure("curl connectivity check command failed: %s", err)
			}

			run.ValidateFlows(ctx, client.Name(), []FilterPair{
				{Filter: DropFilter(), Expect: false, Msg: "Drop"},
				{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "RST"},
				{Filter: TCPFilter(echo.Pod.Status.PodIP, client.Pod.Status.PodIP, 8080, 0, true, true, false, false), Expect: true, Msg: "SYN-ACK"},
				{Filter: TCPFilter(echo.Pod.Status.PodIP, client.Pod.Status.PodIP, 8080, 0, false, true, true, false), Expect: true, Msg: "FIN-ACK"},
			})

			run.ValidateFlows(ctx, echo.Name(), []FilterPair{
				{Filter: DropFilter(), Expect: false, Msg: "Drop"},
				{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "RST"},
				{Filter: TCPFilter(client.Pod.Status.PodIP, echo.Pod.Status.PodIP, 0, 8080, true, false, false, false), Expect: true, Msg: "SYN"},
				{Filter: TCPFilter(client.Pod.Status.PodIP, echo.Pod.Status.PodIP, 0, 8080, false, true, true, false), Expect: true, Msg: "FIN"},
			})

			run.End()
		}
	}
}
