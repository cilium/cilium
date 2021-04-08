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
)

type PodToPod struct {
	check.PolicyContext
	Variant string
}

func (t *PodToPod) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToPod) Name() string {
	return "pod-to-pod" + t.Variant
}

func (t *PodToPod) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		for _, echo := range c.EchoPods() {
			run := check.NewTestRun(t, c, client, echo)
			cmd := curlCommand(net.JoinHostPort(echo.Pod.Status.PodIP, strconv.Itoa(8080)))
			stdout, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, cmd)
			run.LogResult(cmd, err, stdout)
			egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
				DstPort: 8080,
			})
			run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
			ingressFlowRequirements := run.GetIngressRequirements(check.FlowParameters{
				DstPort: 8080,
			})
			if ingressFlowRequirements != nil {
				run.ValidateFlows(ctx, echo.Name(), echo.Pod.Status.PodIP, ingressFlowRequirements)
			}
			run.End()
		}
	}
}
