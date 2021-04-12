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
)

type ClientToClient struct {
	check.PolicyContext
	Variant string
}

func (t *ClientToClient) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *ClientToClient) Name() string {
	return "client-to-client" + t.Variant
}

func (t *ClientToClient) Run(ctx context.Context, c check.TestContext) {
	for _, src := range c.ClientPods() {
		for _, dst := range c.ClientPods() {
			if src.Pod.Status.PodIP == dst.Pod.Status.PodIP {
				// Currently we only get flows once per IP
				continue
			}
			run := check.NewTestRun(t, c, src, dst)
			cmd := []string{"ping", "-c", "3", dst.Pod.Status.PodIP}
			stdout, err := src.K8sClient.ExecInPod(ctx, src.Pod.Namespace, src.Pod.Name, "", cmd)
			run.LogResult(cmd, err, stdout)
			egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
				Protocol: check.ICMP,
			})
			run.ValidateFlows(ctx, src.Name(), src.Pod.Status.PodIP, egressFlowRequirements)
			ingressFlowRequirements := run.GetIngressRequirements(check.FlowParameters{
				Protocol: check.ICMP,
			})
			if ingressFlowRequirements != nil {
				run.ValidateFlows(ctx, dst.Name(), dst.Pod.Status.PodIP, ingressFlowRequirements)
			}
			run.End()
		}
	}
}
