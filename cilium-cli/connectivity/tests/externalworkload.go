// Copyright 2021 Authors of Cilium
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

type PodToExternalWorkload struct {
	check.PolicyContext
	Variant string
}

func (t *PodToExternalWorkload) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToExternalWorkload) Name() string {
	return "pod-to-external-workload" + t.Variant
}

func (t *PodToExternalWorkload) Run(ctx context.Context, c check.TestContext) {
	for _, src := range c.ClientPods() {
		for _, dst := range c.ExternalWorkloads() {
			run := check.NewTestRun(t, c, src, dst, 0) // 0 port number for ICMP
			cmd := []string{"ping", "-w", "3", "-c", "1", dst.ExternalWorkload.Status.IP}

			stdout, stderr, err := src.K8sClient.ExecInPodWithStderr(ctx, src.Pod.Namespace, src.Pod.Name, "", cmd)
			run.LogResult(cmd, err, stdout, stderr)
			egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
				Protocol: check.ICMP,
			})
			run.ValidateFlows(ctx, src.Name(), src.Pod.Status.PodIP, egressFlowRequirements)
			ingressFlowRequirements := run.GetIngressRequirements(check.FlowParameters{
				Protocol: check.ICMP,
			})
			if ingressFlowRequirements != nil {
				run.ValidateFlows(ctx, dst.Name(), dst.ExternalWorkload.Status.IP, ingressFlowRequirements)
			}
			run.End()
		}
	}
}
