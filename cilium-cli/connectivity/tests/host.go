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

type PodToHost struct {
	check.PolicyContext
	Variant string
}

func (t *PodToHost) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToHost) Name() string {
	return "pod-to-host" + t.Variant
}

func (t *PodToHost) Run(ctx context.Context, c check.TestContext) {
	// Construct a map of all unique host IPs where pods are running on.
	// This will include:
	// - The local host
	// - Remote hosts unless running in single node environments
	// - Remote hosts in remote clusters when running in multi-cluster mode
	hostIPs := map[string]struct{}{}
	for _, client := range c.ClientPods() {
		hostIPs[client.Pod.Status.HostIP] = struct{}{}
	}
	for _, echo := range c.EchoPods() {
		hostIPs[echo.Pod.Status.HostIP] = struct{}{}
	}

	for _, client := range c.ClientPods() {
		for hostIP := range hostIPs {
			cmd := []string{"ping", "-w", "3", "-c", "1", hostIP}
			run := check.NewTestRun(t, c, client, check.NetworkEndpointContext{Peer: hostIP}, 0) // 0 port number for ICMP
			stdout, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
			run.LogResult(cmd, err, stdout)
			egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
				Protocol: check.ICMP,
			})
			run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
			run.End()
		}
	}
}
