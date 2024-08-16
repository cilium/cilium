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

type PodToWorld struct {
	check.PolicyContext
	Variant string
}

func (t *PodToWorld) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToWorld) Name() string {
	return "pod-to-world" + t.Variant
}

func (t *PodToWorld) Run(ctx context.Context, c check.TestContext) {
	fqdn := "google.com"

	for _, client := range c.ClientPods() {
		run := check.NewTestRun(t, c, client, check.NetworkEndpointContext{Peer: fqdn})
		cmd := curlCommand("https://" + fqdn)
		stdout, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
		run.LogResult(cmd, err, stdout)
		egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
			DstPort:     443,
		})
		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
		run.End()
	}
}
