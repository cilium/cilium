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

	// With https
	if client := c.RandomClientPod(); client != nil {
		run := check.NewTestRun(t, c, client, check.NetworkEndpointContext{Peer: fqdn}, 443)
		cmd := curlCommand("https://" + fqdn)
		stdout, stderr, err := client.K8sClient.ExecInPodWithStderr(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
		run.LogResult(cmd, err, stdout, stderr)
		egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
		})
		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
		run.End()
	}

	// With http
	if client := c.RandomClientPod(); client != nil {
		run := check.NewTestRun(t, c, client, check.NetworkEndpointContext{Peer: fqdn}, 80)
		cmd := curlCommand("http://" + fqdn)
		stdout, stderr, err := client.K8sClient.ExecInPodWithStderr(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
		run.LogResult(cmd, err, stdout, stderr)
		egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
		})
		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
		run.End()
	}

	// With http to www.google.com
	fqdn2 := "www.google.com"
	if client := c.RandomClientPod(); client != nil {
		run := check.NewTestRun(t, c, client, check.NetworkEndpointContext{Peer: fqdn2}, 80)
		cmd := curlCommand("http://" + fqdn2)
		stdout, stderr, err := client.K8sClient.ExecInPodWithStderr(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
		run.LogResult(cmd, err, stdout, stderr)
		egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
			DNSRequired: true,
			RSTAllowed:  true,
		})
		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
		run.End()
	}
}
