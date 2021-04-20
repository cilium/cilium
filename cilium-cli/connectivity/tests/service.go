// Copyright 2020 Authors of Cilium
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

type PodToService struct {
	check.PolicyContext
	Variant string
}

func (t *PodToService) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToService) Name() string {
	return "pod-to-service" + t.Variant
}

func (t *PodToService) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		serviceDestinations := serviceDefinitionMap{}
		for _, echoSvc := range c.EchoServices() {
			serviceDestinations[echoSvc.Service.Name] = serviceDefinition{
				port: 8080,
				name: "ClusterIP",
				dns:  true,
			}
		}

		testConnectivityToServiceDefinition(ctx, c, t, client, serviceDestinations)
	}

}

type PodToNodePort struct {
	check.PolicyContext
	Variant string
}

func (t *PodToNodePort) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToNodePort) Name() string {
	return "pod-to-nodeport" + t.Variant
}

func (t *PodToNodePort) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		serviceDestinations := serviceDefinitionMap{}
		for _, echoSvc := range c.EchoServices() {
			for _, echo := range c.EchoPods() {
				if echo.Pod.Status.HostIP != client.Pod.Status.HostIP {
					serviceDestinations[echo.Pod.Status.HostIP] = serviceDefinition{
						port: int(echoSvc.Service.Spec.Ports[0].NodePort),
						name: "NodePort",
					}
				}
			}
		}

		testConnectivityToServiceDefinition(ctx, c, t, client, serviceDestinations)
	}
}

type PodToLocalNodePort struct {
	check.PolicyContext
	Variant string
}

func (t *PodToLocalNodePort) WithPolicy(yaml string) check.ConnectivityTest {
	return t.WithPolicyRunner(t, yaml)
}

func (t *PodToLocalNodePort) Name() string {
	return "pod-to-local-nodeport" + t.Variant
}

func (t *PodToLocalNodePort) Run(ctx context.Context, c check.TestContext) {
	for _, client := range c.ClientPods() {
		serviceDestinations := serviceDefinitionMap{}
		for _, client := range c.ClientPods() {
			for _, echoSvc := range c.EchoServices() {
				for _, echo := range c.EchoPods() {
					if echo.Pod.Status.HostIP == client.Pod.Status.HostIP {
						serviceDestinations[echo.Pod.Status.HostIP] = serviceDefinition{
							port: int(echoSvc.Service.Spec.Ports[0].NodePort),
							name: "NodePort",
						}
					}
				}
			}
		}

		testConnectivityToServiceDefinition(ctx, c, t, client, serviceDestinations)
	}
}

type serviceDefinition struct {
	port int
	name string
	dns  bool
}

type serviceDefinitionMap map[string]serviceDefinition

func testConnectivityToServiceDefinition(ctx context.Context, c check.TestContext, t check.ConnectivityTest, client check.PodContext, def serviceDefinitionMap) {
	for peer, definition := range def {
		destination := net.JoinHostPort(peer, strconv.Itoa(definition.port))
		run := check.NewTestRun(t, c, client, check.NetworkEndpointContext{
			CustomName: destination + " (" + definition.name + ")",
			Peer:       destination,
		}, 8080)
		cmd := curlCommand(destination)
		stdout, stderr, err := client.K8sClient.ExecInPodWithStderr(ctx, client.Pod.Namespace, client.Pod.Name, client.Pod.Labels["name"], cmd)
		run.LogResult(cmd, err, stdout, stderr)
		egressFlowRequirements := run.GetEgressRequirements(check.FlowParameters{
			DNSRequired: definition.dns,
			NodePort:    definition.port,
		})
		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, egressFlowRequirements)
		run.End()
	}
}
