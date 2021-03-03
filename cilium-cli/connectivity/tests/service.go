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
	"github.com/cilium/cilium-cli/connectivity/filters"
)

type PodToService struct{}

func (t *PodToService) Name() string {
	return "pod-to-service"
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

		testConnetivityToServiceDefinition(ctx, c, t.Name(), client, serviceDestinations)
	}

}

type PodToNodePort struct{}

func (t *PodToNodePort) Name() string {
	return "pod-to-nodeport"
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

		testConnetivityToServiceDefinition(ctx, c, t.Name(), client, serviceDestinations)
	}
}

type PodToLocalNodePort struct{}

func (t *PodToLocalNodePort) Name() string {
	return "pod-to-local-nodeport"
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

		testConnetivityToServiceDefinition(ctx, c, t.Name(), client, serviceDestinations)
	}
}

type serviceDefinition struct {
	port int
	name string
	dns  bool
}

type serviceDefinitionMap map[string]serviceDefinition

func testConnetivityToServiceDefinition(ctx context.Context, c check.TestContext, name string, client check.PodContext, def serviceDefinitionMap) {
	for peer, definition := range def {
		destination := net.JoinHostPort(peer, strconv.Itoa(definition.port))
		run := check.NewTestRun(name, c, client, check.NetworkEndpointContext{
			CustomName: destination + " (" + definition.name + ")",
			Peer:       destination,
		})

		_, err := client.K8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, check.ClientDeploymentName, curlCommand(destination))
		if err != nil {
			run.Failure("curl connectivity check command failed: %s", err)
		}

		clientToEcho := filters.IP(client.Pod.Status.PodIP, "")
		echoToClient := filters.IP("", client.Pod.Status.PodIP)

		// Depending on whether NodePort is enabled or
		// not, the port will be differnt. Ideally we
		// look at Cilium to define this but this
		// information is not yet available.
		tcpRequest := filters.Or(filters.TCP(0, definition.port), filters.TCP(0, 8080))  // request to 8080 or NodePort
		tcpResponse := filters.Or(filters.TCP(definition.port, 0), filters.TCP(8080, 0)) // response from port 8080 or NodePort

		flowRequirements := []filters.Pair{
			{Filter: filters.Drop(), Expect: false, Msg: "Drop"},
			{Filter: filters.RST(), Expect: false, Msg: "RST"},
			{Filter: filters.And(clientToEcho, tcpRequest, filters.SYN()), Expect: true, Msg: "SYN"},
			{Filter: filters.And(echoToClient, tcpResponse, filters.SYNACK()), Expect: true, Msg: "SYN-ACK"},
			{Filter: filters.And(clientToEcho, tcpRequest, filters.FIN()), Expect: true, Msg: "FIN"},
			{Filter: filters.And(echoToClient, tcpResponse, filters.FIN()), Expect: true, Msg: "FIN-ACK"},
		}

		if definition.dns {
			flowRequirements = append(flowRequirements, []filters.Pair{
				{Filter: filters.And(filters.IP(client.Pod.Status.PodIP, ""), filters.UDP(0, 53)), Expect: true, Msg: "DNS request"},
				{Filter: filters.And(filters.IP("", client.Pod.Status.PodIP), filters.UDP(53, 0)), Expect: true, Msg: "DNS response"},
			}...)
		}

		run.ValidateFlows(ctx, client.Name(), client.Pod.Status.PodIP, flowRequirements)

		run.End()
	}
}
