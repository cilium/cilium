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

package connectivity

import (
	"context"
	"net"
	"strconv"
)

type connectivityTestPodToService struct{}

func (p *connectivityTestPodToService) Name() string {
	return "pod-to-service"
}

type serviceDefinition struct {
	port int
	name string
	dns  bool
}

func (p *connectivityTestPodToService) Run(ctx context.Context, c TestContext) {
	for _, client := range c.ClientPods() {
		for _, echoSvc := range c.EchoServices() {
			serviceDestinations := map[string]serviceDefinition{
				echoSvc.Service.Name: serviceDefinition{
					port: 8080,
					name: "ClusterIP",
					dns:  true,
				},
			}

			for _, echo := range c.EchoPods() {
				serviceDestinations[echo.Pod.Status.HostIP] = serviceDefinition{
					port: int(echoSvc.Service.Spec.Ports[0].NodePort),
					name: "NodePort",
				}
			}

			for peer, definition := range serviceDestinations {
				destination := net.JoinHostPort(peer, strconv.Itoa(definition.port))
				run := NewTestRun(p.Name(), c, client, NetworkEndpointContext{
					CustomName: destination + " (" + definition.name + ")",
					Peer:       destination,
				})

				_, err := client.k8sClient.ExecInPod(ctx, client.Pod.Namespace, client.Pod.Name, clientDeploymentName, curlCommand(destination))
				if err != nil {
					run.Failure("curl connectivity check command failed: %s", err)
				}

				flowRequirements := []FilterPair{
					{Filter: DropFilter(), Expect: false, Msg: "Drop"},
					{Filter: TCPFilter("", "", 0, 0, false, true, false, true), Expect: false, Msg: "RST"},
					{Filter: TCPFilter(client.Pod.Status.PodIP, "", 0, 8080, true, false, false, false), Expect: true, Msg: "SYN"},
					{Filter: TCPFilter("", client.Pod.Status.PodIP, 8080, 0, true, true, false, false), Expect: true, Msg: "SYN-ACK"},
					{Filter: TCPFilter(client.Pod.Status.PodIP, "", 0, 8080, false, true, true, false), Expect: true, Msg: "FIN"},
					{Filter: TCPFilter("", client.Pod.Status.PodIP, 8080, 0, false, true, true, false), Expect: true, Msg: "FIN-ACK"},
				}

				if definition.dns {
					flowRequirements = append(flowRequirements, []FilterPair{
						{Filter: UDPFilter(client.Pod.Status.PodIP, "", 0, 53), Expect: true, Msg: "DNS request"},
						{Filter: UDPFilter("", client.Pod.Status.PodIP, 53, 0), Expect: true, Msg: "DNS response"},
					}...)
				}

				run.ValidateFlows(ctx, client.Name(), flowRequirements)

				run.End()
			}
		}
	}
}
