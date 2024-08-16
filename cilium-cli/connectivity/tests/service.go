// SPDX-License-Identifier: Apache-2.0
// Copyright 2020-2021 Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"github.com/cilium/cilium-cli/connectivity/check"
)

// PodToService sends an HTTP request from all client Pods
// to all Services in the test context.
func PodToService() check.Scenario {
	return &podToService{}
}

// podToService implements a Scenario.
type podToService struct{}

func (s *podToService) Name() string {
	return "pod-to-service"
}

func (s *podToService) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, svc := range t.Context().EchoServices() {
			t.NewAction(s, fmt.Sprintf("curl-%d", i), &pod, svc).Run(func(a *check.Action) {
				a.ExecInPod(ctx, curl(svc))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: true,
					AltDstPort:  svc.Port(),
				}))
			})

			i++
		}
	}
}

// PodToRemoteNodePort sends an HTTP request from all client Pods
// to all echo Services' NodePorts, but only to other nodes.
func PodToRemoteNodePort() check.Scenario {
	return &podToRemoteNodePort{}
}

// podToRemoteNodePort implements a Scenario.
type podToRemoteNodePort struct{}

func (s *podToRemoteNodePort) Name() string {
	return "pod-to-remote-nodeport"
}

func (s *podToRemoteNodePort) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, svc := range t.Context().EchoServices() {
			for _, node := range t.Context().CiliumPods() {
				node := node // copy to avoid memory aliasing when using reference

				// Use Cilium Pods as a substitute for nodes accepting workloads.
				if pod.Pod.Status.HostIP != node.Pod.Status.HostIP {
					// If src and dst pod are running on different nodes,
					// call the Cilium Pod's host IP on the service's NodePort.
					curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, &node)

					i++
				}
			}
		}
	}
}

// PodToLocalNodePort sends an HTTP request from all client Pods
// to all echo Services' NodePorts, but only on the same node as
// the client Pods.
func PodToLocalNodePort() check.Scenario {
	return &podToLocalNodePort{}
}

// podToLocalNodePort implements a Scenario.
type podToLocalNodePort struct{}

func (s *podToLocalNodePort) Name() string {
	return "pod-to-local-nodeport"
}

func (s *podToLocalNodePort) Run(ctx context.Context, t *check.Test) {
	var i int

	for _, pod := range t.Context().ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference

		for _, svc := range t.Context().EchoServices() {
			for _, node := range t.Context().CiliumPods() {
				node := node // copy to avoid memory aliasing when using reference

				// Use Cilium Pods as a substitute for nodes accepting workloads.
				if pod.Pod.Status.HostIP == node.Pod.Status.HostIP {
					// If src and dst pod are running on the same node,
					// call the Cilium Pod's host IP on the service's NodePort.
					curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, &node)

					i++
				}
			}
		}
	}
}

func curlNodePort(ctx context.Context, s check.Scenario, t *check.Test,
	name string, pod *check.Pod, svc check.Service, node *check.Pod) {

	// Get the NodePort allocated to the Service.
	np := uint32(svc.Service.Spec.Ports[0].NodePort)

	// Manually construct an HTTP endpoint to override the destination IP
	// and port of the request.
	ep := check.HTTPEndpoint(name, fmt.Sprintf("%s://%s:%d%s", svc.Scheme(), node.Pod.Status.HostIP, np, svc.Path()))

	// Create the Action with the original svc as this will influence what the
	// flow matcher looks for in the flow logs.
	t.NewAction(s, name, pod, svc).Run(func(a *check.Action) {
		a.ExecInPod(ctx, curl(ep))

		a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
			// The fact that curl is hitting the NodePort instead of the
			// backend Pod's port is specified here. This will cause the matcher
			// to accept both the NodePort and the ClusterIP (container) port.
			AltDstPort: np,
		}))
	})
}
