// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"fmt"

	"golang.org/x/exp/slices"
	corev1 "k8s.io/api/core/v1"

	"github.com/cilium/cilium/pkg/versioncheck"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/utils/features"
)

// PodToService sends an HTTP request from all client Pods
// to all Services in the test context.
func PodToService(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToService{
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToService implements a Scenario.
type podToService struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToService) Name() string {
	return "pod-to-service"
}

func (s *podToService) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}
		for _, svc := range ct.EchoServices() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(svc, features.IPFamilyAny))

				a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
					DNSRequired: true,
					AltDstPort:  svc.Port(),
				}))

				a.ValidateMetrics(ctx, pod, a.GetEgressMetricsRequirements())
			})

			i++
		}
	}
}

// PodToIngress sends an HTTP request from all client Pods
// to all Ingress service in the test context.
func PodToIngress(opts ...Option) check.Scenario {
	options := &labelsOption{}
	for _, opt := range opts {
		opt(options)
	}
	return &podToIngress{
		sourceLabels:      options.sourceLabels,
		destinationLabels: options.destinationLabels,
	}
}

// podToIngress implements a Scenario.
type podToIngress struct {
	sourceLabels      map[string]string
	destinationLabels map[string]string
}

func (s *podToIngress) Name() string {
	return "pod-to-ingress-service"
}

func (s *podToIngress) Run(ctx context.Context, t *check.Test) {
	var i int
	ct := t.Context()

	for _, pod := range ct.ClientPods() {
		pod := pod // copy to avoid memory aliasing when using reference
		if !hasAllLabels(pod, s.sourceLabels) {
			continue
		}
		for _, svc := range ct.IngressService() {
			if !hasAllLabels(svc, s.destinationLabels) {
				continue
			}

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommand(svc, features.IPFamilyAny))

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
			for _, node := range t.Context().Nodes() {
				node := node // copy to avoid memory aliasing when using reference
				remote := true
				for _, addr := range node.Status.Addresses {
					if pod.Pod.Status.HostIP == addr.Address {
						remote = false
						break
					}
				}
				if !remote {
					continue
				}

				// If src and dst pod are running on different nodes,
				// call the Cilium Pod's host IP on the service's NodePort.
				curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, node, true, false)

				i++
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
			for _, node := range t.Context().Nodes() {
				node := node // copy to avoid memory aliasing when using reference

				for _, addr := range node.Status.Addresses {
					if pod.Pod.Status.HostIP == addr.Address {
						// If src and dst pod are running on the same node,
						// call the Cilium Pod's host IP on the service's NodePort.
						curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &pod, svc, node, true, false)

						i++
					}
				}
			}
		}
	}
}

func curlNodePort(ctx context.Context, s check.Scenario, t *check.Test,
	name string, pod *check.Pod, svc check.Service, node *corev1.Node,
	validateFlows bool, secondaryNetwork bool) {

	// Get the NodePort allocated to the Service.
	np := uint32(svc.Service.Spec.Ports[0].NodePort)

	addrs := slices.Clone(node.Status.Addresses)

	if secondaryNetwork {
		if t.Context().Features[check.FeatureIPv4].Enabled {
			addrs = append(addrs, corev1.NodeAddress{
				Type:    "SecondaryNetworkIPv4",
				Address: t.Context().SecondaryNetworkNodeIPv4()[node.Name],
			})
		}
		if t.Context().Features[check.FeatureIPv6].Enabled {
			addrs = append(addrs, corev1.NodeAddress{
				Type:    "SecondaryNetworkIPv6",
				Address: t.Context().SecondaryNetworkNodeIPv6()[node.Name],
			})
		}
	}

	t.ForEachIPFamily(func(ipFam features.IPFamily) {

		for _, addr := range addrs {
			if features.GetIPFamily(addr.Address) != ipFam {
				continue
			}

			// On GKE ExternalIP is not reachable from inside a cluster
			if addr.Type == corev1.NodeExternalIP {
				if f, ok := t.Context().Feature(check.FeatureFlavor); ok && f.Enabled && f.Mode == "gke" {
					continue
				}
			}

			//  Skip IPv6 requests when running on <1.14.0 Cilium with CNPs
			if features.GetIPFamily(addr.Address) == features.IPFamilyV6 &&
				versioncheck.MustCompile("<1.14.0")(t.Context().CiliumVersion) &&
				(len(t.CiliumNetworkPolicies()) > 0 || len(t.KubernetesNetworkPolicies()) > 0) {
				continue
			}

			// Manually construct an HTTP endpoint to override the destination IP
			// and port of the request.
			ep := check.HTTPEndpoint(name, fmt.Sprintf("%s://%s:%d%s", svc.Scheme(), addr.Address, np, svc.Path()))

			// Create the Action with the original svc as this will influence what the
			// flow matcher looks for in the flow logs.
			t.NewAction(s, name, pod, svc, features.IPFamilyAny).Run(func(a *check.Action) {
				a.ExecInPod(ctx, t.Context().CurlCommand(ep, features.IPFamilyAny))

				if validateFlows {
					a.ValidateFlows(ctx, pod, a.GetEgressRequirements(check.FlowParameters{
						// The fact that curl is hitting the NodePort instead of the
						// backend Pod's port is specified here. This will cause the matcher
						// to accept both the NodePort and the ClusterIP (container) port.
						AltDstPort: np,
					}))
				}
			})
		}
	})
}

// OutsideToNodePort sends an HTTP request from client pod running on a node w/o
// Cilium to NodePort services.
func OutsideToNodePort() check.Scenario {
	return &outsideToNodePort{}
}

type outsideToNodePort struct{}

func (s *outsideToNodePort) Name() string {
	return "outside-to-nodeport"
}

func (s *outsideToNodePort) Run(ctx context.Context, t *check.Test) {
	clientPod := t.Context().HostNetNSPodsByNode()[t.NodesWithoutCilium()[0]]
	i := 0

	// With kube-proxy doing N/S LB it is not possible to see the original client
	// IP, as iptables rules do the LB SNAT/DNAT before the packet hits any
	// of Cilium's datapath BPF progs. So, skip the flow validation in that case.
	_, validateFlows := t.Context().Feature(check.FeatureKPRNodePort)

	for _, svc := range t.Context().EchoServices() {
		for _, node := range t.Context().Nodes() {
			node := node // copy to avoid memory aliasing when using reference

			curlNodePort(ctx, s, t, fmt.Sprintf("curl-%d", i), &clientPod, svc, node, validateFlows, t.Context().Params().SecondaryNetworkIface != "")
			i++
		}
	}
}
