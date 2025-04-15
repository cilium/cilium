// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

// extractClientIPFromResponse extracts the client IP from the response of the echo-external service
func extractClientIPFromResponse(res string) net.IP {
	var clientIP struct {
		ClientIP string `json:"client-ip"`
	}

	json.Unmarshal([]byte(res), &clientIP)

	return net.ParseIP(clientIP.ClientIP).To4()
}

// EgressGateway is a test case which, given the cegp-sample-client CiliumEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// and the cegp-sample-echo CiliumEgressGatewayPolicy targeting:
// - the echo service pods (kind=echo) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// tests connectivity for:
// - pod to host traffic
// - pod to service traffic
// - pod to external IP traffic
// - reply traffic for services
// - reply traffic for pods
func EgressGateway() check.Scenario {
	return &egressGateway{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGateway struct {
	check.ScenarioBase
}

func (s *egressGateway) Name() string {
	return "egress-gateway"
}

func (s *egressGateway) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := ct.GetGatewayNodeInternalIP(egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	err := check.WaitForEgressGatewayBpfPolicyEntries(ctx, ct.CiliumPods(), func(ciliumPod check.Pod) ([]check.BPFEgressGatewayPolicyEntry, error) {
		var targetEntries []check.BPFEgressGatewayPolicyEntry

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				check.BPFEgressGatewayPolicyEntry{
					SourceIP:  client.Pod.Status.PodIP,
					DestCIDR:  "0.0.0.0/0",
					EgressIP:  egressIP,
					GatewayIP: egressGatewayNodeInternalIP.String(),
				})
		}

		for _, echo := range ct.EchoPods() {
			targetEntries = append(targetEntries,
				check.BPFEgressGatewayPolicyEntry{
					SourceIP:  echo.Pod.Status.PodIP,
					DestCIDR:  "0.0.0.0/0",
					EgressIP:  egressIP,
					GatewayIP: egressGatewayNodeInternalIP.String(),
				})
		}

		return targetEntries, nil
	}, func(ciliumPod check.Pod) ([]check.BPFEgressGatewayPolicyEntry, error) {
		return ct.GetConnDisruptEgressPolicyEntries(ctx, ciliumPod)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Ping hosts (pod to host connectivity). Should not get masqueraded with egress IP
	i := 0
	for _, client := range ct.ClientPods() {
		for _, dst := range ct.HostNetNSPodsByNode() {
			t.NewAction(s, fmt.Sprintf("ping-%d", i), &client, &dst, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.PingCommand(dst, features.IPFamilyV4))
			})
			i++
		}
	}

	// DNS query (pod to service connectivity). Should not get masqueraded with egress IP
	i = 0
	for _, client := range ct.ClientPods() {
		kubeDNSService, err := ct.K8sClient().GetService(ctx, "kube-system", "kube-dns", metav1.GetOptions{})
		if err != nil {
			t.Fatal("Cannot get kube-dns service")
		}
		kubeDNSServicePeer := check.Service{Service: kubeDNSService}

		t.NewAction(s, fmt.Sprintf("dig-%d", i), &client, kubeDNSServicePeer, features.IPFamilyV4).Run(func(a *check.Action) {
			a.ExecInPod(ctx, ct.DigCommand(kubeDNSServicePeer, features.IPFamilyV4))
		})
		i++
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service using DNS)
	i = 0
	for _, client := range ct.ClientPods() {
		for _, externalEchoSvc := range ct.EchoExternalServices() {
			externalEcho := externalEchoSvc.ToEchoIPService()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
				clientIP := extractClientIPFromResponse(a.CmdOutput())

				if !clientIP.Equal(egressGatewayNodeInternalIP) {
					a.Fatal("Request reached external echo service with wrong source IP")
				}
			})
			i++
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i = 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
				clientIP := extractClientIPFromResponse(a.CmdOutput())

				if !clientIP.Equal(egressGatewayNodeInternalIP) {
					a.Fatal("Request reached external echo service with wrong source IP")
				}
			})
			i++
		}
	}

	// When connecting from outside the cluster to a nodeport service whose pods are selected by an egress policy,
	// the reply traffic should not be SNATed with the egress IP
	i = 0
	for _, client := range ct.ExternalEchoPods() {
		for _, node := range ct.Nodes() {
			for _, echo := range ct.EchoServices() {
				// convert the service to a ServiceExternalIP as we want to access it through its external IP
				echo := echo.ToNodeportService(node)

				t.NewAction(s, fmt.Sprintf("curl-echo-service-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(echo))
				})
				i++
			}
		}
	}

	if status, ok := ct.Feature(features.Tunnel); ok && !status.Enabled {
		// When connecting from outside the cluster directly to a pod which is selected by an egress policy, the
		// reply traffic should not be SNATed with the egress IP (only connections originating from these pods
		// should go through egress gateway).
		//
		// This test is executed only when Cilium is running in direct routing mode, since we can simply add a
		// route on the node that doesn't run Cilium to direct pod's traffic to the node where the pod is
		// running (while in tunneling mode we would need the external node to send the traffic over the tunnel)
		i = 0
		for _, client := range ct.ExternalEchoPods() {
			for _, echo := range ct.EchoPods() {
				t.NewAction(s, fmt.Sprintf("curl-echo-pod-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommand(echo))
				})
				i++
			}
		}
	}
}

// EgressGatewayExcludedCIDRs is a test case which, given the cegp-sample CiliumEgressGatewayPolicy targeting:
// targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - the IP of the external node as excluded CIDR
// - kind-worker2 as gateway node
//
// This suite tests the excludedCIDRs property and ensure traffic matching an excluded CIDR does not get masqueraded with the egress IP
func EgressGatewayExcludedCIDRs() check.Scenario {
	return &egressGatewayExcludedCIDRs{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type egressGatewayExcludedCIDRs struct {
	check.ScenarioBase
}

func (s *egressGatewayExcludedCIDRs) Name() string {
	return "egress-gateway-excluded-cidrs"
}

func (s *egressGatewayExcludedCIDRs) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := ct.GetGatewayNodeInternalIP(egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	err := check.WaitForEgressGatewayBpfPolicyEntries(ctx, ct.CiliumPods(), func(ciliumPod check.Pod) ([]check.BPFEgressGatewayPolicyEntry, error) {
		var targetEntries []check.BPFEgressGatewayPolicyEntry

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			for _, nodeWithoutCiliumName := range t.NodesWithoutCilium() {
				nodeWithoutCilium, err := ciliumPod.K8sClient.GetNode(context.Background(), nodeWithoutCiliumName, metav1.GetOptions{})
				if err != nil {
					if k8sErrors.IsNotFound(err) {
						continue
					}

					t.Fatalf("Cannot retrieve external node")
				}

				targetEntries = append(targetEntries,
					check.BPFEgressGatewayPolicyEntry{
						SourceIP:  client.Pod.Status.PodIP,
						DestCIDR:  "0.0.0.0/0",
						EgressIP:  egressIP,
						GatewayIP: egressGatewayNodeInternalIP.String(),
					})

				targetEntries = append(targetEntries,
					check.BPFEgressGatewayPolicyEntry{
						SourceIP:  client.Pod.Status.PodIP,
						DestCIDR:  fmt.Sprintf("%s/32", nodeWithoutCilium.Status.Addresses[0].Address),
						EgressIP:  egressIP,
						GatewayIP: "Excluded CIDR",
					})
			}
		}

		return targetEntries, nil
	}, func(ciliumPod check.Pod) ([]check.BPFEgressGatewayPolicyEntry, error) {
		return ct.GetConnDisruptEgressPolicyEntries(ctx, ciliumPod)
	})
	if err != nil {
		t.Fatal(err)
	}

	// Traffic matching an egress gateway policy and an excluded CIDR should leave the cluster masqueraded with the
	// node IP where the pod is running rather than with the egress IP(pod to external service)
	i := 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
				clientIP := extractClientIPFromResponse(a.CmdOutput())

				if !clientIP.Equal(net.ParseIP(client.Pod.Status.HostIP)) {
					a.Fatal("Request reached external echo service with wrong source IP")
				}
			})
			i++
		}
	}
}
