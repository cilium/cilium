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
	"github.com/cilium/cilium/pkg/versioncheck"
)

// extractClientIPFromResponse extracts the client IP from the response of the echo-external service
func extractClientIPFromResponse(res string) net.IP {
	var clientIP struct {
		ClientIP string `json:"client-ip"`
	}

	json.Unmarshal([]byte(res), &clientIP)

	return net.ParseIP(clientIP.ClientIP)
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

	var ipv6Enabled bool
	if status, ok := ct.Feature(features.IPv6); ok && status.Enabled && versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion) {
		ipv6Enabled = true
	}

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := ct.GetGatewayNodeInternalIP(egressGatewayNode, false)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get IPv4 egress gateway node internal IP")
	}

	egressGatewayNodeInternalIPv6 := ct.GetGatewayNodeInternalIP(egressGatewayNode, true)
	if ipv6Enabled && egressGatewayNodeInternalIPv6 == nil {
		t.Fatal("Cannot get IPv6 egress gateway node internal IP")
	}

	err := check.WaitForEgressGatewayBpfPolicyEntries(ctx, ct.CiliumPods(), func(ciliumPod check.Pod) ([]check.BPFEgressGatewayPolicyEntry, error) {
		var targetEntries []check.BPFEgressGatewayPolicyEntry

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		egressIPv6 := "::"
		if ipv6Enabled && ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIPv6 = egressGatewayNodeInternalIPv6.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				check.BPFEgressGatewayPolicyEntry{
					SourceIP:  client.Pod.Status.PodIP,
					DestCIDR:  "0.0.0.0/0",
					EgressIP:  egressIP,
					GatewayIP: egressGatewayNodeInternalIP.String(),
				})

			if ipv6Enabled && client.Pod.Status.PodIPs != nil {
				for _, podIP := range client.Pod.Status.PodIPs {
					if net.ParseIP(podIP.IP).To4() == nil {
						targetEntries = append(targetEntries,
							check.BPFEgressGatewayPolicyEntry{
								SourceIP:  podIP.IP,
								DestCIDR:  "::/0",
								EgressIP:  egressIPv6,
								GatewayIP: egressGatewayNodeInternalIP.String(),
							})
						break
					}
				}
			}
		}

		for _, echo := range ct.EchoPods() {
			targetEntries = append(targetEntries,
				check.BPFEgressGatewayPolicyEntry{
					SourceIP:  echo.Pod.Status.PodIP,
					DestCIDR:  "0.0.0.0/0",
					EgressIP:  egressIP,
					GatewayIP: egressGatewayNodeInternalIP.String(),
				})

			if ipv6Enabled && echo.Pod.Status.PodIPs != nil {
				for _, podIP := range echo.Pod.Status.PodIPs {
					if net.ParseIP(podIP.IP).To4() == nil {
						targetEntries = append(targetEntries,
							check.BPFEgressGatewayPolicyEntry{
								SourceIP:  podIP.IP,
								DestCIDR:  "::/0",
								EgressIP:  egressIPv6,
								GatewayIP: egressGatewayNodeInternalIP.String(),
							})
						break
					}
				}
			}
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
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				t.NewAction(s, fmt.Sprintf("ping-%s-%d", ipFam, i), &client, &dst, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.PingCommand(dst, ipFam))
				})
			})
			i++
		}
	}

	// DNS query (pod to service connectivity). Should not get masqueraded with egress IP
	// This test case fails for ipv6, might need to make changes for this to work with kube-dns or target a different in-cluster service.
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
			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				gatewayIP := egressGatewayNodeInternalIP
				if ipFam == features.IPFamilyV6 {
					if !ipv6Enabled {
						return
					}
					gatewayIP = egressGatewayNodeInternalIPv6
				}
				t.NewAction(s, fmt.Sprintf("curl-external-echo-service-%s-%d", ipFam, i), &client, externalEcho, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
					clientIP := extractClientIPFromResponse(a.CmdOutput())

					if !clientIP.Equal(gatewayIP) {
						a.Failf("Request reached external echo service with wrong source IP: expected: %s, actual %s", gatewayIP.String(), clientIP.String())
					}
				})
			})
			i++
		}
	}

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i = 0
	for _, client := range ct.ClientPods() {
		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				gatewayIP := egressGatewayNodeInternalIP
				if ipFam == features.IPFamilyV6 {
					if !ipv6Enabled {
						return
					}
					gatewayIP = egressGatewayNodeInternalIPv6
				}
				t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%s-%d", ipFam, i), &client, externalEcho, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
					clientIP := extractClientIPFromResponse(a.CmdOutput())

					if !clientIP.Equal(gatewayIP) {
						a.Failf("Request reached external echo service with wrong source IP: expected: %s, actual %s", gatewayIP.String(), clientIP.String())
					}
				})

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

				t.ForEachIPFamily(func(ipFam features.IPFamily) {
					t.NewAction(s, fmt.Sprintf("curl-echo-service-%s-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, a.CurlCommand(echo))
					})
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
				t.ForEachIPFamily(func(ipFam features.IPFamily) {
					t.NewAction(s, fmt.Sprintf("curl-echo-pod-%s-%d", ipFam, i), &client, echo, ipFam).Run(func(a *check.Action) {
						a.ExecInPod(ctx, a.CurlCommand(echo))
					})
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

	var ipv6Enabled bool
	if status, ok := ct.Feature(features.IPv6); ok && status.Enabled && versioncheck.MustCompile(">=1.18.0")(ct.CiliumVersion) {
		ipv6Enabled = true
	}

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := ct.GetGatewayNodeInternalIP(egressGatewayNode, false)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IPv4")
	}

	var egressGatewayNodeInternalIPv6 net.IP
	egressGatewayNodeInternalIPv6 = ct.GetGatewayNodeInternalIP(egressGatewayNode, true)
	if ipv6Enabled && egressGatewayNodeInternalIPv6 == nil {
		t.Fatal("Cannot get egress gateway node internal IPv6")
	}

	err := check.WaitForEgressGatewayBpfPolicyEntries(ctx, ct.CiliumPods(), func(ciliumPod check.Pod) ([]check.BPFEgressGatewayPolicyEntry, error) {
		var targetEntries []check.BPFEgressGatewayPolicyEntry

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		egressIPv6 := "::"
		if ipv6Enabled && ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIPv6 = egressGatewayNodeInternalIPv6.String()
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

				if ipv6Enabled && len(client.Pod.Status.PodIPs) > 1 {
					var clientIPv6 string
					for _, podIP := range client.Pod.Status.PodIPs {
						if ip := net.ParseIP(podIP.IP); ip != nil && ip.To4() == nil {
							clientIPv6 = podIP.IP
							break
						}
					}

					if clientIPv6 != "" {
						targetEntries = append(targetEntries,
							check.BPFEgressGatewayPolicyEntry{
								SourceIP:  clientIPv6,
								DestCIDR:  "::/0",
								EgressIP:  egressIPv6,
								GatewayIP: egressGatewayNodeInternalIP.String(),
							})

						for _, addr := range nodeWithoutCilium.Status.Addresses {
							if ip := net.ParseIP(addr.Address); ip != nil && ip.To4() == nil {
								targetEntries = append(targetEntries,
									check.BPFEgressGatewayPolicyEntry{
										SourceIP:  clientIPv6,
										DestCIDR:  fmt.Sprintf("%s/128", addr.Address),
										EgressIP:  egressIPv6,
										GatewayIP: "Excluded CIDR",
									})
								break
							}
						}
					}
				}
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

			t.ForEachIPFamily(func(ipFam features.IPFamily) {
				hostIP := net.ParseIP(client.Pod.Status.HostIP)
				if ipFam == features.IPFamilyV6 {
					if !ipv6Enabled {
						return
					}
					for _, addr := range client.Pod.Status.HostIPs {
						if ip := net.ParseIP(addr.IP); ip != nil && ip.To4() == nil {
							hostIP = ip
							break
						}
					}
				}

				t.NewAction(s, fmt.Sprintf("curl-%s-%d", ipFam, i), &client, externalEcho, ipFam).Run(func(a *check.Action) {
					a.ExecInPod(ctx, a.CurlCommandWithOutput(externalEcho))
					clientIP := extractClientIPFromResponse(a.CmdOutput())

					if !clientIP.Equal(hostIP) {
						a.Failf("Request reached external echo service with wrong source IP: expected: %s, actual %s", hostIP.String(), clientIP.String())
					}
				})
			})
			i++
		}
	}
}
