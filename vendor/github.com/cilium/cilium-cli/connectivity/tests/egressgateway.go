// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium-cli/defaults"
	"github.com/cilium/cilium-cli/utils/features"
	"github.com/cilium/cilium-cli/utils/wait"

	v1 "k8s.io/api/core/v1"
	k8sErrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// bpfEgressGatewayPolicyEntry represents an entry in the BPF egress gateway policy map
type bpfEgressGatewayPolicyEntry struct {
	SourceIP  string `json:"sourceIP"`
	DestCIDR  string `json:"destCIDR"`
	EgressIP  string `json:"egressIP"`
	GatewayIP string `json:"gatewayIP"`
}

// matches is an helper used to compare the receiver bpfEgressGatewayPolicyEntry with another entry
func (e *bpfEgressGatewayPolicyEntry) matches(t bpfEgressGatewayPolicyEntry) bool {
	return t.SourceIP == e.SourceIP &&
		t.DestCIDR == e.DestCIDR &&
		t.EgressIP == e.EgressIP &&
		t.GatewayIP == e.GatewayIP
}

// WaitForEgressGatewayBpfPolicyEntries waits for the egress gateway policy maps on each node to WaitForEgressGatewayBpfPolicyEntries
// with the entries returned by the targetEntriesCallback
func WaitForEgressGatewayBpfPolicyEntries(ctx context.Context, t *check.Test,
	targetEntriesCallback func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry,
) {
	ct := t.Context()

	w := wait.NewObserver(ctx, wait.Parameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBpfPolicyEntries := func() error {
		for _, ciliumPod := range ct.CiliumPods() {
			targetEntries := targetEntriesCallback(ciliumPod)

			cmd := strings.Split("cilium bpf egress list -o json", " ")
			stdout, err := ciliumPod.K8sClient.ExecInPod(ctx, ciliumPod.Pod.Namespace, ciliumPod.Pod.Name, defaults.AgentContainerName, cmd)
			if err != nil {
				t.Fatal("failed to run cilium bpf egress list command: %w", err)
			}

			entries := []bpfEgressGatewayPolicyEntry{}
			json.Unmarshal(stdout.Bytes(), &entries)

		nextTargetEntry:
			for _, targetEntry := range targetEntries {
				for _, entry := range entries {
					if targetEntry.matches(entry) {
						continue nextTargetEntry
					}
				}

				return fmt.Errorf("Could not find egress gateway policy entry matching %+v", targetEntry)
			}

		nextEntry:
			for _, entry := range entries {
				for _, targetEntry := range targetEntries {
					if targetEntry.matches(entry) {
						continue nextEntry
					}
				}

				return fmt.Errorf("Untracked entry %+v in the egress gateway policy map", entry)
			}
		}

		return nil
	}

	for {
		if err := ensureBpfPolicyEntries(); err != nil {
			if err := w.Retry(err); err != nil {
				t.Fatal("Failed to ensure egress gateway policy map is properly populated:", err)
			}

			continue
		}

		return
	}
}

// getGatewayNodeInternalIP returns the k8s internal IP of the node acting as gateway for this test
func getGatewayNodeInternalIP(ct *check.ConnectivityTest, egressGatewayNode string) net.IP {
	gatewayNode, ok := ct.Nodes()[egressGatewayNode]
	if !ok {
		return nil
	}

	for _, addr := range gatewayNode.Status.Addresses {
		if addr.Type != v1.NodeInternalIP {
			continue
		}

		ip := net.ParseIP(addr.Address)
		if ip == nil || ip.To4() == nil {
			continue
		}

		return ip
	}

	return nil
}

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
	return &egressGateway{}
}

type egressGateway struct{}

func (s *egressGateway) Name() string {
	return "egress-gateway"
}

func (s *egressGateway) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	WaitForEgressGatewayBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

		egressIP := "0.0.0.0"
		if ciliumPod.Pod.Spec.NodeName == egressGatewayNode {
			egressIP = egressGatewayNodeInternalIP.String()
		}

		for _, client := range ct.ClientPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:  client.Pod.Status.PodIP,
					DestCIDR:  "0.0.0.0/0",
					EgressIP:  egressIP,
					GatewayIP: egressGatewayNodeInternalIP.String(),
				})
		}

		for _, echo := range ct.EchoPods() {
			targetEntries = append(targetEntries,
				bpfEgressGatewayPolicyEntry{
					SourceIP:  echo.Pod.Status.PodIP,
					DestCIDR:  "0.0.0.0/0",
					EgressIP:  egressIP,
					GatewayIP: egressGatewayNodeInternalIP.String(),
				})
		}

		return targetEntries
	})

	// Ping hosts (pod to host connectivity). Should not get masqueraded with egress IP
	i := 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, dst := range ct.HostNetNSPodsByNode() {
			dst := dst

			t.NewAction(s, fmt.Sprintf("ping-%d", i), &client, &dst, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.PingCommand(dst, features.IPFamilyV4))
			})
			i++
		}
	}

	// DNS query (pod to service connectivity). Should not get masqueraded with egress IP
	i = 0
	for _, client := range ct.ClientPods() {
		client := client

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

	// Traffic matching an egress gateway policy should leave the cluster masqueraded with the egress IP (pod to external service)
	i = 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-external-echo-pod-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4))
				clientIP := extractClientIPFromResponse(a.CmdOutput())

				if !clientIP.Equal(egressGatewayNodeInternalIP) {
					t.Fatal("Request reached external echo service with wrong source IP")
				}
			})
			i++
		}
	}

	// When connecting from outside the cluster to a nodeport service whose pods are selected by an egress policy,
	// the reply traffic should not be SNATed with the egress IP
	i = 0
	for _, client := range ct.ExternalEchoPods() {
		client := client

		for _, node := range ct.Nodes() {
			for _, echo := range ct.EchoServices() {
				// convert the service to a ServiceExternalIP as we want to access it through its external IP
				echo := echo.ToNodeportService(node)

				t.NewAction(s, fmt.Sprintf("curl-echo-service-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, features.IPFamilyV4))
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
			client := client

			for _, echo := range ct.EchoPods() {
				t.NewAction(s, fmt.Sprintf("curl-echo-pod-%d", i), &client, echo, features.IPFamilyV4).Run(func(a *check.Action) {
					a.ExecInPod(ctx, ct.CurlCommand(echo, features.IPFamilyV4))
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
	return &egressGatewayExcludedCIDRs{}
}

type egressGatewayExcludedCIDRs struct{}

func (s *egressGatewayExcludedCIDRs) Name() string {
	return "egress-gateway-excluded-cidrs"
}

func (s *egressGatewayExcludedCIDRs) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	egressGatewayNode := t.EgressGatewayNode()
	if egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressGatewayNodeInternalIP := getGatewayNodeInternalIP(ct, egressGatewayNode)
	if egressGatewayNodeInternalIP == nil {
		t.Fatal("Cannot get egress gateway node internal IP")
	}

	WaitForEgressGatewayBpfPolicyEntries(ctx, t, func(ciliumPod check.Pod) []bpfEgressGatewayPolicyEntry {
		targetEntries := []bpfEgressGatewayPolicyEntry{}

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
					bpfEgressGatewayPolicyEntry{
						SourceIP:  client.Pod.Status.PodIP,
						DestCIDR:  "0.0.0.0/0",
						EgressIP:  egressIP,
						GatewayIP: egressGatewayNodeInternalIP.String(),
					})

				targetEntries = append(targetEntries,
					bpfEgressGatewayPolicyEntry{
						SourceIP:  client.Pod.Status.PodIP,
						DestCIDR:  fmt.Sprintf("%s/32", nodeWithoutCilium.Status.Addresses[0].Address),
						EgressIP:  egressIP,
						GatewayIP: "Excluded CIDR",
					})
			}
		}

		return targetEntries
	})

	// Traffic matching an egress gateway policy and an excluded CIDR should leave the cluster masqueraded with the
	// node IP where the pod is running rather than with the egress IP(pod to external service)
	i := 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			externalEcho := externalEcho.ToEchoIPPod()

			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, externalEcho, features.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlCommandWithOutput(externalEcho, features.IPFamilyV4))
				clientIP := extractClientIPFromResponse(a.CmdOutput())

				if !clientIP.Equal(net.ParseIP(client.Pod.Status.HostIP)) {
					t.Fatal("Request reached external echo service with wrong source IP")
				}
			})
			i++
		}
	}
}
