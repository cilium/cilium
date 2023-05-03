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
	"github.com/cilium/cilium-cli/internal/utils"
)

// EgressGateway is a test case which, given the cegp-sample
// CiliumEgressGatewayPolicy targeting:
// - a couple of client pods (kind=client) as source
// - the 0.0.0.0/0 destination CIDR
// - kind-worker2 as gateway node
//
// ensures that traffic from both clients reaches the echo-external service with
// the egress IP of the gateway node.
func EgressGateway() check.Scenario {
	return &egressGateway{}
}

type egressGateway struct {
	egressGatewayNode string
}

func (s *egressGateway) Name() string {
	return "egress-gateway"
}

func (s *egressGateway) Run(ctx context.Context, t *check.Test) {
	ct := t.Context()

	s.egressGatewayNode = t.EgressGatewayNode()
	if s.egressGatewayNode == "" {
		t.Fatal("Cannot get egress gateway node")
	}

	egressIP := s.getGatewayNodeInternalIP(ct)

	s.waitForBpfPolicyEntries(ctx, t)

	i := 0
	for _, client := range ct.ClientPods() {
		client := client

		for _, externalEcho := range ct.ExternalEchoPods() {
			t.NewAction(s, fmt.Sprintf("curl-%d", i), &client, externalEcho, check.IPFamilyV4).Run(func(a *check.Action) {
				a.ExecInPod(ctx, ct.CurlClientIPCommand(externalEcho, check.IPFamilyV4))
				clientIP := extractClientIPFromResponse(a.CmdOutput())

				if !clientIP.Equal(egressIP) {
					t.Fatal("Request reached external echo service with wrong source IP")
				}
			})
			i++
		}
	}
}

// getGatewayNodeInternalIP returns the k8s internal IP of the node acting as
// gateway for this test
func (s *egressGateway) getGatewayNodeInternalIP(ct *check.ConnectivityTest) net.IP {
	gatewayNode, ok := ct.Nodes()[s.egressGatewayNode]
	if !ok {
		return nil
	}

	for _, addr := range gatewayNode.Status.Addresses {
		if addr.Type != "InternalIP" {
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

// bpfEgressGatewayPolicyEntry represents an entry in the BPF egress gateway
// policy map
type bpfEgressGatewayPolicyEntry struct {
	SourceIP  string
	DestCIDR  string
	EgressIP  string
	GatewayIP string
}

// matches is an helper used to compare the receiver bpfEgressGatewayPolicyEntry
// with another entry
func (e *bpfEgressGatewayPolicyEntry) matches(t bpfEgressGatewayPolicyEntry) bool {
	return t.SourceIP == e.SourceIP &&
		t.DestCIDR == e.DestCIDR &&
		t.EgressIP == e.EgressIP &&
		t.GatewayIP == e.GatewayIP
}

// waitForBpfPolicyEntries waits for the egress gateway policy maps on each node
// to be populated with the entries for the cegp-sample CiliumEgressGatewayPolicy
func (s *egressGateway) waitForBpfPolicyEntries(ctx context.Context, t *check.Test) {
	ct := t.Context()

	w := utils.NewWaitObserver(ctx, utils.WaitParameters{Timeout: 10 * time.Second})
	defer w.Cancel()

	ensureBpfPolicyEntries := func() error {
		gatewayNodeInternalIP := s.getGatewayNodeInternalIP(ct)
		if gatewayNodeInternalIP == nil {
			t.Fatalf("Cannot retrieve internal IP of gateway node")
		}

		for _, ciliumPod := range ct.CiliumPods() {
			egressIP := "0.0.0.0"
			if ciliumPod.Pod.Spec.NodeName == s.egressGatewayNode {
				egressIP = gatewayNodeInternalIP.String()
			}

			targetEntries := []bpfEgressGatewayPolicyEntry{}
			for _, client := range ct.ClientPods() {
				targetEntries = append(targetEntries,
					bpfEgressGatewayPolicyEntry{
						SourceIP:  client.Pod.Status.PodIP,
						DestCIDR:  "0.0.0.0/0",
						EgressIP:  egressIP,
						GatewayIP: gatewayNodeInternalIP.String(),
					})
			}

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

// extractClientIPFromResponse extracts the client IP from the response of the
// echo-external service
func extractClientIPFromResponse(res string) net.IP {
	var clientIP struct {
		ClientIP string `json:"client-ip"`
	}

	json.Unmarshal([]byte(res), &clientIP)

	return net.ParseIP(clientIP.ClientIP).To4()
}
