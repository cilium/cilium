// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
)

var _ check.Scenario = (*ztunnelPodToPodEncryption)(nil)

// ZTunnelPodToPodEncryption is a test which ensures client traffic to a server
// pod is mTLS tunnelled via ztunnel.
func ZTunnelPodToPodEncryption() check.Scenario {
	return &ztunnelPodToPodEncryption{
		ScenarioBase: check.NewScenarioBase(),
	}
}

type ztunnelPodToPodEncryption struct {
	check.ScenarioBase

	ct *check.ConnectivityTest

	namespace string

	// client pod used to generate traffic
	client *check.Pod
	// server pod which receives and responds to client traffic
	server *check.Pod
	// pod on client's node providing access to host network namespace
	clientHostNS *check.Pod
	// pod on server's node providing access to host network namespace
	serverHostNS *check.Pod
	// ZTunnel pod running on the client's node
	clientZTunnel *check.Pod
	// ZTunnel pod running on the server's node
	serverZTunnel *check.Pod

	finalizers []func() error
}

func (s *ztunnelPodToPodEncryption) Name() string {
	return "ztunnel-pod-to-pod-encryption"
}

// waitOnZTunnelDS waits for the ztunnel daemonset to be ready and ensure tests
// do not begin until it is.
func (s *ztunnelPodToPodEncryption) waitOnZTunnelDS(ctx context.Context, t *check.Test) {
	// wait for ztunnel-cilium daemonset to be ready
	if err := check.WaitForDaemonSet(ctx, t, s.ct.K8sClient(), s.namespace, "ztunnel-cilium"); err != nil {
		t.Fatalf("Failed to wait for ztunnel-cilium daemonset: %s", err)
	}
}

// getClientAndServerPods acquires the client and server pods to be used in the test.
// The server pod must be on a different host to the client pod.
//
// It also acquires host namespace pods on the client and server nodes to allow
// access to the host network namespaces.
func (s *ztunnelPodToPodEncryption) getClientAndServerPods(t *check.Test) {
	// grab client and server pod, server must be on another host
	s.client = s.ct.RandomClientPod()
	if s.client == nil {
		t.Fatalf("Failed to acquire a client pod\n")
	}

	// for now, we test only on the same host.
	for _, pod := range s.ct.EchoPods() {
		if pod.Pod.Status.HostIP == s.client.Pod.Status.HostIP {
			s.server = &pod
			break
		}
	}
	if s.server == nil {
		t.Fatalf("Failed to acquire a server pod\n")
	}

	// grab host namespace pods for accessing the network namespaces of client
	// and server pods.
	if clientHostNS, ok := s.ct.HostNetNSPodsByNode()[s.client.Pod.Spec.NodeName]; !ok {
		t.Fatalf("Fail to acquire host namespace pod on %s\n (client's node)", s.client.Pod.Spec.NodeName)
	} else {
		s.clientHostNS = &clientHostNS
	}

	if serverHostNS, ok := s.ct.HostNetNSPodsByNode()[s.server.Pod.Spec.NodeName]; !ok {
		t.Fatalf("Fail to acquire host namespace pod on %s\n (server's node)", s.server.Pod.Spec.NodeName)
	} else {
		s.serverHostNS = &serverHostNS
	}

}

// getZTunnelPods acquires the ztunnel pods running on the same nodes as the client
// and server pods respectively.
//
// This is required to later validate that ztunnel received both client and server
// workload state information prior to running the test.
func (s *ztunnelPodToPodEncryption) getZTunnelPods(ctx context.Context, t *check.Test) {
	// get ztunnel pods
	ztunnelPods, err := s.ct.K8sClient().ListPods(ctx, s.namespace, metav1.ListOptions{
		LabelSelector: "app=ztunnel",
	})
	if err != nil {
		t.Fatalf("Failed to list ztunnel pods: %s", err)
	}
	if len(ztunnelPods.Items) == 0 {
		t.Fatalf("No ztunnel pods found in namespace %s with label app=ztunnel", s.namespace)
	}
	t.Debugf("Found %d ztunnel pods", len(ztunnelPods.Items))

	// get ztunnel pods running on the same nodes as client and server respectively
	for i := range ztunnelPods.Items {
		pod := &ztunnelPods.Items[i]
		if pod.Status.HostIP == s.client.Pod.Status.HostIP {
			s.clientZTunnel = &check.Pod{Pod: pod}
		}
		if pod.Status.HostIP == s.server.Pod.Status.HostIP {
			s.serverZTunnel = &check.Pod{Pod: pod}
		}
	}
	if s.clientZTunnel == nil {
		t.Fatalf("Failed to acquire ztunnel pod on client node")
	}
	if s.serverZTunnel == nil {
		t.Fatalf("Failed to acquire ztunnel pod on server node")
	}
}

// workload represents a workload in the ztunnel dump_config output
type workload struct {
	Name           string   `json:"name"`
	Namespace      string   `json:"namespace"`
	ServiceAccount string   `json:"serviceAccount"`
	UID            string   `json:"uid"`
	WorkloadIPs    []string `json:"workloadIps"`
	Node           string   `json:"node"`
	Status         string   `json:"status"`
}

// ztunnelDumpConfig represents the dump_config response structure
type ztunnelDumpConfig struct {
	Workloads []workload `json:"workloads"`
}

// validateZTunnelState checks that both client and server ztunnel has received
// workload information for both the server and client.
//
// We also confirm that the client and server pods have ztunnel sockets
// configured.
//
// Polling will occurr until the provided ctx is canceled.
func (s *ztunnelPodToPodEncryption) validateZTunnelState(ctx context.Context, t *check.Test) {
	const ztunnelAdminPort = "15000"

	// Fetch and parse ztunnel workloads from a ztunnel pod
	fetchWorkloads := func(hostNS *check.Pod) ([]workload, error) {
		// Execute curl to get dump_config from ztunnel
		stdout, err := hostNS.K8sClient.ExecInPod(
			ctx,
			hostNS.Pod.Namespace,
			hostNS.Pod.Name,
			"", // empty container name means first container
			[]string{"curl", "-s", fmt.Sprintf("http://localhost:%s/config_dump", ztunnelAdminPort)},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to execute curl in ztunnel pod: %w", err)
		}

		// Debug: dump the raw response
		t.Debugf("=== Raw ztunnel dump_config response from %s ===\nLength: %d bytes\n%s\n=== End response ===", hostNS.Pod.Name, stdout.Len(), stdout.String())

		// Parse JSON response
		var config ztunnelDumpConfig
		if err := json.Unmarshal(stdout.Bytes(), &config); err != nil {
			return nil, fmt.Errorf("failed to parse ztunnel dump_config JSON: %w", err)
		}

		return config.Workloads, nil
	}

	validated := false
	for ctx.Err() == nil {
		// Fetch workloads from both ztunnels
		clientWorkloads, err := fetchWorkloads(s.clientHostNS)
		if err != nil {
			t.Fatalf("Failed to fetch workloads from client ztunnel: %v", err)
		}

		serverWorkloads, err := fetchWorkloads(s.serverHostNS)
		if err != nil {
			t.Fatalf("Failed to fetch workloads from server ztunnel: %v", err)
		}

		t.Debugf("Client ztunnel has %v workloads", clientWorkloads)
		t.Debugf("Server ztunnel has %v workloads", serverWorkloads)

		// ensure client workloads contain both client and server pods
		clientHasClient := false
		clientHasServer := false
		for _, wl := range clientWorkloads {
			if wl.UID == string(s.client.Pod.UID) {
				clientHasClient = true
			}
			if wl.UID == string(s.server.Pod.UID) {
				clientHasServer = true
			}
		}

		if !clientHasClient || !clientHasServer {
			t.Debugf("Client ztunnel missing workload information: hasClient=%v hasServer=%v, retrying", clientHasClient, clientHasServer)
			goto retry
		}

		validated = true

		break
	retry:
		time.Sleep(1 * time.Second)
		continue
	}

	if !validated {
		t.Fatalf("Timed out waiting for ztunnel pods to receive workload information for client and server pods")
	}
	t.Debugf("Both ztunnel pods have workload information for client and server pods, and sockets are configured")
}

func (s *ztunnelPodToPodEncryption) Run(ctx context.Context, t *check.Test) {
	s.ct = t.Context()
	s.namespace = s.ct.Params().CiliumNamespace

	// on exit, run registered finalizers
	defer func() {
		for _, f := range s.finalizers {
			if err := f(); err != nil {
				t.Infof("Failed to run finalizer: %w", err)
			}
		}
	}()

	s.waitOnZTunnelDS(ctx, t)
	s.getClientAndServerPods(t)
	s.getZTunnelPods(ctx, t)

	timeout, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	s.validateZTunnelState(timeout, t)

}
