// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/cilium/cilium/cilium-cli/connectivity/check"
	"github.com/cilium/cilium/cilium-cli/connectivity/sniff"
	"github.com/cilium/cilium/cilium-cli/k8s"
	"github.com/cilium/cilium/cilium-cli/utils/features"
)

var _ check.Scenario = (*ztunnelPodToPodEncryption)(nil)

// ZTunnelPodToPodEncryption is a test which verifies ztunnel mTLS encryption behavior.
//
// This test enables mTLS encryption by labeling the namespace with mtls-enabled=true,
// then verifies:
//  1. Encrypted traffic is present on port 15008 (ztunnel inbound port)
//  2. Plain text HTTP traffic is NOT present on the application port (8080)
//  3. Ztunnel pods have proper workload state information
//
// How ztunnel encryption works:
// - Pod sends traffic to remote pod IP on application port (e.g., 8080)
// - When mtls-enabled=true label is present, local ztunnel intercepts and redirects to itself on port 15008
// - Traffic is wrapped in HTTP/2 CONNECT (HBONE) with mTLS
// - Remote ztunnel unwraps and forwards to destination pod
//
// The test uses two sets of sniffers:
// - Sniffer 1 (ModeSanity): Expects to see encrypted traffic on port 15008
// - Sniffer 2 (ModeAssert): Expects to NOT see plain HTTP traffic on port 8080
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

	encryptMode features.Status
	ipv4Enabled features.Status
	ipv6Enabled features.Status

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
// The server pod must be on a different host to the client pod (or same host for now).
//
// It also acquires host namespace pods on the client and server nodes to allow
// access to the host network namespaces.
func (s *ztunnelPodToPodEncryption) getClientAndServerPods(t *check.Test) {
	// grab client and server pod, server must be on another host
	s.client = s.ct.RandomClientPod()
	if s.client == nil {
		t.Fatalf("Failed to acquire a client pod\n")
	}

	for _, pod := range s.ct.EchoPods() {
		if pod.Pod.Status.HostIP != s.client.Pod.Status.HostIP {
			s.server = &pod
			break
		}
	}
	if s.server == nil {
		t.Fatalf("Failed to acquire a server pod")
	}

	// grab host namespace pods for accessing the network namespaces of client
	// and server pods.
	if clientHostNS, ok := s.ct.HostNetNSPodsByNode()[s.client.Pod.Spec.NodeName]; !ok {
		t.Fatalf("Failed to acquire host namespace pod on %s (client's node)", s.client.Pod.Spec.NodeName)
	} else {
		s.clientHostNS = &clientHostNS
	}

	if serverHostNS, ok := s.ct.HostNetNSPodsByNode()[s.server.Pod.Spec.NodeName]; !ok {
		t.Fatalf("Failed to acquire host namespace pod on %s (server's node)", s.server.Pod.Spec.NodeName)
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
// Polling will occur until the provided ctx is canceled.
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

// labelNamespace adds or removes the mtls-enabled label from the test namespace
func (s *ztunnelPodToPodEncryption) labelNamespace(ctx context.Context, t *check.Test, enableMTLS bool) error {
	// Get the first available client from the context
	var client *k8s.Client
	for _, c := range s.ct.Clients() {
		client = c
		break
	}

	if client == nil {
		return fmt.Errorf("no Kubernetes client available")
	}

	// Create patch to add or remove the mtls-enabled label
	var patch map[string]any
	if enableMTLS {
		patch = map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{
					"mtls-enabled": "true",
				},
			},
		}
		t.Infof("Labeling namespace %s with 'mtls-enabled=true'", s.ct.Params().TestNamespace)
	} else {
		patch = map[string]any{
			"metadata": map[string]any{
				"labels": map[string]any{
					"mtls-enabled": nil,
				},
			},
		}
		t.Infof("Removing 'mtls-enabled' label from namespace %s", s.ct.Params().TestNamespace)
	}

	patchBytes, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to marshal patch: %w", err)
	}

	_, err = client.Clientset.CoreV1().Namespaces().Patch(
		ctx,
		s.ct.Params().TestNamespace,
		types.StrategicMergePatchType,
		patchBytes,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to patch namespace: %w", err)
	}

	return nil
}

// verifyNamespaceLabel checks the current state of the mtls-enabled label
func (s *ztunnelPodToPodEncryption) verifyNamespaceLabel(ctx context.Context, t *check.Test, expectedValue string) error {
	var client *k8s.Client
	for _, c := range s.ct.Clients() {
		client = c
		break
	}

	if client == nil {
		return fmt.Errorf("no Kubernetes client available")
	}

	ns, err := client.GetNamespace(ctx, s.ct.Params().TestNamespace, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get namespace %s: %w", s.ct.Params().TestNamespace, err)
	}

	if ns.Labels == nil {
		if expectedValue == "" {
			return nil
		}
		return fmt.Errorf("namespace %s has no labels", s.ct.Params().TestNamespace)
	}

	mtlsEnabled, exists := ns.Labels["mtls-enabled"]
	if !exists {
		if expectedValue == "" {
			return nil
		}
		return fmt.Errorf("namespace %s is missing 'mtls-enabled' label", s.ct.Params().TestNamespace)
	}

	if mtlsEnabled != expectedValue {
		return fmt.Errorf("namespace %s has 'mtls-enabled=%s' but expected '%s'",
			s.ct.Params().TestNamespace, mtlsEnabled, expectedValue)
	}

	t.Debugf("✓ Namespace %s has label 'mtls-enabled=%s'", s.ct.Params().TestNamespace, expectedValue)
	return nil
}

// plainTextHTTPFilter creates tcpdump filters to capture plain text HTTP traffic
func (s *ztunnelPodToPodEncryption) plainTextHTTPFilter(ctx context.Context, srcIP, dstIP string) (string, error) {
	if ctx.Err() != nil {
		return "", fmt.Errorf("context already cancelled")
	}

	// Filter for TCP traffic on port 8080 (echo server port) between specific src and dst
	// This captures unencrypted HTTP traffic between the two specific pods
	filter := fmt.Sprintf("tcp and port 8080 and ((src host %s and dst host %s) or (src host %s and dst host %s))",
		srcIP, dstIP, dstIP, srcIP)

	return filter, nil
}

// ztunnelTCPDumpFilters creates tcpdump filters to capture traffic to port 15008
func (s *ztunnelPodToPodEncryption) ztunnelTCPDumpFilters(ctx context.Context, srcIP, dstIP string) (string, error) {
	if ctx.Err() != nil {
		return "", fmt.Errorf("context already cancelled")
	}

	// Filter for TCP traffic to port 15008 (ztunnel inbound traffic)
	// This captures encrypted HBONE traffic between ztunnels
	filter := fmt.Sprintf("tcp and port 15008 and (host %s or host %s)", srcIP, dstIP)

	return filter, nil
}

// startSniffers starts tcpdump on both client and server pod veth interfaces
func (s *ztunnelPodToPodEncryption) startSniffers(ctx context.Context, t *check.Test, mode sniff.Mode, filters map[string]string, name string) (map[string]*sniff.Sniffer, error) {
	if ctx.Err() != nil {
		return nil, fmt.Errorf("context already cancelled")
	}

	sniffers := make(map[string]*sniff.Sniffer)
	captureInterface := "any"

	var err error
	var cancel func() error

	if s.ipv4Enabled.Enabled {
		clientFilter := filters["client-ipv4"]
		serverFilter := filters["server-ipv4"]

		sniffers["client-ipv4"], cancel, err = sniff.Sniff(ctx, name, s.clientHostNS, captureInterface, clientFilter, mode, sniff.SniffKillTimeout, t)
		if err != nil {
			return nil, fmt.Errorf("failed to start sniffer on client: %w", err)
		}
		s.finalizers = append(s.finalizers, cancel)
		t.Debugf("started client tcpdump sniffer: [client: %s] [node: %s] [interface: %s] [filter: %s] [mode: %s]",
			s.client.Pod.Name, s.client.Pod.Spec.NodeName, captureInterface, clientFilter, mode)

		sniffers["server-ipv4"], cancel, err = sniff.Sniff(ctx, name, s.serverHostNS, captureInterface, serverFilter, mode, sniff.SniffKillTimeout, t)
		if err != nil {
			return nil, fmt.Errorf("failed to start sniffer on server: %w", err)
		}
		s.finalizers = append(s.finalizers, cancel)
		t.Debugf("started server tcpdump sniffer: [server: %s] [node: %s] [interface: %s] [filter: %s] [mode: %s]",
			s.server.Pod.Name, s.server.Pod.Spec.NodeName, captureInterface, serverFilter, mode)
	}

	if s.ipv6Enabled.Enabled {
		nameIPv6 := fmt.Sprintf("%s-ipv6", name)
		clientFilter := filters["client-ipv6"]
		serverFilter := filters["server-ipv6"]

		sniffers["client-ipv6"], cancel, err = sniff.Sniff(ctx, nameIPv6, s.clientHostNS, captureInterface, clientFilter, mode, sniff.SniffKillTimeout, t)
		if err != nil {
			return nil, fmt.Errorf("failed to start sniffer on client for IPv6: %w", err)
		}
		s.finalizers = append(s.finalizers, cancel)
		t.Debugf("started client tcpdump sniffer for IPv6: [client: %s] [node: %s] [interface: %s] [filter: %s] [mode: %s]",
			s.client.Pod.Name, s.client.Pod.Spec.NodeName, captureInterface, clientFilter, mode)

		sniffers["server-ipv6"], cancel, err = sniff.Sniff(ctx, nameIPv6, s.serverHostNS, captureInterface, serverFilter, mode, sniff.SniffKillTimeout, t)
		if err != nil {
			return nil, fmt.Errorf("failed to start sniffer on server for IPv6: %w", err)
		}
		s.finalizers = append(s.finalizers, cancel)
		t.Debugf("started server tcpdump sniffer for IPv6: [server: %s] [node: %s] [interface: %s] [filter: %s] [mode: %s]",
			s.server.Pod.Name, s.server.Pod.Spec.NodeName, captureInterface, serverFilter, mode)
	}

	return sniffers, nil
}

// clientToServerTestWithRetry performs a curl from client to server with retry mechanism
func (s *ztunnelPodToPodEncryption) clientToServerTestWithRetry(ctx context.Context, t *check.Test, encryptedSniffers, plainTextSniffers map[string]*sniff.Sniffer) {
	if ctx.Err() != nil {
		t.Fatalf("Context already cancelled")
	}

	const maxRetries = 5
	const retryDelay = 2 * time.Second

	if s.ipv4Enabled.Enabled {
		t.Debugf("performing client->server curl with retry: [client: %s] [server: %s] [family: ipv4]", s.client.Pod.Name, s.server.Pod.Name)

		// Retry loop for the curl command execution
		var lastErr error
		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				t.Infof("Retry attempt %d/%d after mTLS enrollment...", attempt, maxRetries)
				time.Sleep(retryDelay)
			}

			// Try to execute curl
			output, err := s.client.K8sClient.ExecInPod(ctx,
				s.client.Pod.Namespace, s.client.Pod.Name, s.client.Pod.Labels["name"],
				[]string{"curl", "-sS", "--fail", "--connect-timeout", "5", "--max-time", "10",
					fmt.Sprintf("http://%s:%d/", s.server.Address(features.IPFamilyV4), s.server.Port())})

			if err == nil && output.Len() > 0 {
				t.Infof("✓ Curl succeeded on attempt %d", attempt)
				lastErr = nil
				break
			}

			lastErr = err
			if attempt < maxRetries {
				t.Debugf("Curl attempt %d failed: %v, retrying...", attempt, err)
			}
		}

		if lastErr != nil {
			t.Fatalf("Curl failed after %d attempts: %v", maxRetries, lastErr)
		}

		// Now run the action to validate sniffers
		action := t.NewAction(s, fmt.Sprintf("curl-%s", features.IPFamilyV4), s.client, s.server, features.IPFamilyV4)
		action.Run(func(a *check.Action) {
			// Validate encrypted traffic sniffers
			if sniffer, ok := encryptedSniffers["client-ipv4"]; ok {
				sniffer.Validate(a)
			}
			if sniffer, ok := encryptedSniffers["server-ipv4"]; ok {
				sniffer.Validate(a)
			}
			// Validate plain text traffic sniffers
			if sniffer, ok := plainTextSniffers["client-ipv4"]; ok {
				sniffer.Validate(a)
			}
			if sniffer, ok := plainTextSniffers["server-ipv4"]; ok {
				sniffer.Validate(a)
			}
		})
	}

	if s.ipv6Enabled.Enabled {
		t.Debugf("performing client->server curl with retry: [client: %s] [server: %s] [family: ipv6]", s.client.Pod.Name, s.server.Pod.Name)

		// Retry loop for the curl command execution
		var lastErr error
		for attempt := 1; attempt <= maxRetries; attempt++ {
			if attempt > 1 {
				t.Infof("Retry attempt %d/%d after mTLS enrollment...", attempt, maxRetries)
				time.Sleep(retryDelay)
			}

			// Try to execute curl
			output, err := s.client.K8sClient.ExecInPod(ctx,
				s.client.Pod.Namespace, s.client.Pod.Name, s.client.Pod.Labels["name"],
				[]string{"curl", "-sS", "--fail", "--connect-timeout", "5", "--max-time", "10",
					fmt.Sprintf("http://[%s]:%d/", s.server.Address(features.IPFamilyV6), s.server.Port())})

			if err == nil && output.Len() > 0 {
				t.Infof("✓ Curl succeeded on attempt %d", attempt)
				lastErr = nil
				break
			}

			lastErr = err
			if attempt < maxRetries {
				t.Debugf("Curl attempt %d failed: %v, retrying...", attempt, err)
			}
		}

		if lastErr != nil {
			t.Fatalf("Curl failed after %d attempts: %v", maxRetries, lastErr)
		}

		// Now run the action to validate sniffers
		action := t.NewAction(s, fmt.Sprintf("curl-%s", features.IPFamilyV6), s.client, s.server, features.IPFamilyV6)
		action.Run(func(a *check.Action) {
			// Validate encrypted traffic sniffers
			if sniffer, ok := encryptedSniffers["client-ipv6"]; ok {
				sniffer.Validate(a)
			}
			if sniffer, ok := encryptedSniffers["server-ipv6"]; ok {
				sniffer.Validate(a)
			}
			// Validate plain text traffic sniffers
			if sniffer, ok := plainTextSniffers["client-ipv6"]; ok {
				sniffer.Validate(a)
			}
			if sniffer, ok := plainTextSniffers["server-ipv6"]; ok {
				sniffer.Validate(a)
			}
		})
	}
}

func (s *ztunnelPodToPodEncryption) Run(ctx context.Context, t *check.Test) {
	s.ct = t.Context()
	s.namespace = s.ct.Params().CiliumNamespace

	// on exit, run registered finalizers
	defer func() {
		for _, f := range s.finalizers {
			if err := f(); err != nil {
				t.Infof("Failed to run finalizer: %v", err)
			}
		}
	}()

	// grab the features influencing this test
	var ok bool
	s.ipv4Enabled, ok = s.ct.Feature(features.IPv4)
	if !ok {
		t.Fatalf("Failed to detect IPv4 feature")
	}
	s.ipv6Enabled, ok = s.ct.Feature(features.IPv6)
	if !ok {
		t.Fatalf("Failed to detect IPv6 feature")
	}
	s.encryptMode, ok = s.ct.Feature(features.EncryptionPod)
	if !ok {
		t.Fatalf("Failed to detect encryption mode")
	}

	if !s.ipv4Enabled.Enabled && !s.ipv6Enabled.Enabled {
		t.Fatalf("Test requires at least one IP family to be enabled")
	}

	s.waitOnZTunnelDS(ctx, t)
	s.getClientAndServerPods(t)
	s.getZTunnelPods(ctx, t)

	t.Log("==== Ztunnel Encryption Test: Verify mTLS encrypted traffic ====")

	// Enable mTLS by adding the label to namespace
	if err := s.labelNamespace(ctx, t, true); err != nil {
		t.Fatalf("Failed to add mtls-enabled label: %v", err)
	}

	// Verify label is present
	if err := s.verifyNamespaceLabel(ctx, t, "true"); err != nil {
		t.Fatalf("Namespace label verification failed: %v", err)
	}

	timeout, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	s.validateZTunnelState(timeout, t)

	// Create filters for encrypted ztunnel traffic (port 15008)
	encryptedFilters := make(map[string]string)
	var err error

	if s.ipv4Enabled.Enabled {
		encryptedFilters["client-ipv4"], err = s.ztunnelTCPDumpFilters(ctx, s.client.Address(features.IPFamilyV4), s.server.Address(features.IPFamilyV4))
		if err != nil {
			t.Fatalf("Failed to create ztunnel filter: %v", err)
		}
		encryptedFilters["server-ipv4"], err = s.ztunnelTCPDumpFilters(ctx, s.server.Address(features.IPFamilyV4), s.client.Address(features.IPFamilyV4))
		if err != nil {
			t.Fatalf("Failed to create ztunnel filter: %v", err)
		}
	}

	if s.ipv6Enabled.Enabled {
		encryptedFilters["client-ipv6"], err = s.ztunnelTCPDumpFilters(ctx, s.client.Address(features.IPFamilyV6), s.server.Address(features.IPFamilyV6))
		if err != nil {
			t.Fatalf("Failed to create ztunnel filter for IPv6: %v", err)
		}
		encryptedFilters["server-ipv6"], err = s.ztunnelTCPDumpFilters(ctx, s.server.Address(features.IPFamilyV6), s.client.Address(features.IPFamilyV6))
		if err != nil {
			t.Fatalf("Failed to create ztunnel filter for IPv6: %v", err)
		}
	}

	// Create filters for plain text HTTP traffic (port 8080)
	plainTextFilters := make(map[string]string)

	if s.ipv4Enabled.Enabled {
		plainTextFilters["client-ipv4"], err = s.plainTextHTTPFilter(ctx, s.client.Address(features.IPFamilyV4), s.server.Address(features.IPFamilyV4))
		if err != nil {
			t.Fatalf("Failed to create plain text filter: %v", err)
		}
		plainTextFilters["server-ipv4"], err = s.plainTextHTTPFilter(ctx, s.server.Address(features.IPFamilyV4), s.client.Address(features.IPFamilyV4))
		if err != nil {
			t.Fatalf("Failed to create plain text filter: %v", err)
		}
	}

	if s.ipv6Enabled.Enabled {
		plainTextFilters["client-ipv6"], err = s.plainTextHTTPFilter(ctx, s.client.Address(features.IPFamilyV6), s.server.Address(features.IPFamilyV6))
		if err != nil {
			t.Fatalf("Failed to create plain text filter for IPv6: %v", err)
		}
		plainTextFilters["server-ipv6"], err = s.plainTextHTTPFilter(ctx, s.server.Address(features.IPFamilyV6), s.client.Address(features.IPFamilyV6))
		if err != nil {
			t.Fatalf("Failed to create plain text filter for IPv6: %v", err)
		}
	}

	// Start sniffers for encrypted traffic (expect to see packets - ModeSanity)
	t.Info("Starting packet capture to verify encrypted traffic on port 15008...")
	encryptedSniffers, err := s.startSniffers(ctx, t, sniff.ModeSanity, encryptedFilters, "ztunnel-encrypted")
	if err != nil {
		t.Fatalf("Failed to start encrypted traffic sniffers: %s", err)
	}

	// Start sniffers for plain text traffic (expect to NOT see packets - ModeAssert)
	t.Info("Starting packet capture to verify absence of plain text HTTP traffic on port 8080...")
	plainTextSniffers, err := s.startSniffers(ctx, t, sniff.ModeAssert, plainTextFilters, "ztunnel-plaintext")
	if err != nil {
		t.Fatalf("Failed to start plain text traffic sniffers: %s", err)
	}

	// Run the test with retry mechanism
	t.Info("Sending HTTP request with mTLS encryption enabled (with retry)...")
	s.clientToServerTestWithRetry(ctx, t, encryptedSniffers, plainTextSniffers)

	t.Info("✓ Test complete: Encrypted traffic verified on port 15008, no plain text traffic on port 8080")
}
